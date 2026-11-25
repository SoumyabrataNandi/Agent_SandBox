//! RunService: the single path from any front end to the sandbox (U5 design §1).

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use sandboxd_audit::{AuditEvent, AuditSink, EventKind, rfc3339_millis};
use sandboxd_policy::{Policy, PolicyDir, PolicyError, fmt_duration};
use sandboxd_runtime::{RunEvent, RunResult, Sandbox, Session, SessionEnd, SessionError};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::{
    api::{ApiPolicy, ApiRunRequest, ApiSession, ApiSessionCreate, ApiSessionRun},
    auth::Principal,
    metrics::Metrics,
    sessions::SessionStore,
};

/// Why a request was refused before running. Guest failures are never `ServiceError`s.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    #[error("the audit log is unavailable; runs are refused until it recovers")]
    AuditUnavailable,
    #[error("policy {0:?} not found")]
    PolicyNotFound(String),
    #[error("server is at capacity; retry later")]
    Overloaded,
    #[error("{0}")]
    InvalidRequest(String),
    #[error("missing or invalid bearer token")]
    Unauthorized,
    #[error("session not found")]
    SessionNotFound,
    #[error("another call is running in this session; retry when it finishes")]
    SessionBusy,
    #[error("too many sessions; close one or retry later")]
    SessionLimit,
    #[error("policy {0:?} does not enable sessions")]
    SessionsDisabled(String),
    #[error("{0}")]
    PolicyViolation(String),
    #[error("{0}")]
    Internal(String),
}

impl ServiceError {
    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            ServiceError::AuditUnavailable => "AUDIT_UNAVAILABLE",
            ServiceError::PolicyNotFound(_) => "POLICY_NOT_FOUND",
            ServiceError::Overloaded => "OVERLOADED",
            ServiceError::InvalidRequest(_) => "INVALID_REQUEST",
            ServiceError::Unauthorized => "UNAUTHORIZED",
            ServiceError::SessionNotFound => "SESSION_NOT_FOUND",
            ServiceError::SessionBusy => "SESSION_BUSY",
            ServiceError::SessionLimit => "SESSION_LIMIT",
            ServiceError::SessionsDisabled(_) => "SESSIONS_DISABLED",
            ServiceError::PolicyViolation(_) => "POLICY_VIOLATION",
            ServiceError::Internal(_) => "INTERNAL",
        }
    }
    /// HTTP status.
    pub fn status(&self) -> u16 {
        match self {
            ServiceError::AuditUnavailable => 503,
            ServiceError::PolicyNotFound(_) => 404,
            ServiceError::Overloaded => 429,
            ServiceError::InvalidRequest(_) => 400,
            ServiceError::Unauthorized => 401,
            ServiceError::SessionNotFound => 404,
            ServiceError::SessionBusy => 409,
            ServiceError::SessionLimit => 429,
            ServiceError::SessionsDisabled(_) => 403,
            ServiceError::PolicyViolation(_) => 400,
            ServiceError::Internal(_) => 500,
        }
    }
}

/// Admission control settings (Q6).
#[derive(Debug, Clone, Copy)]
pub struct AdmissionConfig {
    pub max_concurrent: usize,
    pub queue_depth: usize,
    pub queue_timeout: Duration,
    /// Live sessions, server-wide (`[runtime] max_sessions`, C3-U4): each holds an interpreter.
    pub max_sessions: usize,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            max_concurrent: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            queue_depth: 64,
            queue_timeout: Duration::from_secs(10),
            max_sessions: 16,
        }
    }
}

/// Shared service state; cheap to clone.
#[derive(Clone)]
pub struct RunService {
    inner: Arc<Inner>,
}

struct Inner {
    sandbox: Sandbox,
    policies: PolicyDir,
    audit: Arc<dyn AuditSink>,
    slots: Arc<Semaphore>,
    waiting: AtomicUsize,
    admission: AdmissionConfig,
    metrics: Metrics,
    sessions: Arc<SessionStore>,
}

impl std::fmt::Debug for RunService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunService")
            .field("admission", &self.inner.admission)
            .finish_non_exhaustive()
    }
}

impl RunService {
    pub fn new(
        sandbox: Sandbox,
        policies: PolicyDir,
        audit: Arc<dyn AuditSink>,
        admission: AdmissionConfig,
    ) -> Self {
        let max = admission.max_concurrent.max(1);
        let svc = Self {
            inner: Arc::new(Inner {
                sessions: SessionStore::new(admission.max_sessions),
                sandbox,
                policies,
                audit,
                slots: Arc::new(Semaphore::new(max)),
                waiting: AtomicUsize::new(0),
                admission: AdmissionConfig {
                    max_concurrent: max,
                    ..admission
                },
                metrics: Metrics::default(),
            }),
        };
        // Expire idle and over-age sessions (holds only a weak reference).
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let weak = Arc::downgrade(&svc.inner);
            rt.spawn(async move {
                let mut tick = tokio::time::interval(REAP_INTERVAL);
                loop {
                    tick.tick().await;
                    let Some(inner) = weak.upgrade() else { break };
                    RunService { inner }.reap().await;
                }
            });
        }
        svc
    }

    /// Instance pool occupancy (None without pooling).
    pub fn pool_status(&self) -> Option<sandboxd_runtime::PoolStatus> {
        self.inner.sandbox.pool_status()
    }

    /// Operator Python packages (`name version`), empty without a wheelhouse (cycle 5).
    pub fn packages(&self) -> Vec<String> {
        self.inner
            .sandbox
            .packages()
            .map(|p| p.names())
            .unwrap_or_default()
    }

    /// Metrics registry (for `/metrics`).
    pub fn metrics(&self) -> &Metrics {
        &self.inner.metrics
    }

    /// The audit sink (for server lifecycle events).
    pub fn audit(&self) -> &Arc<dyn AuditSink> {
        &self.inner.audit
    }

    /// `true` while runs can be accepted (audit writable).
    pub fn healthy(&self) -> bool {
        let ok = self.inner.audit.is_healthy();
        self.inner.metrics.audit_healthy_set(ok);
        ok
    }

    /// Policies for listing (no host paths).
    pub fn policies(&self) -> Vec<ApiPolicy> {
        self.inner
            .policies
            .list()
            .into_iter()
            .filter_map(|s| {
                let p = self.inner.policies.get(&s.name).ok()?;
                Some(ApiPolicy {
                    name: s.name,
                    description: s.description,
                    overrides_builtin: s.overrides_builtin,
                    wall_clock: fmt_duration(p.limits().wall_clock),
                    memory: p.limits().memory.to_string(),
                    mounts: p
                        .filesystem()
                        .mounts
                        .iter()
                        .map(|m| format!("{} ({})", m.guest, m.mode.as_str()))
                        .collect(),
                })
            })
            .collect()
    }

    /// Validate, admit, and run one request.
    pub async fn submit(
        &self,
        principal: &Principal,
        req: ApiRunRequest,
        events: Option<mpsc::Sender<RunEvent>>,
    ) -> Result<RunResult, ServiceError> {
        let m = &self.inner.metrics;
        let started = SystemTime::now();
        // S1: fail closed.
        if !self.healthy() {
            m.reject("audit_unavailable");
            return Err(ServiceError::AuditUnavailable);
        }
        // S2: policy.
        let policy = self.policy(principal, req.policy_name())?;
        // S4: decode before queueing (cheap, and a bad request shouldn't hold a slot).
        let run_req = req.into_run_request().map_err(|e| {
            m.reject("invalid_request");
            ServiceError::InvalidRequest(e)
        })?;
        // S3: admission.
        let (_permit, queued_ms) = self.admit().await?;

        // S5: run.
        m.running_add(1);
        m.pool_set(self.inner.sandbox.pool_status());
        let mut result = self
            .inner
            .sandbox
            .execute(run_req, policy, &principal.0, events)
            .await;
        m.running_add(-1);
        m.pool_set(self.inner.sandbox.pool_status());
        result.timings.queued_ms = queued_ms;
        result.timings.total_ms += queued_ms;

        self.record(&result, started);
        Ok(result)
    }

    fn record(&self, result: &RunResult, started: SystemTime) {
        let outcome = serde_json::to_value(result.outcome)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        let limits: Vec<String> = result
            .limits_hit
            .iter()
            .filter_map(|k| {
                serde_json::to_value(k)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
            })
            .collect();
        self.inner.metrics.record_run(
            result.language.as_str(),
            &result.policy,
            &outcome,
            result.timings.total_ms as f64 / 1000.0,
            &limits,
        );
        crate::otel::record_run_span(result, started);
    }

    /// Wait for an execution slot (S3). Returns the permit and the time spent queued.
    async fn admit(&self) -> Result<(OwnedSemaphorePermit, u64), ServiceError> {
        let m = &self.inner.metrics;
        let t_queue = Instant::now();
        let waiting = self.inner.waiting.fetch_add(1, Ordering::SeqCst);
        if waiting >= self.inner.admission.queue_depth && self.inner.slots.available_permits() == 0
        {
            self.inner.waiting.fetch_sub(1, Ordering::SeqCst);
            m.reject("overloaded");
            return Err(ServiceError::Overloaded);
        }
        m.queue_add(1);
        let permit = tokio::time::timeout(
            self.inner.admission.queue_timeout,
            self.inner.slots.clone().acquire_owned(),
        )
        .await;
        self.inner.waiting.fetch_sub(1, Ordering::SeqCst);
        m.queue_add(-1);
        let Ok(Ok(permit)) = permit else {
            m.reject("overloaded");
            return Err(ServiceError::Overloaded);
        };
        let queued_ms = u64::try_from(t_queue.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok((permit, queued_ms))
    }

    fn policy(&self, principal: &Principal, name: &str) -> Result<Arc<Policy>, ServiceError> {
        self.inner.policies.get(name).map_err(|e| {
            self.inner.metrics.reject("policy_not_found");
            self.inner.audit.emit(
                AuditEvent::new(EventKind::PolicyDenied {
                    what: e.to_string(),
                    requested: Some(name.to_string()),
                })
                .principal(principal.0.clone()),
            );
            match e {
                PolicyError::NotFound(n) => ServiceError::PolicyNotFound(n),
                other => ServiceError::InvalidRequest(other.to_string()),
            }
        })
    }

    // ---- sessions (cycle 3, C3-U4) -------------------------------------------------------

    /// Create a session (`POST /v1/sessions`, MCP `session_create`).
    pub async fn create_session(
        &self,
        principal: &Principal,
        req: ApiSessionCreate,
    ) -> Result<ApiSession, ServiceError> {
        let m = &self.inner.metrics;
        if !self.healthy() {
            m.reject("audit_unavailable");
            return Err(ServiceError::AuditUnavailable);
        }
        let policy = self.policy(principal, req.policy_name())?;
        if !policy.session().enabled {
            m.reject("sessions_disabled");
            self.inner.audit.emit(
                AuditEvent::new(EventKind::PolicyDenied {
                    what: "sessions are not enabled by this policy".into(),
                    requested: Some(policy.name().to_string()),
                })
                .principal(principal.0.clone()),
            );
            return Err(ServiceError::SessionsDisabled(policy.name().to_string()));
        }
        let opts = req.into_options().map_err(|e| {
            m.reject("invalid_request");
            ServiceError::InvalidRequest(e)
        })?;
        let Some(reservation) = self
            .inner
            .sessions
            .reserve(policy.name(), policy.session().max_sessions)
        else {
            m.reject("session_limit");
            return Err(ServiceError::SessionLimit);
        };
        let session = self
            .inner
            .sandbox
            .open_session(opts, policy, &principal.0)
            .await
            .map_err(|e| {
                m.reject("session_create");
                session_error(e)
            })?;
        reservation.commit(session.clone());
        m.sessions_set(self.inner.sessions.len());
        m.pool_set(self.inner.sandbox.pool_status());
        Ok(api_session(&session))
    }

    /// The session `id` if `principal` owns it. Anything else is "not found" (and audited), so
    /// ids can't be probed (design §4).
    fn owned(&self, principal: &Principal, id: &str) -> Result<Session, ServiceError> {
        match self.inner.sessions.get(id) {
            Some(s) if s.principal() == principal.0 => Ok(s),
            other => {
                self.inner.audit.emit(
                    AuditEvent::new(EventKind::PolicyDenied {
                        what: if other.is_some() {
                            "session owned by another principal".into()
                        } else {
                            "unknown session".into()
                        },
                        requested: Some(id.chars().take(64).collect()),
                    })
                    .principal(principal.0.clone()),
                );
                Err(ServiceError::SessionNotFound)
            }
        }
    }

    /// Run one call in a session. The result is `(result, why the session ended)`.
    pub async fn session_run(
        &self,
        principal: &Principal,
        id: &str,
        req: ApiSessionRun,
        events: Option<mpsc::Sender<RunEvent>>,
    ) -> Result<(RunResult, Option<SessionEnd>), ServiceError> {
        let m = &self.inner.metrics;
        let started = SystemTime::now();
        if !self.healthy() {
            m.reject("audit_unavailable");
            return Err(ServiceError::AuditUnavailable);
        }
        let session = self.owned(principal, id)?;
        let call = req.into_call().map_err(|e| {
            m.reject("invalid_request");
            ServiceError::InvalidRequest(e)
        })?;
        let (_permit, queued_ms) = self.admit().await?;
        m.running_add(1);
        let out = session.call(call, events).await;
        m.running_add(-1);
        match out {
            Ok(o) => {
                m.session_call();
                if let Some(reason) = o.ended {
                    self.forget(id, reason);
                }
                let mut result = o.result;
                result.timings.queued_ms = queued_ms;
                result.timings.total_ms += queued_ms;
                self.record(&result, started);
                Ok((result, o.ended))
            }
            Err(SessionError::Ended(reason)) => {
                self.forget(id, reason);
                Err(ServiceError::SessionNotFound)
            }
            Err(e) => Err(session_error(e)),
        }
    }

    /// A session's state.
    pub fn session_info(
        &self,
        principal: &Principal,
        id: &str,
    ) -> Result<ApiSession, ServiceError> {
        Ok(api_session(&self.owned(principal, id)?))
    }

    /// Close a session (waits for a running call to finish).
    pub async fn close_session(
        &self,
        principal: &Principal,
        id: &str,
    ) -> Result<ApiSession, ServiceError> {
        let s = self.owned(principal, id)?;
        if self.inner.sessions.remove(id).is_some() {
            s.close(SessionEnd::Closed).await;
            self.ended(SessionEnd::Closed);
        }
        Ok(api_session(&s))
    }

    /// Close every session (server shutdown).
    pub async fn close_all_sessions(&self) {
        for s in self.inner.sessions.all() {
            if self.inner.sessions.remove(s.id()).is_some() {
                s.close(SessionEnd::Shutdown).await;
                self.ended(SessionEnd::Shutdown);
            }
        }
    }

    /// Live sessions.
    pub fn session_count(&self) -> usize {
        self.inner.sessions.len()
    }

    /// End sessions that are idle past `idle_ttl` or older than `max_lifetime`.
    async fn reap(&self) {
        for s in self.inner.sessions.all() {
            let info = s.info();
            let p = s.policy().session();
            let reason = if info.ended.is_some() {
                info.ended
            } else if info.age >= p.max_lifetime {
                Some(SessionEnd::Lifetime)
            } else if !info.busy && info.idle >= p.idle_ttl {
                Some(SessionEnd::Idle)
            } else {
                None
            };
            if let Some(r) = reason
                && self.inner.sessions.remove(s.id()).is_some()
            {
                s.close(r).await;
                self.ended(r);
            }
        }
    }

    fn forget(&self, id: &str, reason: SessionEnd) {
        if self.inner.sessions.remove(id).is_some() {
            self.ended(reason);
        }
    }

    fn ended(&self, reason: SessionEnd) {
        let m = &self.inner.metrics;
        m.session_ended(reason.as_str());
        m.sessions_set(self.inner.sessions.len());
        m.pool_set(self.inner.sandbox.pool_status());
    }
}

/// How often idle/lifetime expiry is checked.
const REAP_INTERVAL: Duration = Duration::from_secs(5);

fn session_error(e: SessionError) -> ServiceError {
    match e {
        SessionError::Disabled => ServiceError::SessionsDisabled(String::new()),
        SessionError::Busy => ServiceError::SessionBusy,
        SessionError::Ended(_) => ServiceError::SessionNotFound,
        SessionError::InvalidRequest(m) => ServiceError::InvalidRequest(m),
        SessionError::PolicyViolation(m) => ServiceError::PolicyViolation(m),
        SessionError::Internal(m) => ServiceError::Internal(m),
    }
}

fn api_session(s: &Session) -> ApiSession {
    let info = s.info();
    let p = s.policy().session();
    let now = SystemTime::now();
    let created = now.checked_sub(info.age).unwrap_or(now);
    ApiSession {
        session_id: info.id,
        language: info.language.as_str().into(),
        policy: info.policy,
        interpreter: info.interpreter.into(),
        state: if info.ended.is_some() {
            "ended"
        } else if info.busy {
            "busy"
        } else {
            "active"
        }
        .into(),
        ended_reason: info.ended.map(|r| r.as_str().into()),
        calls: info.calls,
        max_calls: p.max_calls,
        created_at: rfc3339_millis(created),
        expires_at: rfc3339_millis(created + p.max_lifetime),
        idle_timeout_s: p.idle_ttl.as_secs(),
    }
}
