//! RunService: the single path from any front end to the sandbox (U5 design §1).

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use sandboxd_audit::{AuditEvent, AuditSink, EventKind};
use sandboxd_policy::{PolicyDir, PolicyError, fmt_duration};
use sandboxd_runtime::{RunEvent, RunResult, Sandbox};
use tokio::sync::{Semaphore, mpsc};

use crate::{
    api::{ApiPolicy, ApiRunRequest},
    auth::Principal,
    metrics::{KindLabel, LangLabel, Metrics, RunLabels},
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
        }
    }
}

/// Admission control settings (Q6).
#[derive(Debug, Clone, Copy)]
pub struct AdmissionConfig {
    pub max_concurrent: usize,
    pub queue_depth: usize,
    pub queue_timeout: Duration,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            max_concurrent: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            queue_depth: 64,
            queue_timeout: Duration::from_secs(10),
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
        Self {
            inner: Arc::new(Inner {
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
        }
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
        self.inner.metrics.audit_healthy.set(i64::from(ok));
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
        // S1: fail closed.
        if !self.healthy() {
            m.reject("audit_unavailable");
            return Err(ServiceError::AuditUnavailable);
        }
        // S2: policy.
        let policy_name = req.policy_name().to_string();
        let policy = self.inner.policies.get(&policy_name).map_err(|e| {
            m.reject("policy_not_found");
            self.inner.audit.emit(
                AuditEvent::new(EventKind::PolicyDenied {
                    what: e.to_string(),
                    requested: Some(policy_name.clone()),
                })
                .principal(principal.0.clone()),
            );
            match e {
                PolicyError::NotFound(n) => ServiceError::PolicyNotFound(n),
                other => ServiceError::InvalidRequest(other.to_string()),
            }
        })?;
        // S4: decode before queueing (cheap, and a bad request shouldn't hold a slot).
        let run_req = req.into_run_request().map_err(|e| {
            m.reject("invalid_request");
            ServiceError::InvalidRequest(e)
        })?;
        // S3: admission.
        let t_queue = Instant::now();
        let waiting = self.inner.waiting.fetch_add(1, Ordering::SeqCst);
        if waiting >= self.inner.admission.queue_depth && self.inner.slots.available_permits() == 0
        {
            self.inner.waiting.fetch_sub(1, Ordering::SeqCst);
            m.reject("overloaded");
            return Err(ServiceError::Overloaded);
        }
        m.queue_depth.inc();
        let permit = tokio::time::timeout(
            self.inner.admission.queue_timeout,
            self.inner.slots.clone().acquire_owned(),
        )
        .await;
        self.inner.waiting.fetch_sub(1, Ordering::SeqCst);
        m.queue_depth.dec();
        let Ok(Ok(_permit)) = permit else {
            m.reject("overloaded");
            return Err(ServiceError::Overloaded);
        };
        let queued_ms = u64::try_from(t_queue.elapsed().as_millis()).unwrap_or(u64::MAX);

        // S5: run.
        m.running.inc();
        let mut result = self
            .inner
            .sandbox
            .execute(run_req, policy, &principal.0, events)
            .await;
        m.running.dec();
        result.timings.queued_ms = queued_ms;
        result.timings.total_ms += queued_ms;

        let lang = result.language.as_str().to_string();
        let outcome = serde_json::to_value(result.outcome)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        m.runs
            .get_or_create(&RunLabels {
                language: lang.clone(),
                policy: result.policy.clone(),
                outcome,
            })
            .inc();
        m.duration
            .get_or_create(&LangLabel { language: lang })
            .observe(result.timings.total_ms as f64 / 1000.0);
        for k in &result.limits_hit {
            let kind = serde_json::to_value(k)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default();
            m.limits.get_or_create(&KindLabel { kind }).inc();
        }
        Ok(result)
    }
}
