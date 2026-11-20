//! Persistent interpreter sessions (cycle 3, C3-U4; `aidlc-docs/cycle-3/construction/c3-u4-sessions`).
//!
//! A [`Session`] is one live interpreter (one wasmtime `Store`, owned by an actor task) that
//! serves a sequence of calls. The guest runs a loop (`sandboxd_session.py` / `session.mjs`) that
//! reads call frames from `/dev/sandbox/session`; [`Session::call`] releases one frame and waits
//! for the guest's reply.
//!
//! * Per call: stdout/stderr, `/out`, the wall-clock deadline and the fuel budget.
//! * Per session: interpreter state, `/work`, `/in`, network quotas and the memory limit.
//!
//! Fuel. The store gets effectively unlimited fuel; [`CallCtl`] tracks what each call consumes
//! from the moment the guest picks up its frame (a call hook) to its reply (the same hook, before
//! the write). The budget and deadline are checked at every host call and every epoch tick, so a
//! guest is stopped at most one tick ([`crate::EPOCH_TICK`]) plus `FUEL_SYNC` fuel after it
//! overruns. Between calls the
//! guest may only run the few instructions of its loop: an *idle guard* stops one that keeps
//! computing (e.g. a cell that wrote a fake reply), so no code ever runs without a budget.

use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use sandboxd_audit::{AuditEvent, EventKind, FileDigest, LimitKind, Outcome, RunId, sha256_hex};
use sandboxd_net::{NetReport, RunCtx, RunNet};
use sandboxd_policy::{Overrides, Policy};
use sandboxd_vfs::{
    CallIds, DeviceFuture, InputFile, QuotaHandle, RunFs, VfsError, VirtualDevice, VirtualFdTable,
};
use tokio::{
    sync::{OwnedSemaphorePermit, mpsc, oneshot},
    task::JoinHandle,
};
use wasmtime::{AsContext, CallHook, Store, Trap, UpdateDeadline};
use wasmtime_wasi::{WasiCtxBuilder, p1::types::Errno};

use crate::{
    helpers::{JS_BOOT, JS_SESSION, PYTHON_SESSION_LAUNCHER},
    native,
    sandbox::{
        EPOCH_TICK, MemLimiter, RunState, Sandbox, WallClockExceeded, end_event, ms, register_info,
        sanitize_trap,
    },
    stream::CappedStream,
    types::{Language, RunError, RunEvent, RunResult, Timings},
};

/// Fuel given to a session's store (≈ decades of CPU); budgets are per call (see module docs).
const SESSION_FUEL: u64 = 1 << 62;
/// How often (in fuel, ≈ 2 ms of CPU) the guest syncs its fuel counter for the budget checks.
const FUEL_SYNC: u64 = 10_000_000;
/// Fuel the guest may burn between calls (its loop needs a tiny fraction of this).
const IDLE_FUEL: u64 = 200_000_000;
/// How long a closing session's guest gets to leave its loop before it is aborted.
const CLOSE_GRACE: Duration = Duration::from_secs(2);

/// Why a session ended (`session.end` reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionEnd {
    /// Closed by its owner.
    Closed,
    /// No call within `idle_ttl`.
    Idle,
    /// `max_lifetime` reached.
    Lifetime,
    /// `max_calls` reached.
    MaxCalls,
    /// A call hit the wall-clock or CPU limit (or memory, if the interpreter could not recover).
    Limit,
    /// The guest exited (e.g. `os._exit`, `std.exit`).
    Exited,
    /// Server shutdown.
    Shutdown,
    /// Start-up failure or crash.
    Error,
}

impl SessionEnd {
    /// Lower-case name for APIs, audit and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            SessionEnd::Closed => "closed",
            SessionEnd::Idle => "idle",
            SessionEnd::Lifetime => "lifetime",
            SessionEnd::MaxCalls => "max_calls",
            SessionEnd::Limit => "limit",
            SessionEnd::Exited => "exited",
            SessionEnd::Shutdown => "shutdown",
            SessionEnd::Error => "error",
        }
    }
}

impl std::fmt::Display for SessionEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a session could not be created or a call could not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The policy does not enable sessions (`[session] enabled = false`).
    Disabled,
    /// Another call is running in this session (one call at a time).
    Busy,
    /// The session has ended.
    Ended(SessionEnd),
    /// The request is invalid (sizes, names, overrides, stdin).
    InvalidRequest(String),
    /// Overrides would widen the policy, or the policy needs something this runtime lacks.
    PolicyViolation(String),
    /// Host-side failure (never the guest's fault).
    Internal(String),
}

impl SessionError {
    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            SessionError::Disabled => "SESSIONS_DISABLED",
            SessionError::Busy => "SESSION_BUSY",
            SessionError::Ended(_) => "SESSION_ENDED",
            SessionError::InvalidRequest(_) => "INVALID_REQUEST",
            SessionError::PolicyViolation(_) => "POLICY_VIOLATION",
            SessionError::Internal(_) => "INTERNAL",
        }
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Disabled => f.write_str("this policy does not enable sessions"),
            SessionError::Busy => f.write_str("another call is running in this session"),
            SessionError::Ended(r) => write!(f, "the session has ended ({r})"),
            SessionError::InvalidRequest(m)
            | SessionError::PolicyViolation(m)
            | SessionError::Internal(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for SessionError {}

/// How to create a session.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub language: Language,
    /// Files placed under `/in` for the whole session.
    pub files: Vec<InputFile>,
    /// Limit-only overrides for the whole session; can only tighten the policy.
    pub overrides: Overrides,
}

impl SessionOptions {
    /// A session for `language` with no files and no overrides.
    pub fn new(language: Language) -> Self {
        Self {
            language,
            files: Vec::new(),
            overrides: Overrides::default(),
        }
    }
}

/// One call in a session.
#[derive(Debug, Clone, Default)]
pub struct CallRequest {
    pub code: String,
    pub args: Vec<String>,
    /// Not supported in sessions (must be `None` or empty): send data as a file.
    pub stdin: Option<Vec<u8>>,
    /// More files under `/in` (new names only; counted against the session's `input_bytes`).
    pub files: Vec<InputFile>,
    /// Only `wall_clock` and `fuel` may be set (and only tighter than the session's).
    pub overrides: Overrides,
}

impl CallRequest {
    /// A call with just code.
    pub fn new(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            ..Self::default()
        }
    }
}

/// A finished call.
#[derive(Debug, Clone)]
pub struct CallOutcome {
    pub result: RunResult,
    /// Set when this call ended the session (limit, guest exit, `max_calls`).
    pub ended: Option<SessionEnd>,
}

/// A snapshot of a session's state.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: String,
    pub language: Language,
    pub policy: String,
    pub principal: String,
    /// `snapshot` or `upstream`.
    pub interpreter: &'static str,
    pub calls: u64,
    pub age: Duration,
    pub idle: Duration,
    pub busy: bool,
    pub ended: Option<SessionEnd>,
}

// ---- per-call accounting -------------------------------------------------------------------

#[derive(Debug)]
struct CallState {
    /// Bumped by the host for each call.
    generation: u64,
    /// The generation whose frame the guest has read (set by the device, not the host, so a
    /// guest that never went back to its loop can't start the next call's budget).
    delivered: u64,
    /// The generation whose budget is running.
    armed: u64,
    /// A call (or start-up) is running: budgets apply.
    active: bool,
    deadline: Option<Instant>,
    fuel_limit: u64,
    fuel_start: u64,
    fuel_now: u64,
    /// Fuel when the guest last went idle (idle guard).
    idle_from: u64,
    peak: usize,
    denied: bool,
}

type CallCtl = Arc<Mutex<CallState>>;

fn lock(c: &CallCtl) -> MutexGuard<'_, CallState> {
    c.lock().unwrap_or_else(|p| p.into_inner())
}

/// Raised when a call exceeds its fuel budget (reported as the CPU limit).
#[derive(Debug)]
struct CpuExceeded;
impl std::fmt::Display for CpuExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fuel limit exceeded")
    }
}
impl std::error::Error for CpuExceeded {}

/// Budget checks, shared by the call hook and the epoch callback.
fn check(st: &mut CallState, fuel: u64) -> wasmtime::Result<()> {
    if st.active {
        st.fuel_now = fuel;
        if st.fuel_start.saturating_sub(fuel) > st.fuel_limit {
            return Err(wasmtime::Error::new(CpuExceeded));
        }
        if st.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(wasmtime::Error::new(WallClockExceeded));
        }
    } else if st.idle_from.saturating_sub(fuel) > IDLE_FUEL {
        return Err(wasmtime::Error::new(CpuExceeded));
    }
    Ok(())
}

fn go_idle(ctl: &CallCtl) {
    let mut st = lock(ctl);
    st.active = false;
    st.deadline = None;
    st.idle_from = st.fuel_now;
}

// ---- the session device --------------------------------------------------------------------

/// `/dev/sandbox/session`: reads block until the next call's frame; a write is the reply.
struct SessionDevice {
    frames: mpsc::Receiver<Vec<u8>>,
    replies: mpsc::UnboundedSender<Vec<u8>>,
    ctl: CallCtl,
    ready: Option<oneshot::Sender<()>>,
    pending: Vec<u8>,
    off: usize,
}

impl VirtualDevice for SessionDevice {
    fn opened(&mut self) -> DeviceFuture<'_, ()> {
        Box::pin(async move {
            // Start-up is over: the loop is about to wait for its first call.
            go_idle(&self.ctl);
            if let Some(r) = self.ready.take() {
                let _ = r.send(());
            }
            Ok(())
        })
    }
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> DeviceFuture<'a, usize> {
        Box::pin(async move {
            if self.off >= self.pending.len() {
                match self.frames.recv().await {
                    Some(f) => {
                        self.pending = f;
                        self.off = 0;
                        let mut st = lock(&self.ctl);
                        st.delivered = st.generation;
                    }
                    None => return Ok(0), // session over
                }
            }
            let n = (self.pending.len() - self.off).min(buf.len());
            buf[..n].copy_from_slice(&self.pending[self.off..self.off + n]);
            self.off += n;
            Ok(n)
        })
    }
    fn write<'a>(&'a mut self, buf: &'a [u8]) -> DeviceFuture<'a, usize> {
        Box::pin(async move {
            if !lock(&self.ctl).active {
                return Err(Errno::Badf); // no call is waiting for a reply
            }
            go_idle(&self.ctl);
            let _ = self.replies.send(buf.to_vec());
            Ok(buf.len())
        })
    }
    fn close(&mut self) -> DeviceFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

// ---- the session ---------------------------------------------------------------------------

/// What the actor task returns when the guest stops.
struct ActorExit {
    result: wasmtime::Result<()>,
    peak: usize,
    denied: bool,
    fuel: u64,
}

struct Live {
    fs: Option<RunFs>,
    frames: Option<mpsc::Sender<Vec<u8>>>,
    replies: mpsc::UnboundedReceiver<Vec<u8>>,
    actor: Option<JoinHandle<ActorExit>>,
    stdout: CappedStream,
    stderr: CappedStream,
    quota: QuotaHandle,
    ids: CallIds,
    net: Option<RunNet>,
    net_prev: NetReport,
    ctl: CallCtl,
    cell: u64,
    inputs_used: u64,
    _slot: Option<OwnedSemaphorePermit>,
}

#[derive(Debug)]
struct Meta {
    calls: u64,
    last_used: Instant,
    ended: Option<SessionEnd>,
}

struct Shared {
    id: String,
    language: Language,
    policy: Arc<Policy>,
    principal: String,
    interpreter: &'static str,
    created: Instant,
    sandbox: Sandbox,
    live: tokio::sync::Mutex<Live>,
    meta: Mutex<Meta>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        // Dropped without `close`: stop the guest (the store, then the run dir, go with it).
        let live = self.live.get_mut();
        live.frames.take();
        if let Some(a) = live.actor.take() {
            a.abort();
        }
    }
}

/// A live interpreter session. Cloning shares the same session.
#[derive(Clone)]
pub struct Session {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.shared.id)
            .field("language", &self.shared.language)
            .finish_non_exhaustive()
    }
}

fn new_session_id() -> String {
    format!("ses_{}", uuid::Uuid::new_v4().simple())
}

fn vfs_error(e: VfsError) -> SessionError {
    match e {
        VfsError::InvalidInput(_) | VfsError::InputsTooLarge { .. } => {
            SessionError::InvalidRequest(e.to_string())
        }
        _ => SessionError::Internal(format!("filesystem: {e}")),
    }
}

impl Sandbox {
    /// Start a session: a live interpreter waiting for [`Session::call`]s.
    pub async fn open_session(
        &self,
        opts: SessionOptions,
        policy: Arc<Policy>,
        principal: &str,
    ) -> Result<Session, SessionError> {
        let inner = &self.inner;
        let cfg = &inner.cfg;
        let audit = inner.audit.clone();
        let id = new_session_id();
        let run_id = RunId::new();
        let lang = opts.language;
        let denied = |what: String| {
            audit.emit(
                AuditEvent::new(EventKind::PolicyDenied {
                    what,
                    requested: None,
                })
                .policy(policy.name())
                .principal(principal)
                .session(id.clone()),
            );
        };
        if !policy.session().enabled {
            denied("sessions are not enabled by this policy".into());
            return Err(SessionError::Disabled);
        }
        let policy = match policy.tighten(&opts.overrides) {
            Ok(p) => Arc::new(p),
            Err(e) => {
                denied(e.to_string());
                return Err(SessionError::PolicyViolation(e.to_string()));
            }
        };
        if policy.network().grants_anything() && cfg.broker.is_none() {
            let msg = "this policy grants network access, but network access is not configured on this runtime";
            denied(msg.into());
            return Err(SessionError::PolicyViolation(msg.into()));
        }
        let limits = *policy.limits();
        let snap = match lang {
            Language::Python => inner.py_snap.as_ref(),
            Language::JavaScript => inner.js_snap.as_ref(),
        }
        .filter(|s| limits.memory.bytes() >= s.floor);
        let interpreter = if snap.is_some() {
            "snapshot"
        } else {
            "upstream"
        };
        let (argv, pre, entry): (Vec<&str>, _, _) = match (lang, snap) {
            (Language::Python, Some(s)) => (vec!["python"], s.pre.clone(), "sandboxd-session"),
            (Language::JavaScript, Some(s)) => (vec!["qjs"], s.pre.clone(), "sandboxd-session"),
            (Language::Python, None) => (
                vec![
                    "python",
                    "-I",
                    "-B",
                    "-S",
                    "-X",
                    "frozen_modules=on",
                    "-c",
                    PYTHON_SESSION_LAUNCHER,
                ],
                inner.python.clone(),
                "_start",
            ),
            (Language::JavaScript, None) => (
                vec!["qjs", "--std", "-m", "-I", JS_BOOT, JS_SESSION],
                inner.javascript.clone(),
                "_start",
            ),
        };

        // Filesystem: /in (session files), an empty /code for cells, /work, helpers.
        let inputs_used: u64 = opts.files.iter().map(|f| f.bytes.len() as u64).sum();
        let stdlib = (lang == Language::Python).then_some(inner.stdlib.as_path());
        let fs = RunFs::create(&cfg.vfs, &policy, run_id, opts.files, stdlib, audit.clone())
            .and_then(RunFs::with_code_dir)
            .and_then(RunFs::with_work)
            .and_then(|f| f.with_helpers(&inner.helpers))
            .map_err(vfs_error)?;
        let ids = fs.call_ids();
        ids.set(run_id, Some(id.clone()));

        // WASI context: no stdin (calls send files), output re-armed per call.
        let stdout = CappedStream::new(limits.stdout.bytes(), LimitKind::Stdout, None);
        let stderr = CappedStream::new(limits.stderr.bytes(), LimitKind::Stderr, None);
        let mut b = WasiCtxBuilder::new();
        b.args(&argv).stdout(stdout.clone()).stderr(stderr.clone());
        for (k, v) in policy.env() {
            b.env(k, v);
        }
        fs.preopen(&mut b, &policy)
            .map_err(|e| SessionError::Internal(e.to_string()))?;

        let mut vfds = VirtualFdTable::default();
        register_info(&mut vfds, &policy);
        let net = match cfg.broker.as_ref().map(|b| {
            b.for_run(
                &policy,
                RunCtx {
                    run_id,
                    policy: policy.name().to_string(),
                    deadline: Instant::now() + limits.wall_clock,
                    audit: audit.clone(),
                    session_id: Some(id.clone()),
                },
            )
        }) {
            None | Some(Ok(None)) => None,
            Some(Ok(Some(n))) => Some(n),
            Some(Err(e)) => return Err(SessionError::Internal(format!("network setup: {e}"))),
        };
        if let Some(n) = &net {
            n.register(&mut vfds);
        }
        let ctl: CallCtl = Arc::new(Mutex::new(CallState {
            generation: 0,
            delivered: 0,
            armed: 0,
            active: true, // start-up runs under the call budgets
            deadline: Some(Instant::now() + limits.wall_clock),
            fuel_limit: limits.fuel,
            fuel_start: SESSION_FUEL,
            fuel_now: SESSION_FUEL,
            idle_from: SESSION_FUEL,
            peak: 0,
            denied: false,
        }));
        let (frames_tx, frames_rx) = mpsc::channel::<Vec<u8>>(1);
        let (replies_tx, replies_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (ready_tx, ready_rx) = oneshot::channel::<()>();
        let device = Mutex::new(Some(SessionDevice {
            frames: frames_rx,
            replies: replies_tx,
            ctl: ctl.clone(),
            ready: Some(ready_tx),
            pending: Vec::new(),
            off: 0,
        }));
        vfds.register(
            "session",
            Box::new(move |rel: &str| {
                if rel != "session" {
                    return Err(Errno::Noent);
                }
                // One open per session: the loop's. Cells can't open a second handle.
                device
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take()
                    .map(|d| Box::new(d) as Box<dyn VirtualDevice>)
                    .ok_or(Errno::Busy)
            }),
        );
        let interposer = fs.interposer(b.build_p1(), vfds);
        let quota = interposer.quota_handle();

        let slot = match &inner.slots {
            Some((_, sem)) => sem.clone().acquire_owned().await.ok(),
            None => None,
        };
        let mut store = Store::new(
            &inner.engine,
            RunState {
                interposer,
                limiter: MemLimiter {
                    max: usize::try_from(limits.memory.bytes()).unwrap_or(usize::MAX),
                    peak: 0,
                    denied: false,
                },
            },
        );
        store.limiter(|s| &mut s.limiter);
        let _ = store.set_fuel(SESSION_FUEL);
        // Compiled code keeps the fuel counter in a register and only writes it back at some
        // points (a hot loop without calls never does), so the epoch callback could read a stale
        // value. A fuel yield interval makes the guest sync it every FUEL_SYNC units (found by the
        // C3-U4 busy-loop test).
        let _ = store.fuel_async_yield_interval(Some(FUEL_SYNC));
        {
            let ctl = ctl.clone();
            store.call_hook(move |mut s, hook| {
                let fuel = s.as_context().get_fuel().unwrap_or(0);
                let mut st = lock(&ctl);
                match hook {
                    // The guest picked up a new call's frame: start its budget.
                    CallHook::ReturningFromHost if st.delivered != st.armed => {
                        st.armed = st.delivered;
                        st.active = true;
                        st.fuel_start = fuel;
                        st.fuel_now = fuel;
                        st.denied = false;
                        s.data_mut().limiter.denied = false;
                        Ok(())
                    }
                    CallHook::CallingHost if st.active => {
                        let l = &s.data().limiter;
                        st.peak = l.peak;
                        st.denied = l.denied;
                        check(&mut st, fuel)
                    }
                    _ => Ok(()),
                }
            });
        }
        {
            let ctl = ctl.clone();
            store.epoch_deadline_callback(move |s| {
                let fuel = s.as_context().get_fuel().unwrap_or(0);
                check(&mut lock(&ctl), fuel)?;
                Ok(UpdateDeadline::Yield(1))
            });
        }
        store.set_epoch_deadline(1);

        let mut actor = tokio::spawn(async move {
            let result = async {
                let inst = pre.instantiate_async(&mut store).await?;
                let start = inst.get_typed_func::<(), ()>(&mut store, entry)?;
                start.call_async(&mut store, ()).await
            }
            .await;
            let l = &store.data().limiter;
            ActorExit {
                result,
                peak: l.peak,
                denied: l.denied,
                fuel: store.get_fuel().unwrap_or(0),
            }
        });

        // Wait until the loop has opened its device (start-up budgets apply meanwhile).
        let mut joined = false;
        let started = tokio::select! {
            r = ready_rx => r.is_ok(),
            _ = &mut actor => {
                joined = true;
                false
            }
            _ = tokio::time::sleep(limits.wall_clock + EPOCH_TICK * 5) => false,
        };
        if !started {
            if !joined {
                actor.abort();
                let _ = actor.await;
            }
            let (err, _) = stderr.take();
            let detail = String::from_utf8_lossy(&err);
            let detail = detail
                .lines()
                .last()
                .unwrap_or("")
                .chars()
                .take(300)
                .collect::<String>();
            audit.emit(
                AuditEvent::new(EventKind::SessionEnd {
                    reason: SessionEnd::Error.as_str().into(),
                    calls: 0,
                    duration_ms: 0,
                })
                .policy(policy.name())
                .principal(principal)
                .session(id.clone()),
            );
            return Err(SessionError::Internal(format!(
                "the {lang} session interpreter did not start{}",
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            )));
        }
        audit.emit(
            AuditEvent::new(EventKind::SessionStart {
                lang: lang.as_str().into(),
            })
            .policy(policy.name())
            .principal(principal)
            .session(id.clone()),
        );

        Ok(Session {
            shared: Arc::new(Shared {
                id,
                language: lang,
                principal: principal.to_string(),
                interpreter,
                created: Instant::now(),
                sandbox: self.clone(),
                live: tokio::sync::Mutex::new(Live {
                    fs: Some(fs),
                    frames: Some(frames_tx),
                    replies: replies_rx,
                    actor: Some(actor),
                    stdout,
                    stderr,
                    quota,
                    ids,
                    net,
                    net_prev: NetReport::default(),
                    ctl,
                    cell: 0,
                    inputs_used,
                    _slot: slot,
                }),
                meta: Mutex::new(Meta {
                    calls: 0,
                    last_used: Instant::now(),
                    ended: None,
                }),
                policy,
            }),
        })
    }
}

enum Waited {
    Reply(Vec<u8>),
    /// The guest closed the device without replying (it is exiting).
    ReplyClosed,
    Exited(Option<ActorExit>),
    TimedOut,
}

impl Session {
    /// `ses_<32 hex>`.
    pub fn id(&self) -> &str {
        &self.shared.id
    }

    /// Who created the session.
    pub fn principal(&self) -> &str {
        &self.shared.principal
    }

    /// The session's (tightened) policy.
    pub fn policy(&self) -> &Arc<Policy> {
        &self.shared.policy
    }

    pub fn language(&self) -> Language {
        self.shared.language
    }

    fn meta(&self) -> MutexGuard<'_, Meta> {
        self.shared.meta.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Current state.
    pub fn info(&self) -> SessionInfo {
        let m = self.meta();
        SessionInfo {
            id: self.shared.id.clone(),
            language: self.shared.language,
            policy: self.shared.policy.name().to_string(),
            principal: self.shared.principal.clone(),
            interpreter: self.shared.interpreter,
            calls: m.calls,
            age: self.shared.created.elapsed(),
            idle: m.last_used.elapsed(),
            busy: self.shared.live.try_lock().is_err(),
            ended: m.ended,
        }
    }

    /// Run one call. Errors are for requests that never reached the guest; everything that ran
    /// is a [`CallOutcome`] (whose result may itself be an error, a limit or an exit).
    pub async fn call(
        &self,
        req: CallRequest,
        events: Option<mpsc::Sender<RunEvent>>,
    ) -> Result<CallOutcome, SessionError> {
        let sh = &self.shared;
        let mut guard = sh.live.try_lock().map_err(|_| SessionError::Busy)?;
        let live = &mut *guard;
        if let Some(end) = self.meta().ended {
            return Err(SessionError::Ended(end));
        }
        let session_pol = sh.policy.session();
        if sh.created.elapsed() >= session_pol.max_lifetime {
            self.finish(live, SessionEnd::Lifetime).await;
            return Err(SessionError::Ended(SessionEnd::Lifetime));
        }
        let t0 = Instant::now();
        let cfg = &sh.sandbox.inner.cfg;
        let audit = sh.sandbox.inner.audit.clone();
        let lang = sh.language;

        // 1. Validation.
        if req.code.len() > cfg.max_code_bytes {
            return Err(SessionError::InvalidRequest(format!(
                "code is {} bytes; max {}",
                req.code.len(),
                cfg.max_code_bytes
            )));
        }
        if req.args.len() > cfg.max_args
            || req
                .args
                .iter()
                .any(|a| a.len() > cfg.max_arg_bytes || a.contains('\0'))
        {
            return Err(SessionError::InvalidRequest(format!(
                "at most {} args of {} bytes, no NUL",
                cfg.max_args, cfg.max_arg_bytes
            )));
        }
        if req.stdin.as_ref().is_some_and(|s| !s.is_empty()) {
            return Err(SessionError::InvalidRequest(
                "stdin is not supported in session calls; send the data as a file (it appears under /in)".into(),
            ));
        }
        let o = &req.overrides;
        if o.memory.is_some()
            || o.stdout.is_some()
            || o.stderr.is_some()
            || o.artifact_count.is_some()
            || o.artifact_bytes.is_some()
            || o.input_bytes.is_some()
        {
            return Err(SessionError::InvalidRequest(
                "a session call may only override wall_clock and fuel; set other limits when creating the session".into(),
            ));
        }
        let limits = match sh.policy.tighten(o) {
            Ok(p) => *p.limits(),
            Err(e) => {
                audit.emit(
                    AuditEvent::new(EventKind::PolicyDenied {
                        what: e.to_string(),
                        requested: None,
                    })
                    .policy(sh.policy.name())
                    .principal(&sh.principal)
                    .session(sh.id.clone()),
                );
                return Err(SessionError::PolicyViolation(e.to_string()));
            }
        };
        let Some(fs) = live.fs.as_ref() else {
            return Err(SessionError::Ended(SessionEnd::Error));
        };

        // 2. Cell file and inputs.
        let cell = live.cell + 1;
        let name = format!(
            "cell_{cell}.{}",
            match lang {
                Language::Python => "py",
                Language::JavaScript => "js",
            }
        );
        let budget = sh
            .policy
            .limits()
            .input_bytes
            .bytes()
            .saturating_sub(live.inputs_used);
        let added = fs.add_inputs(&req.files, budget).map_err(vfs_error)?;
        fs.write_code(&name, req.code.as_bytes())
            .map_err(vfs_error)?;
        live.cell = cell;
        live.inputs_used += added;

        let run_id = RunId::new();
        audit.emit(
            AuditEvent::new(EventKind::RunStart {
                interpreter: Some(sh.interpreter.into()),
                lang: lang.as_str().into(),
                code_sha256: sha256_hex(req.code.as_bytes()),
                code_bytes: req.code.len() as u64,
                code: sh.policy.audit().log_code.then(|| req.code.clone()),
                inputs: req
                    .files
                    .iter()
                    .map(|f| FileDigest {
                        name: f.name.clone(),
                        bytes: f.bytes.len() as u64,
                        sha256: sha256_hex(&f.bytes),
                    })
                    .collect(),
            })
            .run(run_id)
            .policy(sh.policy.name())
            .principal(&sh.principal)
            .session(sh.id.clone()),
        );

        // 3. Arm this call.
        let (tx, mut rx) = mpsc::unbounded_channel::<RunEvent>();
        let forwarder = events.map(|out| {
            tokio::spawn(async move {
                while let Some(ev) = rx.recv().await {
                    if out.send(ev).await.is_err() {
                        break;
                    }
                }
            })
        });
        live.stdout.rearm(Some(tx.clone()));
        live.stderr.rearm(Some(tx.clone()));
        let (work_bytes, work_files) = fs.work_usage();
        live.quota.reset_to(work_bytes, work_files);
        live.ids.set(run_id, Some(sh.id.clone()));
        let deadline = Instant::now() + limits.wall_clock;
        if let Some(n) = &live.net {
            n.begin_call(run_id, deadline);
        }
        {
            let mut st = lock(&live.ctl);
            st.generation += 1;
            st.deadline = Some(deadline);
            st.fuel_limit = limits.fuel;
        }
        let frame = serde_json::json!({
            "cell": cell,
            "path": format!("{}/{name}", sandboxd_policy::CODE_GUEST_PATH),
            "args": req.args,
        });
        let setup_ms = ms(t0.elapsed());

        // 4. Run: release the frame, wait for the reply (or the guest stopping, or the clock).
        let t_run = Instant::now();
        let sent = match &live.frames {
            Some(f) => f
                .send(serde_json::to_vec(&frame).unwrap_or_default())
                .await
                .is_ok(),
            None => false,
        };
        let mut waited = match live.actor.as_mut() {
            None => Waited::Exited(None),
            Some(_) if !sent => Waited::ReplyClosed,
            Some(actor) => {
                tokio::select! {
                    r = live.replies.recv() => match r {
                        Some(b) => Waited::Reply(b),
                        None => Waited::ReplyClosed,
                    },
                    a = &mut *actor => Waited::Exited(a.ok()),
                    _ = tokio::time::sleep(limits.wall_clock + EPOCH_TICK * 5) => Waited::TimedOut,
                }
            }
        };
        if matches!(waited, Waited::ReplyClosed) {
            // The guest dropped its device: it is on its way out.
            waited = match live.actor.as_mut() {
                Some(actor) => {
                    match tokio::time::timeout(limits.wall_clock + EPOCH_TICK * 5, &mut *actor)
                        .await
                    {
                        Ok(a) => Waited::Exited(a.ok()),
                        Err(_) => Waited::TimedOut,
                    }
                }
                None => Waited::Exited(None),
            };
        }
        if matches!(waited, Waited::Exited(_)) {
            live.actor = None; // joined: must not be polled again
        }
        let run_ms = ms(t_run.elapsed());

        // 5. Classify.
        let mut limits_hit: Vec<LimitKind> = Vec::new();
        let mut error: Option<RunError> = None;
        let (mut out, mut exit_code, mut ended) = (Outcome::Ok, None, None);
        let (fuel_used, peak, denied) = {
            let st = lock(&live.ctl);
            (
                st.fuel_start.saturating_sub(st.fuel_now),
                st.peak,
                st.denied,
            )
        };
        let (mut fuel_used, mut peak, mut denied) = (fuel_used, peak, denied);
        match waited {
            Waited::Reply(bytes) => {
                let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
                let code = v["exit_code"]
                    .as_i64()
                    .and_then(|c| i32::try_from(c).ok())
                    .unwrap_or(1);
                exit_code = Some(code);
                if code != 0 {
                    out = Outcome::Exit;
                }
            }
            Waited::TimedOut => {
                out = Outcome::Limit;
                limits_hit.push(LimitKind::WallClock);
                ended = Some(SessionEnd::Limit);
            }
            Waited::ReplyClosed | Waited::Exited(None) => {
                out = Outcome::Trap;
                error = Some(RunError::Internal("the session interpreter stopped".into()));
                ended = Some(SessionEnd::Error);
            }
            Waited::Exited(Some(ax)) => {
                let st = lock(&live.ctl);
                fuel_used = st.fuel_start.saturating_sub(ax.fuel);
                peak = ax.peak;
                denied = ax.denied;
                drop(st);
                ended = Some(SessionEnd::Exited);
                match ax.result {
                    Ok(()) => exit_code = Some(0),
                    Err(e) => {
                        if let Some(code) = e.downcast_ref::<wasmtime_wasi::I32Exit>() {
                            exit_code = Some(code.0);
                            if code.0 != 0 {
                                out = Outcome::Exit;
                            }
                        } else if e.downcast_ref::<WallClockExceeded>().is_some() {
                            out = Outcome::Limit;
                            limits_hit.push(LimitKind::WallClock);
                            ended = Some(SessionEnd::Limit);
                        } else if e.downcast_ref::<CpuExceeded>().is_some()
                            || e.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel)
                        {
                            out = Outcome::Limit;
                            limits_hit.push(LimitKind::Cpu);
                            ended = Some(SessionEnd::Limit);
                        } else if ax.denied {
                            out = Outcome::Limit;
                            ended = Some(SessionEnd::Limit);
                        } else {
                            out = Outcome::Trap;
                            error = Some(RunError::Trap(sanitize_trap(&e)));
                            ended = Some(SessionEnd::Error);
                        }
                    }
                }
            }
        }
        if denied {
            limits_hit.push(LimitKind::Memory);
            if out == Outcome::Exit || out == Outcome::Trap {
                out = Outcome::Limit;
                error = None;
            }
        }

        // 6. Collect this call's outputs.
        let t_collect = Instant::now();
        let mut artifacts = Vec::new();
        if let Some(fs) = live.fs.as_ref() {
            match fs.collect_artifacts() {
                Ok(c) => {
                    if c.limit_hit.is_some() {
                        limits_hit.push(LimitKind::Artifacts);
                    }
                    artifacts = c.artifacts;
                }
                Err(e) => {
                    error.get_or_insert(RunError::Internal(format!("artifact collection: {e}")));
                }
            }
            if let Err(e) = fs.clear_outputs() {
                error.get_or_insert(RunError::Internal(format!("clearing /out: {e}")));
            }
        }
        if live.quota.get().hit {
            limits_hit.push(LimitKind::Artifacts);
        }
        let net_now = live.net.as_ref().map(|n| n.finish()).unwrap_or_default();
        let net_requests = net_now.requests.saturating_sub(live.net_prev.requests);
        if net_now.limit_hit && !live.net_prev.limit_hit {
            limits_hit.push(LimitKind::Network);
        }
        live.net_prev = net_now;
        if live.stdout.truncated() {
            limits_hit.push(LimitKind::Stdout);
        }
        if live.stderr.truncated() {
            limits_hit.push(LimitKind::Stderr);
        }
        limits_hit.dedup();
        if matches!(out, Outcome::Ok | Outcome::Exit) && !limits_hit.is_empty() {
            out = Outcome::Limit;
        }
        let (stdout_b, stdout_trunc) = live.stdout.take();
        let (stderr_b, stderr_trunc) = live.stderr.take();
        // Stop streaming to this call (and release its event sender).
        live.stdout.rearm(None);
        live.stderr.rearm(None);
        if error.is_none()
            && lang == Language::Python
            && let Some(module) = native::detect(&stderr_b)
        {
            error = Some(RunError::UnsupportedNativeExtension { module });
        }
        let collect_ms = ms(t_collect.elapsed());

        let result = RunResult {
            run_id,
            language: lang,
            policy: sh.policy.name().to_string(),
            outcome: out,
            exit_code,
            stdout: stdout_b,
            stderr: stderr_b,
            stdout_truncated: stdout_trunc,
            stderr_truncated: stderr_trunc,
            artifacts,
            limits_hit,
            error,
            fuel_used,
            peak_memory: peak as u64,
            net_requests,
            timings: Timings {
                queued_ms: 0,
                setup_ms,
                run_ms,
                collect_ms,
                total_ms: ms(t0.elapsed()),
            },
        };
        for k in &result.limits_hit {
            if matches!(k, LimitKind::Cpu | LimitKind::WallClock | LimitKind::Memory) {
                let (limit, observed) = match k {
                    LimitKind::Cpu => (limits.fuel, result.fuel_used),
                    LimitKind::WallClock => (ms(limits.wall_clock), run_ms),
                    _ => (sh.policy.limits().memory.bytes(), result.peak_memory),
                };
                audit.emit(
                    AuditEvent::new(EventKind::LimitHit {
                        kind: *k,
                        limit,
                        observed,
                    })
                    .run(run_id)
                    .policy(sh.policy.name())
                    .session(sh.id.clone()),
                );
            }
        }
        audit.emit(end_event(&result, &sh.principal).session(sh.id.clone()));

        let calls = {
            let mut m = self.meta();
            m.calls += 1;
            m.last_used = Instant::now();
            m.calls
        };
        if ended.is_none() && calls >= u64::from(session_pol.max_calls) {
            ended = Some(SessionEnd::MaxCalls);
        }
        if let Some(reason) = ended {
            self.finish(live, reason).await;
        }
        let _ = tx.send(RunEvent::Finished(Box::new(result.clone())));
        drop(tx);
        if let Some(f) = forwarder {
            let _ = f.await;
        }
        Ok(CallOutcome { result, ended })
    }

    /// End the session (waits for a running call to finish). Idempotent.
    pub async fn close(&self, reason: SessionEnd) {
        let mut live = self.shared.live.lock().await;
        self.finish(&mut live, reason).await;
    }

    async fn finish(&self, live: &mut Live, reason: SessionEnd) {
        {
            let mut m = self.meta();
            if m.ended.is_some() {
                return;
            }
            m.ended = Some(reason);
        }
        // EOF on the device: the guest loop returns and the interpreter exits.
        live.frames.take();
        if let Some(mut a) = live.actor.take()
            && tokio::time::timeout(CLOSE_GRACE, &mut a).await.is_err()
        {
            a.abort();
            let _ = a.await;
        }
        live.net = None;
        live.fs = None; // deletes the session's directories
        live._slot = None;
        let sh = &self.shared;
        sh.sandbox.inner.audit.emit(
            AuditEvent::new(EventKind::SessionEnd {
                reason: reason.as_str().into(),
                calls: self.meta().calls,
                duration_ms: ms(sh.created.elapsed()),
            })
            .policy(sh.policy.name())
            .principal(&sh.principal)
            .session(sh.id.clone()),
        );
    }
}
