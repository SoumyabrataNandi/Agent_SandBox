//! The execution engine (U4 design §2–§5).

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use sandboxd_audit::{
    AuditEvent, AuditSink, EventKind, FileDigest, LimitKind, Outcome, RunId, sha256_hex,
};
use sandboxd_net::{Broker, RunCtx};
use sandboxd_policy::Policy;
use sandboxd_vfs::{
    Interposer, RunFs, StaticDevice, VfsConfig, VirtualDevice, VirtualFdTable, ensure_stdlib,
};
use tokio::sync::mpsc;
use wasmtime::{Config, Engine, InstancePre, Linker, ResourceLimiter, Store, Trap, UpdateDeadline};
use wasmtime_wasi::{WasiCtxBuilder, p1::wasi_snapshot_preview1 as p1, p2::pipe::MemoryInputPipe};

use crate::{
    cache::{ModuleCache, ensure_bytecode, ensure_helper_bytecode, python_wasm},
    error::RuntimeError,
    helpers::{JS_BOOT, PYTHON_LAUNCHER, ensure_helpers, python_needs_bootstrap},
    native,
    stream::CappedStream,
    types::{Language, RunError, RunEvent, RunRequest, RunResult, Timings},
};

/// Tunables that are not part of a policy.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub vfs: VfsConfig,
    pub max_code_bytes: usize,
    pub max_args: usize,
    pub max_arg_bytes: usize,
    /// Precompile stdlib bytecode on first use (Q2). Disable only for tests of the cold path.
    pub precompile_stdlib: bool,
    /// Network egress broker (cycle 2). `None`: runs whose policy grants network access are
    /// refused with `POLICY_VIOLATION`; runs without grants are unaffected.
    pub broker: Option<Arc<Broker>>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            vfs: VfsConfig::default_locations(),
            max_code_bytes: 1 << 20,
            max_args: 64,
            max_arg_bytes: 4096,
            precompile_stdlib: true,
            broker: None,
        }
    }
}

/// What `Sandbox::new` did, for logs and the CLI.
#[derive(Debug, Clone, Copy, Default)]
pub struct WarmupReport {
    pub python_cached: bool,
    pub javascript_cached: bool,
    pub bytecode_compiled: bool,
    pub elapsed: Duration,
}

/// Linear-memory limiter (U4 design §4).
#[derive(Debug)]
struct MemLimiter {
    max: usize,
    peak: usize,
    denied: bool,
}

impl ResourceLimiter for MemLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.max {
            self.denied = true;
            return Ok(false);
        }
        self.peak = self.peak.max(desired);
        Ok(true)
    }
    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        Ok(desired <= 1_000_000)
    }
}

struct RunState {
    interposer: Interposer,
    limiter: MemLimiter,
}

/// Raised from the epoch callback when the wall-clock deadline passes.
#[derive(Debug)]
struct WallClockExceeded;
impl std::fmt::Display for WallClockExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wall-clock limit exceeded")
    }
}
impl std::error::Error for WallClockExceeded {}

struct Ticker {
    stop: Arc<AtomicBool>,
}
impl Drop for Ticker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct Inner {
    engine: Engine,
    python: InstancePre<RunState>,
    javascript: InstancePre<RunState>,
    stdlib: PathBuf,
    helpers: PathBuf,
    cfg: RuntimeConfig,
    audit: Arc<dyn AuditSink>,
    _ticker: Ticker,
}

/// Shared, cloneable handle to the engine and prepared interpreters.
#[derive(Clone)]
pub struct Sandbox {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sandbox")
            .field("stdlib", &self.inner.stdlib)
            .finish_non_exhaustive()
    }
}

/// Epoch tick period (wall-clock precision).
pub const EPOCH_TICK: Duration = Duration::from_millis(10);

impl Sandbox {
    /// Build the engine, load or compile both interpreters, provision the stdlib (+ bytecode).
    pub async fn new(
        cfg: RuntimeConfig,
        audit: Arc<dyn AuditSink>,
    ) -> Result<(Sandbox, WarmupReport), RuntimeError> {
        let t0 = Instant::now();
        let mut wc = Config::new();
        wc.consume_fuel(true)
            .epoch_interruption(true)
            // Wasm may use 1 MiB of the 4 MiB async fiber stack; the remaining ~3 MiB is headroom
            // for host calls (WASI, interposer) made from deep in the guest's stack. With equal
            // sizes a deeply recursing guest overflowed the *host* stack and crashed the process
            // (found by escape suite E-MEM / E-CRASH).
            .max_wasm_stack(1 << 20)
            .async_stack_size(4 << 20);
        let engine = Engine::new(&wc).map_err(|e| RuntimeError::Compile(e.to_string()))?;

        let cache = ModuleCache::new(&cfg.vfs.cache_dir, &engine)?;
        let (py_mod, python_cached) = cache.load_or_compile(
            &engine,
            "python",
            sandboxd_assets::PYTHON.sha256,
            python_wasm,
        )?;
        let (js_mod, javascript_cached) = cache.load_or_compile(
            &engine,
            "quickjs",
            sandboxd_assets::JAVASCRIPT.sha256,
            || Ok(sandboxd_assets::JAVASCRIPT.bytes.to_vec()),
        )?;

        let stdlib = ensure_stdlib(&cfg.vfs.cache_dir, &sandboxd_assets::PYTHON)?;
        let helpers = ensure_helpers(&cfg.vfs.cache_dir)?;
        let bytecode_compiled = if cfg.precompile_stdlib {
            let std_new = ensure_bytecode(&engine, &py_mod, &stdlib).await?;
            // Not fatal: without bytecode the helpers load from source.
            let helpers_new = ensure_helper_bytecode(&engine, &py_mod, &stdlib, &helpers)
                .await
                .unwrap_or(false);
            std_new || helpers_new
        } else {
            false
        };

        let mut linker: Linker<RunState> = Linker::new(&engine);
        p1::add_to_linker(&mut linker, |s: &mut RunState| &mut s.interposer)
            .map_err(|e| RuntimeError::Compile(e.to_string()))?;
        let python = linker
            .instantiate_pre(&py_mod)
            .map_err(|e| RuntimeError::Compile(e.to_string()))?;
        let javascript = linker
            .instantiate_pre(&js_mod)
            .map_err(|e| RuntimeError::Compile(e.to_string()))?;

        let stop = Arc::new(AtomicBool::new(false));
        {
            let (engine, stop) = (engine.clone(), stop.clone());
            std::thread::Builder::new()
                .name("sandboxd-epoch".into())
                .spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        std::thread::sleep(EPOCH_TICK);
                        engine.increment_epoch();
                    }
                })
                .map_err(|e| RuntimeError::Io(format!("spawn epoch ticker: {e}")))?;
        }

        let report = WarmupReport {
            python_cached,
            javascript_cached,
            bytecode_compiled,
            elapsed: t0.elapsed(),
        };
        Ok((
            Sandbox {
                inner: Arc::new(Inner {
                    engine,
                    python,
                    javascript,
                    stdlib,
                    helpers,
                    cfg,
                    audit,
                    _ticker: Ticker { stop },
                }),
            },
            report,
        ))
    }

    /// Run one request. Never panics and never returns `Err`: every failure is a `RunResult`.
    /// `events` (optional) receives streamed output and is always sent `Finished` last.
    pub async fn execute(
        &self,
        req: RunRequest,
        policy: Arc<Policy>,
        principal: &str,
        events: Option<mpsc::Sender<RunEvent>>,
    ) -> RunResult {
        let run_id = RunId::new();
        let (lang, pol_name) = (req.language, policy.name().to_string());
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
        let inner = self.inner.clone();
        let principal_s = principal.to_string();
        let task_tx = tx.clone();
        let handle =
            tokio::spawn(
                async move { run(inner, req, policy, run_id, principal_s, task_tx).await },
            );
        let result = match handle.await {
            Ok(r) => r,
            Err(e) => {
                let msg = if e.is_panic() {
                    "internal panic during run"
                } else {
                    "run task cancelled"
                };
                let r = failed(
                    run_id,
                    lang,
                    &pol_name,
                    RunError::Internal(msg.into()),
                    Timings::default(),
                );
                self.inner.audit.emit(end_event(&r, principal));
                r
            }
        };
        let _ = tx.send(RunEvent::Finished(Box::new(result.clone())));
        drop(tx);
        if let Some(f) = forwarder {
            let _ = f.await;
        }
        result
    }

    /// The engine (shared with tooling such as `cache warm`).
    pub fn engine(&self) -> &Engine {
        &self.inner.engine
    }
}

fn failed(
    run_id: RunId,
    language: Language,
    policy: &str,
    error: RunError,
    timings: Timings,
) -> RunResult {
    RunResult {
        run_id,
        language,
        policy: policy.to_string(),
        outcome: Outcome::Error,
        exit_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        artifacts: Vec::new(),
        limits_hit: Vec::new(),
        error: Some(error),
        fuel_used: 0,
        peak_memory: 0,
        timings,
    }
}

fn end_event(r: &RunResult, principal: &str) -> AuditEvent {
    AuditEvent::new(EventKind::RunEnd {
        outcome: r.outcome,
        exit_code: r.exit_code,
        duration_ms: r.timings.total_ms,
        fuel_used: Some(r.fuel_used),
        peak_memory: Some(r.peak_memory),
        limits_hit: r.limits_hit.clone(),
        stdout_bytes: r.stdout.len() as u64,
        stderr_bytes: r.stderr.len() as u64,
        artifacts: r
            .artifacts
            .iter()
            .map(|a| FileDigest {
                name: a.name.clone(),
                bytes: a.bytes.len() as u64,
                sha256: a.sha256.clone(),
            })
            .collect(),
    })
    .run(r.run_id)
    .policy(r.policy.clone())
    .principal(principal)
}

/// `/dev/sandbox/info`: the policy name and which network families it grants (nothing else).
fn register_info(vfds: &mut VirtualFdTable, policy: &Policy) {
    let net = policy.network();
    let info = serde_json::json!({
        "policy": policy.name(),
        "http": !net.http.is_empty(),
        "tcp": !net.tcp.is_empty(),
    });
    let bytes: Arc<[u8]> = serde_json::to_vec(&info).unwrap_or_default().into();
    vfds.register(
        "info",
        Box::new(move |rel: &str| {
            if rel == "info" {
                Ok(Box::new(StaticDevice::new(bytes.clone())) as Box<dyn VirtualDevice>)
            } else {
                Err(wasmtime_wasi::p1::types::Errno::Noent)
            }
        }),
    );
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// First line only, without host paths: never leak host details through trap messages.
fn sanitize_trap(e: &wasmtime::Error) -> String {
    let s = format!("{e}");
    let first = s.lines().next().unwrap_or("trap").to_string();
    first.chars().take(200).collect()
}

async fn run(
    inner: Arc<Inner>,
    req: RunRequest,
    policy: Arc<Policy>,
    run_id: RunId,
    principal: String,
    tx: mpsc::UnboundedSender<RunEvent>,
) -> RunResult {
    let t0 = Instant::now();
    let lang = req.language;
    let audit = inner.audit.clone();
    let cfg = &inner.cfg;

    // 1. Request validation and policy tightening.
    let invalid = |msg: String| {
        failed(
            run_id,
            lang,
            policy.name(),
            RunError::InvalidRequest(msg),
            Timings::default(),
        )
    };
    let reject = |r: RunResult| {
        let mut r = r;
        r.timings.total_ms = ms(t0.elapsed());
        audit.emit(end_event(&r, &principal));
        r
    };
    if req.session.is_some() {
        return reject(failed(
            run_id,
            lang,
            policy.name(),
            RunError::NotImplemented("persistent sessions"),
            Timings::default(),
        ));
    }
    if req.code.len() > cfg.max_code_bytes {
        return reject(invalid(format!(
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
        return reject(invalid(format!(
            "at most {} args of {} bytes, no NUL",
            cfg.max_args, cfg.max_arg_bytes
        )));
    }
    let policy = match policy.tighten(&req.overrides) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            audit.emit(
                AuditEvent::new(EventKind::PolicyDenied {
                    what: e.to_string(),
                    requested: None,
                })
                .run(run_id)
                .policy(policy.name())
                .principal(&principal),
            );
            return reject(failed(
                run_id,
                lang,
                policy.name(),
                RunError::PolicyViolation(e.to_string()),
                Timings::default(),
            ));
        }
    };
    if policy.network().grants_anything() && cfg.broker.is_none() {
        let msg = "this policy grants network access, but network access is not configured on                    this runtime";
        audit.emit(
            AuditEvent::new(EventKind::PolicyDenied {
                what: msg.into(),
                requested: None,
            })
            .run(run_id)
            .policy(policy.name())
            .principal(&principal),
        );
        return reject(failed(
            run_id,
            lang,
            policy.name(),
            RunError::PolicyViolation(msg.into()),
            Timings::default(),
        ));
    }
    let limits = *policy.limits();
    if let Some(stdin) = &req.stdin
        && stdin.len() as u64 > limits.input_bytes.bytes()
    {
        return reject(invalid(format!(
            "stdin is {} bytes; policy input_bytes is {}",
            stdin.len(),
            limits.input_bytes
        )));
    }

    // 2. run.start
    audit.emit(
        AuditEvent::new(EventKind::RunStart {
            lang: lang.as_str().into(),
            code_sha256: sha256_hex(req.code.as_bytes()),
            code_bytes: req.code.len() as u64,
            code: policy.audit().log_code.then(|| req.code.clone()),
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
        .policy(policy.name())
        .principal(&principal),
    );

    // 3. Filesystem.
    let stdlib = (lang == Language::Python).then_some(inner.stdlib.as_path());
    let (file_name, argv0, pre) = match lang {
        Language::Python => {
            let mut argv = vec!["python", "-I", "-B", "-S", "-X", "frozen_modules=on"];
            if python_needs_bootstrap(policy.network().grants_anything(), &req.code) {
                argv.extend(["-c", PYTHON_LAUNCHER]);
            }
            argv.push("/code/main.py");
            ("main.py", argv, &inner.python)
        }
        Language::JavaScript => (
            "main.mjs",
            vec!["qjs", "--std", "-m", "-I", JS_BOOT, "/code/main.mjs"],
            &inner.javascript,
        ),
    };
    let fs = match RunFs::create(
        &cfg.vfs,
        &policy,
        run_id,
        req.files.clone(),
        stdlib,
        audit.clone(),
    )
    .and_then(|f| f.with_code(file_name, req.code.as_bytes()))
    .and_then(|f| f.with_helpers(&inner.helpers))
    {
        Ok(f) => f,
        Err(e) => {
            let err = match &e {
                sandboxd_vfs::VfsError::InvalidInput(_)
                | sandboxd_vfs::VfsError::InputsTooLarge { .. } => {
                    RunError::InvalidRequest(e.to_string())
                }
                _ => RunError::Internal(format!("filesystem setup: {e}")),
            };
            let mut r = failed(run_id, lang, policy.name(), err, Timings::default());
            if matches!(e, sandboxd_vfs::VfsError::InputsTooLarge { .. }) {
                r.limits_hit.push(LimitKind::Inputs);
            }
            return reject(r);
        }
    };

    // 4. WASI context.
    let stdout = CappedStream::new(limits.stdout.bytes(), LimitKind::Stdout, Some(tx.clone()));
    let stderr = CappedStream::new(limits.stderr.bytes(), LimitKind::Stderr, Some(tx.clone()));
    let mut b = WasiCtxBuilder::new();
    let mut argv: Vec<String> = argv0.into_iter().map(String::from).collect();
    argv.extend(req.args.iter().cloned());
    b.args(&argv).stdout(stdout.clone()).stderr(stderr.clone());
    for (k, v) in policy.env() {
        b.env(k, v);
    }
    if let Some(stdin) = req.stdin.clone() {
        b.stdin(MemoryInputPipe::new(stdin));
    }
    if let Err(e) = fs.preopen(&mut b, &policy) {
        return reject(failed(
            run_id,
            lang,
            policy.name(),
            RunError::Internal(e.to_string()),
            Timings::default(),
        ));
    }
    // Devices: `info` always (N2.3 messages), `http`/`tcp` when the policy grants them. Network
    // time counts against the run's wall clock (N1.2): the broker shares the epoch deadline.
    let deadline = Instant::now() + limits.wall_clock;
    let mut vfds = VirtualFdTable::default();
    register_info(&mut vfds, &policy);
    let net = match cfg.broker.as_ref().map(|b| {
        b.for_run(
            &policy,
            RunCtx {
                run_id,
                policy: policy.name().to_string(),
                deadline,
                audit: audit.clone(),
            },
        )
    }) {
        None | Some(Ok(None)) => None,
        Some(Ok(Some(n))) => Some(n),
        Some(Err(e)) => {
            return reject(failed(
                run_id,
                lang,
                policy.name(),
                RunError::Internal(format!("network setup: {e}")),
                Timings::default(),
            ));
        }
    };
    if let Some(n) = &net {
        n.register(&mut vfds);
    }
    let interposer = fs.interposer(b.build_p1(), vfds);

    // 5. Store with limits.
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
    let _ = store.set_fuel(limits.fuel);
    store.epoch_deadline_callback(move |_| {
        if Instant::now() >= deadline {
            Err(wasmtime::Error::new(WallClockExceeded))
        } else {
            Ok(UpdateDeadline::Yield(1))
        }
    });
    store.set_epoch_deadline(1);
    let setup_ms = ms(t0.elapsed());

    // 6. Run. The outer timeout also covers time spent inside host calls (e.g. sleep).
    let t_run = Instant::now();
    let grace = EPOCH_TICK * 5;
    let call = async {
        let inst = pre.instantiate_async(&mut store).await?;
        let start = inst.get_typed_func::<(), ()>(&mut store, "_start")?;
        start.call_async(&mut store, ()).await
    };
    let outcome = tokio::time::timeout(limits.wall_clock + grace, call).await;
    let run_ms = ms(t_run.elapsed());

    // 7. Classify (design §5).
    let mut limits_hit: Vec<LimitKind> = Vec::new();
    let mut error: Option<RunError> = None;
    let (mut out, mut exit_code) = (Outcome::Ok, None);
    match outcome {
        Err(_elapsed) => {
            out = Outcome::Limit;
            limits_hit.push(LimitKind::WallClock);
        }
        Ok(Ok(())) => exit_code = Some(0),
        Ok(Err(e)) => {
            if let Some(code) = e.downcast_ref::<wasmtime_wasi::I32Exit>() {
                exit_code = Some(code.0);
                if code.0 != 0 {
                    out = Outcome::Exit;
                }
            } else if e.downcast_ref::<WallClockExceeded>().is_some() {
                out = Outcome::Limit;
                limits_hit.push(LimitKind::WallClock);
            } else if e.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) {
                out = Outcome::Limit;
                limits_hit.push(LimitKind::Cpu);
            } else if store.data().limiter.denied {
                out = Outcome::Limit;
            } else {
                out = Outcome::Trap;
                error = Some(RunError::Trap(sanitize_trap(&e)));
            }
        }
    }
    let state = store.data_mut();
    if state.limiter.denied {
        limits_hit.push(LimitKind::Memory);
        if out == Outcome::Exit || out == Outcome::Trap {
            out = Outcome::Limit;
            error = None;
        }
    }
    let report = state.interposer.finish();
    let peak_memory = state.limiter.peak as u64;
    let fuel_used = limits.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
    drop(store);

    let t_collect = Instant::now();
    let collected = match fs.collect_artifacts() {
        Ok(c) => c,
        Err(e) => {
            error.get_or_insert(RunError::Internal(format!("artifact collection: {e}")));
            Default::default()
        }
    };
    if report.limit_hit.is_some() || collected.limit_hit.is_some() {
        limits_hit.push(LimitKind::Artifacts);
    }
    if net.as_ref().is_some_and(|n| n.finish().limit_hit) {
        limits_hit.push(LimitKind::Network);
    }
    if stdout.truncated() {
        limits_hit.push(LimitKind::Stdout);
    }
    if stderr.truncated() {
        limits_hit.push(LimitKind::Stderr);
    }
    limits_hit.dedup();
    if matches!(out, Outcome::Ok | Outcome::Exit) && !limits_hit.is_empty() {
        // A limit was hit: either the result is incomplete (exit 0) or the guest failed because of
        // it (e.g. a write error after the output cap). `exit_code` is kept for diagnosis.
        out = Outcome::Limit;
    }
    let (stdout_b, stdout_trunc) = stdout.take();
    let (stderr_b, stderr_trunc) = stderr.take();
    if error.is_none()
        && lang == Language::Python
        && let Some(module) = native::detect(&stderr_b)
    {
        error = Some(RunError::UnsupportedNativeExtension { module });
    }
    let collect_ms = ms(t_collect.elapsed());
    drop(fs);

    let result = RunResult {
        run_id,
        language: lang,
        policy: policy.name().to_string(),
        outcome: out,
        exit_code,
        stdout: stdout_b,
        stderr: stderr_b,
        stdout_truncated: stdout_trunc,
        stderr_truncated: stderr_trunc,
        artifacts: collected.artifacts,
        limits_hit,
        error,
        fuel_used,
        peak_memory,
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
                _ => (limits.memory.bytes(), result.peak_memory),
            };
            audit.emit(
                AuditEvent::new(EventKind::LimitHit {
                    kind: *k,
                    limit,
                    observed,
                })
                .run(run_id)
                .policy(policy.name()),
            );
        }
    }
    audit.emit(end_event(&result, &principal));
    result
}
