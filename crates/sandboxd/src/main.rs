//! `sandboxd`: run untrusted, agent-generated code in a WebAssembly sandbox.
//!
//! Commands: `run`, `serve`, `mcp`, `policy check|list`, `cache warm|clear|path`, `token new`, `version`.
//! Design: `aidlc-docs/construction/u5-server/design.md` §5.

#![forbid(unsafe_code)]

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use clap::{Args, Parser, Subcommand};
use rmcp::ServiceExt;
use sandboxd_audit::{
    AssetPin, AuditEvent, AuditSink, EventKind, JsonlOptions, JsonlSink, NullSink, Redactor,
};
use sandboxd_policy::{LoadOptions, Policy, PolicyDir};
use sandboxd_runtime::{Outcome, RunEvent, RuntimeConfig, Sandbox};
use sandboxd_server::{
    AuditDest, Principal, RunService, SandboxMcp, ServerConfig, TokenSet,
    api::{ApiEncoding, ApiFile, ApiLanguage, ApiLimits, ApiRunRequest, ApiRunResult},
    generate_token, hash_token,
    http::{AppState, router},
};
use sandboxd_vfs::VfsConfig;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(
    name = "sandboxd",
    version,
    about = "Run untrusted, agent-generated code in a WebAssembly sandbox"
)]
struct Cli {
    /// Config file (default: $SANDBOXD_CONFIG, then ./sandboxd.toml if present).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant, reason = "parsed once per process")]
enum Cmd {
    /// Run a program once, in-process.
    Run(RunArgs),
    /// Serve the HTTP API and MCP (Streamable HTTP at /mcp).
    Serve {
        /// Listen address (overrides config).
        #[arg(long)]
        listen: Option<String>,
    },
    /// Serve MCP over stdio (for Claude Desktop / Claude Code).
    Mcp,
    /// Policy tools.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Module/stdlib cache tools.
    #[command(subcommand)]
    Cache(CacheCmd),
    /// Token tools.
    #[command(subcommand)]
    Token(TokenCmd),
    /// Print version and pinned interpreter assets.
    Version,
}

#[derive(Args, Debug)]
struct RunArgs {
    /// Program file, or `-` for stdin.
    file: String,
    /// Language: py | js (default: from the file extension).
    #[arg(long)]
    lang: Option<String>,
    /// Policy name.
    #[arg(long, default_value = "default")]
    policy: String,
    /// Wall-clock limit, e.g. 2s (can only tighten the policy).
    #[arg(long)]
    timeout: Option<String>,
    /// Memory limit, e.g. 128mb.
    #[arg(long)]
    memory: Option<String>,
    /// Fuel (instruction) budget, e.g. 5G.
    #[arg(long)]
    fuel: Option<String>,
    /// Input file: PATH or NAME=PATH (appears under /in).
    #[arg(long = "input", value_name = "[NAME=]PATH")]
    inputs: Vec<String>,
    /// Directory for /out artifacts (default ./sandboxd-out/<run_id>).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Argument passed to the program (repeatable).
    #[arg(long = "arg")]
    args: Vec<String>,
    /// Print the full result as JSON instead of streaming output.
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum PolicyCmd {
    /// Validate policy files and explain the effective policy.
    Check { files: Vec<PathBuf> },
    /// List policies from the configured policy directory.
    List,
}

#[derive(Subcommand, Debug)]
enum CacheCmd {
    /// Compile interpreters and stdlib bytecode now.
    Warm,
    /// Delete cached modules and stdlib (rebuilt on next use).
    Clear,
    /// Print cache and work directories.
    Path,
}

#[derive(Subcommand, Debug)]
enum TokenCmd {
    /// Generate a new API token and the config line holding its hash.
    New {
        #[arg(long, default_value = "default")]
        name: String,
    },
}

/// Exit statuses (design §5).
mod status {
    pub const OK: u8 = 0;
    pub const GUEST_EXIT: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const LIMIT: u8 = 3;
    pub const FAILURE: u8 = 4;
    pub const SETUP: u8 = 5;
}

fn main() -> ExitCode {
    // Process-wide rustls provider: needed by the network broker and by rmcp's HTTP client
    // (feature-unified reqwest TLS). Idempotent.
    sandboxd_net::ensure_crypto_provider();
    let cli = Cli::parse();
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SANDBOXD_LOG")
                .unwrap_or_else(|_| "warn".into()),
        )
        .try_init();
    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => return fail(format!("tokio runtime: {e}")),
    };
    rt.block_on(async move {
        let cfg = match load_config(cli.config.as_deref()) {
            Ok(c) => c,
            Err(e) => return fail(e),
        };
        match cli.cmd {
            Cmd::Version => version(),
            Cmd::Token(TokenCmd::New { name }) => {
                let t = generate_token();
                println!("token (give this to the client; it is not stored):\n  {t}\n");
                println!("add to sandboxd.toml:\n  [auth]\n  tokens = [ {{ name = \"{name}\", sha256 = \"{}\" }} ]", hash_token(&t));
                ExitCode::SUCCESS
            }
            Cmd::Cache(c) => cache(c, &cfg).await,
            Cmd::Policy(p) => policy(p, &cfg),
            Cmd::Run(a) => run(a, &cfg).await,
            Cmd::Serve { listen } => serve(cfg, listen).await,
            Cmd::Mcp => mcp(&cfg).await,
        }
    })
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("sandboxd: {msg}");
    ExitCode::from(status::SETUP)
}

fn load_config(explicit: Option<&Path>) -> Result<ServerConfig, String> {
    let path = explicit
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("SANDBOXD_CONFIG").map(PathBuf::from))
        .or_else(|| Some(PathBuf::from("sandboxd.toml")).filter(|p| p.is_file()));
    let Some(path) = path else {
        return Ok(ServerConfig::default());
    };
    let src =
        std::fs::read_to_string(&path).map_err(|e| format!("config {}: {e}", path.display()))?;
    let base = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    ServerConfig::from_toml(&src, &base).map_err(|e| format!("config {}: {e}", path.display()))
}

fn vfs_config(cfg: &ServerConfig) -> VfsConfig {
    let d = VfsConfig::default_locations();
    VfsConfig {
        cache_dir: cfg.cache_dir.clone().unwrap_or(d.cache_dir),
        work_dir: cfg.work_dir.clone().unwrap_or(d.work_dir),
    }
}

fn default_audit_file(v: &VfsConfig) -> PathBuf {
    v.work_dir
        .parent()
        .map(|p| p.join("audit.jsonl"))
        .unwrap_or_else(|| PathBuf::from("audit.jsonl"))
}

/// (sink for the service, writer to flush on exit, human description of the destination).
type AuditParts = (Arc<dyn AuditSink>, Option<Arc<JsonlSink>>, String);

/// Build the audit sink for a mode (Q9 defaults: serve → stdout, mcp/run → file).
fn audit_sink(cfg: &ServerConfig, mode_default: AuditDest) -> Result<AuditParts, String> {
    let redactor = Redactor::with_extra(cfg.redact.iter().map(|(n, r)| (n.as_str(), r.as_str())))
        .map_err(|e| e.to_string())?;
    let v = vfs_config(cfg);
    match cfg.audit.clone().unwrap_or(mode_default) {
        AuditDest::None => Ok((Arc::new(NullSink), None, "disabled".into())),
        AuditDest::Stdout => {
            let s = Arc::new(JsonlSink::to_stdout(redactor, JsonlOptions::default()));
            Ok((s.clone(), Some(s), "stdout".into()))
        }
        AuditDest::File(p) => {
            let path = p.unwrap_or_else(|| default_audit_file(&v));
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("audit dir {}: {e}", parent.display()))?;
            }
            let s = Arc::new(
                JsonlSink::to_file(&path, redactor, JsonlOptions::default())
                    .map_err(|e| format!("audit file {}: {e}", path.display()))?,
            );
            Ok((s.clone(), Some(s), path.display().to_string()))
        }
    }
}

fn load_policies(cfg: &ServerConfig, audit_path: &str) -> Result<PolicyDir, String> {
    let v = vfs_config(cfg);
    let mut forbidden = vec![v.cache_dir.clone(), v.work_dir.clone()];
    if let Some(p) = Path::new(audit_path).parent().filter(|p| p.is_absolute()) {
        forbidden.push(p.to_path_buf());
    }
    match &cfg.policy_dir {
        Some(dir) => PolicyDir::load(
            dir,
            &LoadOptions {
                forbidden_host_roots: forbidden,
                network_enabled: cfg.network.enabled,
            },
        )
        .map_err(|e| e.to_string()),
        None => Ok(PolicyDir::builtin_only()),
    }
}

struct Stack {
    service: RunService,
    audit_writer: Option<Arc<JsonlSink>>,
    audit_desc: String,
    /// OTLP export (`otel` feature + `telemetry.otlp_endpoint`); flushed at exit.
    telemetry: sandboxd_server::Telemetry,
}

async fn build(
    cfg: &ServerConfig,
    mode_default: AuditDest,
    admission: sandboxd_server::AdmissionConfig,
) -> Result<Stack, String> {
    let (audit, writer, desc) = audit_sink(cfg, mode_default)?;
    let policies = load_policies(cfg, &desc)?;
    let rc = RuntimeConfig {
        vfs: vfs_config(cfg),
        broker: network_broker(&cfg.network)?,
        pooling: cfg.pooling,
        snapshots: cfg.snapshots,
        // ADR-C3-3: one slot per concurrent run and per live session (C3-U4), plus start-up
        // tasks (bytecode, probes).
        pool_slots: u32::try_from(
            admission
                .max_concurrent
                .saturating_add(admission.max_sessions),
        )
        .unwrap_or(u32::MAX)
        .saturating_add(2),
        ..RuntimeConfig::default()
    };
    let (sandbox, report) = Sandbox::new(rc, audit.clone())
        .await
        .map_err(|e| e.to_string())?;
    if let Some(why) = &report.snapshot_fallback {
        tracing::warn!(reason = %why, "interpreter snapshots unavailable; using the upstream interpreters");
    }
    if report.snapshot_python || report.snapshot_javascript {
        tracing::info!(
            python_floor_mib = report.snapshot_floor_python >> 20,
            javascript_floor_mib = report.snapshot_floor_javascript >> 20,
            "interpreter snapshots ready; policies with a lower memory limit use the upstream interpreters"
        );
    }
    if let Some(why) = &report.pooling_fallback {
        tracing::warn!(reason = %why, "pooling allocator unavailable; using on-demand allocation");
    }
    if !(report.python_cached && report.javascript_cached) {
        tracing::info!(?report, "interpreters compiled and cached");
    }
    // Before RunService::new: its OTel instruments bind to the global meter provider.
    let telemetry =
        sandboxd_server::Telemetry::init(cfg.otlp_endpoint.as_deref(), cfg.otlp_interval).await?;
    if telemetry.enabled() {
        tracing::info!(endpoint = ?cfg.otlp_endpoint, "OTLP export enabled");
    }
    let service = RunService::new(sandbox, policies, audit, admission);
    service.metrics().startup_ms_set(report.elapsed);
    service.metrics().pool_set(service.pool_status());
    Ok(Stack {
        service,
        audit_writer: writer,
        audit_desc: desc,
        telemetry,
    })
}

/// The egress broker from `[network]`, or `None` when the kill switch is off (policies that grant
/// egress are then already refused at load).
fn network_broker(
    n: &sandboxd_server::NetworkConfig,
) -> Result<Option<Arc<sandboxd_net::Broker>>, String> {
    if !n.enabled {
        return Ok(None);
    }
    let extra_ca_pem = match &n.extra_ca_file {
        Some(p) => Some(
            std::fs::read(p)
                .map_err(|e| format!("[network] extra_ca_file {}: {e}", p.display()))?,
        ),
        None => None,
    };
    let broker = sandboxd_net::Broker::new(sandboxd_net::BrokerConfig {
        proxy: n.proxy.clone(),
        no_proxy: n.no_proxy.clone(),
        use_env_proxy: n.use_env_proxy,
        extra_ca_pem,
    })
    .map_err(|e| format!("[network]: {e}"))?;
    Ok(Some(Arc::new(broker)))
}

fn version() -> ExitCode {
    println!("sandboxd {}", env!("CARGO_PKG_VERSION"));
    for a in sandboxd_assets::ALL {
        println!(
            "  {:<11} {:<18} sha256:{}  {:>6.1} MiB  ({})",
            a.name,
            a.version,
            a.sha256,
            a.bytes.len() as f64 / (1024.0 * 1024.0),
            a.license
        );
    }
    ExitCode::SUCCESS
}

async fn cache(c: CacheCmd, cfg: &ServerConfig) -> ExitCode {
    let v = vfs_config(cfg);
    match c {
        CacheCmd::Path => {
            println!(
                "cache: {}\nwork:  {}",
                v.cache_dir.display(),
                v.work_dir.display()
            );
            ExitCode::SUCCESS
        }
        CacheCmd::Clear => {
            for sub in ["modules", "stdlib", "helpers"] {
                let p = v.cache_dir.join(sub);
                match std::fs::remove_dir_all(&p) {
                    Ok(()) => println!("removed {}", p.display()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return fail(format!("remove {}: {e}", p.display())),
                }
            }
            ExitCode::SUCCESS
        }
        CacheCmd::Warm => {
            let rc = RuntimeConfig {
                vfs: v,
                ..RuntimeConfig::default()
            };
            match Sandbox::new(rc, Arc::new(NullSink)).await {
                Ok((_, r)) => {
                    println!(
                        "warm in {:?} (python cached: {}, javascript cached: {}, bytecode compiled now: {})",
                        r.elapsed, r.python_cached, r.javascript_cached, r.bytecode_compiled
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e),
            }
        }
    }
}

fn policy(p: PolicyCmd, cfg: &ServerConfig) -> ExitCode {
    match p {
        PolicyCmd::List => match load_policies(cfg, "") {
            Ok(dir) => {
                for s in dir.list() {
                    let o = if s.overrides_builtin {
                        " (overrides built-in)"
                    } else {
                        ""
                    };
                    println!("{:<20} {}{o}", s.name, s.description);
                }
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        },
        PolicyCmd::Check { files } => {
            if files.is_empty() {
                eprintln!("usage: sandboxd policy check <file>...");
                return ExitCode::from(status::USAGE);
            }
            let mut bad = false;
            for f in files {
                match Policy::from_path(&f, &LoadOptions::default()) {
                    Ok(p) => {
                        print!("{}", p.explain());
                        if let Err(e) = p.ensure_supported() {
                            bad = true;
                            println!("\nNOT SERVABLE BY THIS VERSION:\n{e}");
                        }
                        println!();
                    }
                    Err(e) => {
                        bad = true;
                        eprintln!("{e}\n");
                    }
                }
            }
            if bad {
                ExitCode::from(status::FAILURE)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

fn read_program(file: &str) -> Result<String, String> {
    if file == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("stdin: {e}"))?;
        Ok(s)
    } else {
        std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))
    }
}

fn language(a: &RunArgs) -> Result<ApiLanguage, String> {
    let l = a.lang.clone().or_else(|| {
        Path::new(&a.file)
            .extension()
            .map(|e| e.to_string_lossy().into_owned())
    });
    match l.as_deref().map(str::to_ascii_lowercase).as_deref() {
        Some("py" | "python") => Ok(ApiLanguage::Python),
        Some("js" | "mjs" | "javascript") => Ok(ApiLanguage::Javascript),
        _ => Err("cannot tell the language: use --lang py|js".into()),
    }
}

/// Only plain relative components; never `..`, roots, or drive prefixes.
fn safe_join(base: &Path, rel: &str) -> Option<PathBuf> {
    let mut p = base.to_path_buf();
    for c in rel.split('/') {
        if c.is_empty() || c == "." || c == ".." || c.contains(['\\', ':']) {
            return None;
        }
        p.push(c);
    }
    Some(p)
}

async fn run(a: RunArgs, cfg: &ServerConfig) -> ExitCode {
    let lang = match language(&a) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("sandboxd: {e}");
            return ExitCode::from(status::USAGE);
        }
    };
    let code = match read_program(&a.file) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let mut files = Vec::new();
    for spec in &a.inputs {
        let (name, path) = match spec.split_once('=') {
            Some((n, p)) if !n.is_empty() && !Path::new(spec).exists() => {
                (n.to_string(), PathBuf::from(p))
            }
            _ => {
                let p = PathBuf::from(spec);
                (
                    p.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    p,
                )
            }
        };
        match std::fs::read(&path) {
            Ok(bytes) => files.push(ApiFile {
                name,
                content: B64.encode(bytes),
                encoding: ApiEncoding::Base64,
            }),
            Err(e) => return fail(format!("input {}: {e}", path.display())),
        }
    }
    let req = ApiRunRequest {
        language: lang,
        code,
        policy: Some(a.policy.clone()),
        files,
        args: a.args.clone(),
        stdin: None,
        limits: Some(ApiLimits {
            wall_clock: a.timeout.clone(),
            fuel: a.fuel.clone(),
            memory: a.memory.clone(),
            stdout: None,
            stderr: None,
        }),
        session_id: None,
    };
    let admission = sandboxd_server::AdmissionConfig {
        max_concurrent: 1,
        queue_depth: 1,
        queue_timeout: Duration::from_secs(60),
        max_sessions: 0,
    };
    let stack = match build(cfg, AuditDest::File(None), admission).await {
        Ok(s) => s,
        Err(e) => return fail(e),
    };

    let (tx, mut rx) = mpsc::channel::<RunEvent>(64);
    let stream_live = !a.json;
    let printer = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if !stream_live {
                continue;
            }
            match ev {
                RunEvent::Stdout(b) => {
                    let mut o = std::io::stdout().lock();
                    let _ = o.write_all(&b);
                    let _ = o.flush();
                }
                RunEvent::Stderr(b) => {
                    let _ = std::io::stderr().lock().write_all(&b);
                }
                _ => {}
            }
        }
    });
    let result = stack
        .service
        .submit(&Principal::local("cli"), req, Some(tx))
        .await;
    let _ = printer.await;
    if let Some(w) = &stack.audit_writer {
        w.shutdown();
    }
    stack.telemetry.shutdown().await;
    let r = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sandboxd: {}: {e}", e.code());
            return ExitCode::from(if e.status() == 400 || e.status() == 404 {
                status::USAGE
            } else {
                status::FAILURE
            });
        }
    };

    // Artifacts.
    let mut written = Vec::new();
    if !r.artifacts.is_empty() {
        let dir = a
            .out
            .clone()
            .unwrap_or_else(|| PathBuf::from("sandboxd-out").join(r.run_id.to_string()));
        for art in &r.artifacts {
            let Some(dest) = safe_join(&dir, &art.name) else {
                eprintln!(
                    "sandboxd: skipping artifact with unsafe name {:?}",
                    art.name
                );
                continue;
            };
            if let Some(p) = dest.parent()
                && let Err(e) = std::fs::create_dir_all(p)
            {
                return fail(format!("{}: {e}", p.display()));
            }
            if let Err(e) = std::fs::write(&dest, &art.bytes) {
                return fail(format!("{}: {e}", dest.display()));
            }
            written.push(dest);
        }
    }

    if a.json {
        let api = ApiRunResult::from(&r);
        println!("{}", serde_json::to_string_pretty(&api).unwrap_or_default());
    } else {
        let mut line = format!(
            "[sandboxd] {} in {} ms",
            serde_json::to_value(r.outcome)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            r.timings.total_ms
        );
        if let Some(c) = r.exit_code {
            line.push_str(&format!(", exit {c}"));
        }
        if !r.limits_hit.is_empty() {
            let names: Vec<String> = r
                .limits_hit
                .iter()
                .filter_map(|k| {
                    serde_json::to_value(k)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                })
                .collect();
            line.push_str(&format!(", limits hit: {}", names.join(", ")));
        }
        if let Some(e) = &r.error {
            line.push_str(&format!("\n[sandboxd] {}: {e}", e.code()));
        }
        for w in &written {
            line.push_str(&format!("\n[sandboxd] artifact → {}", w.display()));
        }
        line.push_str(&format!("\n[sandboxd] audit → {}", stack.audit_desc));
        eprintln!("{line}");
    }
    if matches!(
        r.error,
        Some(
            sandboxd_runtime::RunError::PolicyViolation(_)
                | sandboxd_runtime::RunError::InvalidRequest(_)
        )
    ) {
        return ExitCode::from(status::USAGE);
    }
    ExitCode::from(match r.outcome {
        Outcome::Ok => status::OK,
        Outcome::Exit => status::GUEST_EXIT,
        Outcome::Limit => status::LIMIT,
        Outcome::Trap | Outcome::Error => status::FAILURE,
    })
}

fn start_event(service: &RunService) -> AuditEvent {
    AuditEvent::new(EventKind::ServerStart {
        version: env!("CARGO_PKG_VERSION").into(),
        asset_pins: sandboxd_assets::ALL
            .iter()
            .map(|a| AssetPin {
                name: a.name.into(),
                version: a.version.into(),
                sha256: a.sha256.into(),
            })
            .collect(),
        policies: service.policies().into_iter().map(|p| p.name).collect(),
    })
}

async fn serve(mut cfg: ServerConfig, listen: Option<String>) -> ExitCode {
    if let Some(l) = listen {
        match l.parse() {
            Ok(a) => cfg.listen = a,
            Err(e) => {
                eprintln!("sandboxd: --listen {l:?}: {e}");
                return ExitCode::from(status::USAGE);
            }
        }
    }
    let env_token = std::env::var("SANDBOXD_TOKEN").ok();
    let tokens = match TokenSet::new(&cfg.tokens, env_token.as_deref()) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    if let Err(e) = cfg.check_bind_safety(!tokens.is_empty()) {
        return fail(e);
    }
    if tokens.is_empty() {
        eprintln!(
            "sandboxd: warning: no auth tokens configured; accepting unauthenticated requests on loopback only"
        );
    }
    let stack = match build(&cfg, AuditDest::Stdout, cfg.admission).await {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    stack.service.audit().emit(start_event(&stack.service));
    let state = AppState {
        service: stack.service.clone(),
        tokens: Arc::new(tokens),
        metrics_public: cfg.metrics_public,
    };
    let app = router(state, cfg.max_request_bytes);
    let listener = match tokio::net::TcpListener::bind(cfg.listen).await {
        Ok(l) => l,
        Err(e) => return fail(format!("bind {}: {e}", cfg.listen)),
    };
    let addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
    eprintln!(
        "sandboxd: listening on http://{addr} (API /v1, MCP /mcp); audit → {}",
        stack.audit_desc
    );
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("sandboxd: shutting down (draining runs)");
        })
        .await;
    stack.service.close_all_sessions().await;
    stack
        .service
        .audit()
        .emit(AuditEvent::new(EventKind::ServerStop));
    if let Some(w) = &stack.audit_writer {
        w.shutdown();
    }
    stack.telemetry.shutdown().await;
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(format!("server: {e}")),
    }
}

async fn mcp(cfg: &ServerConfig) -> ExitCode {
    let stack = match build(cfg, AuditDest::File(None), cfg.admission).await {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    stack.service.audit().emit(start_event(&stack.service));
    let server = SandboxMcp::new(stack.service.clone(), "mcp-stdio");
    let result = match server.serve(rmcp::transport::stdio()).await {
        Ok(running) => running
            .waiting()
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    stack.service.close_all_sessions().await;
    stack
        .service
        .audit()
        .emit(AuditEvent::new(EventKind::ServerStop));
    if let Some(w) = &stack.audit_writer {
        w.shutdown();
    }
    stack.telemetry.shutdown().await;
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(format!("mcp: {e}")),
    }
}
