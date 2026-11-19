//! C2-U4 tests (FR-O1): OTLP/HTTP export against an in-process collector stub.
//! Run with `cargo test -p sandboxd-server --features otel --test otel`.
//!
//! Protobuf stores strings verbatim, so the stub asserts on span/metric names, attribute keys and
//! values directly in the exported bytes (no protobuf decoder needed).
#![cfg(feature = "otel")]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router, body::Bytes, extract::State, http::header, response::IntoResponse, routing::post,
};
use sandboxd_policy::PolicyDir;
use sandboxd_runtime::{RuntimeConfig, Sandbox};
use sandboxd_server::{AdmissionConfig, Principal, RunService, Telemetry, api::ApiRunRequest};
use sandboxd_vfs::VfsConfig;

/// (signal, request body) pairs received by the stub.
type Bodies = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

#[derive(Clone, Default)]
struct Received(Bodies);

impl Received {
    fn bodies(&self, path: &str) -> Vec<u8> {
        self.0
            .lock()
            .expect("lock")
            .iter()
            .filter(|(p, _)| p == path)
            .flat_map(|(_, b)| b.clone())
            .collect()
    }
    fn all(&self) -> Vec<u8> {
        self.0
            .lock()
            .expect("lock")
            .iter()
            .flat_map(|(_, b)| b.clone())
            .collect()
    }
}

async fn traces(State(r): State<Received>, body: Bytes) -> impl IntoResponse {
    r.0.lock()
        .expect("lock")
        .push(("traces".into(), body.to_vec()));
    (
        [(header::CONTENT_TYPE, "application/x-protobuf")],
        Vec::<u8>::new(),
    )
}

async fn metrics(State(r): State<Received>, body: Bytes) -> impl IntoResponse {
    r.0.lock()
        .expect("lock")
        .push(("metrics".into(), body.to_vec()));
    (
        [(header::CONTENT_TYPE, "application/x-protobuf")],
        Vec::<u8>::new(),
    )
}

async fn collector() -> (SocketAddr, Received) {
    let rec = Received::default();
    let app = Router::new()
        .route("/v1/traces", post(traces))
        .route("/v1/metrics", post(metrics))
        .with_state(rec.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = l.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    (addr, rec)
}

async fn sandbox() -> Sandbox {
    // Reuse the runtime tests' cache so modules/bytecode are already compiled.
    let cfg = RuntimeConfig {
        vfs: VfsConfig::under(std::env::temp_dir().join("sandboxd-runtime-tests")),
        ..RuntimeConfig::default()
    };
    Sandbox::new(cfg, Arc::new(sandboxd_audit::NullSink))
        .await
        .expect("sandbox")
        .0
}

fn req(language: &str, code: &str) -> ApiRunRequest {
    serde_json::from_value(serde_json::json!({ "language": language, "code": code }))
        .expect("request")
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// One test function: the OpenTelemetry providers are process-global.
#[tokio::test(flavor = "multi_thread")]
async fn otlp_export_spans_and_metrics_and_failure_isolation() {
    let sb = sandbox().await;
    let who = Principal::local("otel-test");

    // ---- 1. Export to a working collector.
    let (addr, rec) = collector().await;
    let telemetry = Telemetry::init(Some(&format!("http://{addr}/")), Duration::from_secs(60))
        .await
        .expect("init");
    assert!(telemetry.enabled());
    let service = RunService::new(
        sb.clone(),
        PolicyDir::builtin_only(),
        Arc::new(sandboxd_audit::NullSink),
        AdmissionConfig::default(),
    );
    const MARKER: &str = "CODE_MARKER_7f3a";
    let ok = service
        .submit(&who, req("python", &format!("print('{MARKER}')")), None)
        .await
        .expect("run");
    assert!(String::from_utf8_lossy(&ok.stdout).contains(MARKER));
    let exit = service
        .submit(&who, req("python", "import sys\nsys.exit(3)"), None)
        .await
        .expect("run");
    assert_eq!(exit.exit_code, Some(3));
    let limit = service
        .submit(
            &who,
            serde_json::from_value(serde_json::json!({
                "language": "javascript",
                "code": "while (true) {}",
                "limits": { "wall_clock": "300ms" }
            }))
            .expect("request"),
            None,
        )
        .await
        .expect("run");
    assert!(!limit.limits_hit.is_empty());
    // Rejected before running: counted, but no span.
    let missing = service
        .submit(
            &who,
            serde_json::from_value(serde_json::json!({
                "language": "python", "code": "print(1)", "policy": "nope"
            }))
            .expect("request"),
            None,
        )
        .await;
    assert!(missing.is_err());
    telemetry.shutdown().await; // flushes spans and a final metric collection

    let t = rec.bodies("traces");
    assert!(!t.is_empty(), "no spans exported");
    for needle in [
        "sandboxd.run",
        "sandboxd.language",
        "python",
        "javascript",
        "sandboxd.outcome",
        "ok",
        "exit",
        "limit",
        "sandboxd.limits_hit",
        "wall_clock",
        "sandboxd.fuel_used",
        "sandboxd.net_requests",
        "sandboxd.total_ms",
        "sandboxd.exit_code",
        &ok.run_id.to_string(),
        "service.name",
        "sandboxd",
    ] {
        assert!(contains(&t, needle), "span export lacks {needle:?}");
    }
    let m = rec.bodies("metrics");
    assert!(!m.is_empty(), "no metrics exported");
    for needle in [
        "sandboxd.runs",
        "sandboxd.run.duration",
        "sandboxd.limits_hit",
        "sandboxd.rejected",
        "policy_not_found",
        "sandboxd.queue_depth",
        "sandboxd.running",
        "outcome",
        "language",
    ] {
        assert!(contains(&m, needle), "metric export lacks {needle:?}");
    }
    // O1.2: no code or output in anything exported; no principal either.
    let all = rec.all();
    assert!(
        !contains(&all, MARKER),
        "program text/output leaked into telemetry"
    );
    assert!(
        !contains(&all, "sys.exit"),
        "program text leaked into telemetry"
    );
    assert!(
        !contains(&all, "otel-test"),
        "principal leaked into telemetry"
    );

    // ---- 2. A dead collector never blocks runs; shutdown stays bounded.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr")
    }; // listener dropped: connections are refused
    let telemetry = Telemetry::init(Some(&format!("http://{dead}")), Duration::from_secs(1))
        .await
        .expect("init");
    let service = RunService::new(
        sb,
        PolicyDir::builtin_only(),
        Arc::new(sandboxd_audit::NullSink),
        AdmissionConfig::default(),
    );
    let t0 = Instant::now();
    for _ in 0..3 {
        let r = service
            .submit(&who, req("javascript", "console.log(1)"), None)
            .await
            .expect("run");
        assert_eq!(String::from_utf8_lossy(&r.stdout), "1\n");
    }
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "runs slowed by a dead collector: {:?}",
        t0.elapsed()
    );
    tokio::time::sleep(Duration::from_millis(1500)).await; // let a periodic export fail
    let t1 = Instant::now();
    telemetry.shutdown().await;
    assert!(
        t1.elapsed() < Duration::from_secs(12),
        "shutdown not bounded: {:?}",
        t1.elapsed()
    );
}

#[tokio::test]
async fn no_endpoint_means_no_export() {
    let t = Telemetry::init(None, Duration::from_secs(30))
        .await
        .expect("init");
    assert!(!t.enabled());
    t.shutdown().await;
}
