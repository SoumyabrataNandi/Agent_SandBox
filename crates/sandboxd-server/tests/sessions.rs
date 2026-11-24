//! C3-U4 session tests through the server: HTTP endpoints, ownership, caps, SSE, MCP, metrics.

use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use rmcp::{ServiceExt, model::CallToolRequestParams};
use sandboxd_audit::{EventKind, MemorySink};
use sandboxd_policy::{LoadOptions, PolicyDir};
use sandboxd_runtime::{RuntimeConfig, Sandbox};
use sandboxd_server::{
    AdmissionConfig, RunService, SandboxMcp, TokenSet, hash_token,
    http::{AppState, router},
};
use sandboxd_vfs::VfsConfig;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const ALICE: &str = "sbx_alice_token_0123456789abcdef";
const BOB: &str = "sbx_bob_token_0123456789abcdef01";

fn sandbox() -> &'static Sandbox {
    static S: OnceLock<Sandbox> = OnceLock::new();
    S.get_or_init(|| {
        std::thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().expect("rt");
            let cfg = RuntimeConfig {
                vfs: VfsConfig::under(std::env::temp_dir().join("sandboxd-runtime-tests")),
                ..RuntimeConfig::default()
            };
            rt.block_on(Sandbox::new(cfg, Arc::new(sandboxd_audit::NullSink)))
                .expect("sandbox")
                .0
        })
        .join()
        .expect("thread")
    })
}

/// `default` (sessions off), `notebook` (sessions on, 2 per policy) and `short` (1 s idle TTL).
/// The files are written once per process: tests run in parallel, and rewriting them while another
/// test loads them lets it read a truncated (empty) file.
fn policies() -> PolicyDir {
    static DIR: OnceLock<std::path::PathBuf> = OnceLock::new();
    let dir = DIR.get_or_init(|| {
        let dir = std::env::temp_dir()
            .join(format!("sandboxd-session-policies-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("notebook.toml"),
            "version = 1\nname = \"notebook\"\n[limits]\nwall_clock = \"5s\"\n[session]\nenabled = true\nmax_sessions = 2\n",
        )
        .expect("write");
        std::fs::write(
            dir.join("short.toml"),
            "version = 1\nname = \"short\"\n[session]\nenabled = true\nidle_ttl = \"1s\"\n",
        )
        .expect("write");
        dir
    });
    PolicyDir::load(dir, &LoadOptions::default()).expect("policies")
}

fn service(audit: Arc<MemorySink>, max_sessions: usize) -> RunService {
    RunService::new(
        sandbox().clone(),
        policies(),
        audit,
        AdmissionConfig {
            max_sessions,
            ..AdmissionConfig::default()
        },
    )
}

fn app(service: RunService) -> axum::Router {
    let tokens = TokenSet::new(
        &[
            ("alice".into(), hash_token(ALICE)),
            ("bob".into(), hash_token(BOB)),
        ],
        None,
    )
    .expect("tokens");
    router(
        AppState {
            service,
            tokens: Arc::new(tokens),
            metrics_public: false,
        },
        1 << 20,
    )
}

fn req(method: &str, path: &str, body: Option<Value>, token: &str) -> Request<Body> {
    let b = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"));
    b.body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
        .expect("req")
}

async fn send(a: &axum::Router, r: Request<Body>) -> (StatusCode, Value) {
    let resp = a.clone().oneshot(r).await.expect("resp");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned())),
    )
}

async fn create(a: &axum::Router, policy: &str, token: &str) -> (StatusCode, Value) {
    send(
        a,
        req(
            "POST",
            "/v1/sessions",
            Some(json!({"language": "python", "policy": policy})),
            token,
        ),
    )
    .await
}

async fn run(a: &axum::Router, id: &str, code: &str, token: &str) -> (StatusCode, Value) {
    send(
        a,
        req(
            "POST",
            &format!("/v1/sessions/{id}/runs"),
            Some(json!({"code": code})),
            token,
        ),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn http_session_lifecycle_and_ownership() {
    let audit = Arc::new(MemorySink::default());
    let svc = service(audit.clone(), 16);
    let a = app(svc.clone());

    let (s, v) = create(&a, "notebook", ALICE).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let id = v["session_id"].as_str().expect("id").to_string();
    assert!(id.starts_with("ses_"));
    assert_eq!(v["state"], "active");
    assert_eq!(v["language"], "python");

    let (s, v) = run(&a, &id, "x = 20\nprint('set')", ALICE).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["stdout"], "set\n");
    assert_eq!(v["session_id"], id.as_str());
    let (_, v) = run(&a, &id, "print(x * 2 + 2)", ALICE).await;
    assert_eq!(v["stdout"], "42\n", "{v}");

    // Another principal (and an unknown id) gets 404, never 403.
    let (s, v) = run(&a, &id, "print(x)", BOB).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("SESSION_NOT_FOUND"))
    );
    let (s, _) = send(&a, req("GET", &format!("/v1/sessions/{id}"), None, BOB)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = send(&a, req("DELETE", &format!("/v1/sessions/{id}"), None, BOB)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = run(&a, "ses_00000000000000000000000000000000", "1", ALICE).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(
        audit.events().iter().any(|e| matches!(&e.kind, EventKind::PolicyDenied { what, .. } if what.contains("another principal"))),
        "refused access is audited"
    );

    let (s, v) = send(&a, req("GET", &format!("/v1/sessions/{id}"), None, ALICE)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["calls"], 2);

    // Streaming works for session calls too.
    let resp = a
        .clone()
        .oneshot(req(
            "POST",
            &format!("/v1/sessions/{id}/runs?stream=true"),
            Some(json!({"code": "print('streamed', x)"})),
            ALICE,
        ))
        .await
        .expect("resp");
    let body = String::from_utf8_lossy(&to_bytes(resp.into_body(), 1 << 20).await.expect("body"))
        .into_owned();
    assert!(
        body.contains("event: stdout") && body.contains("streamed 20"),
        "{body}"
    );
    assert!(body.contains("event: result"), "{body}");

    // A plain run request with session_id goes to the session.
    let (s, v) = send(
        &a,
        req(
            "POST",
            "/v1/runs",
            Some(json!({"language": "python", "code": "print(x)", "session_id": id})),
            ALICE,
        ),
    )
    .await;
    assert_eq!(
        (s, v["stdout"].as_str()),
        (StatusCode::OK, Some("20\n")),
        "{v}"
    );

    let (s, v) = send(
        &a,
        req("DELETE", &format!("/v1/sessions/{id}"), None, ALICE),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v["state"].as_str(), v["ended_reason"].as_str()),
        (Some("ended"), Some("closed"))
    );
    let (s, _) = run(&a, &id, "print(x)", ALICE).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(svc.session_count(), 0);

    // Metrics.
    let (_, m) = send(&a, req("GET", "/metrics", None, ALICE)).await;
    let m = m.as_str().unwrap_or_default().to_string();
    assert!(m.contains("sandboxd_sessions_active 0"), "{m}");
    assert!(m.contains("sandboxd_session_calls_total 4"), "{m}");
    assert!(
        m.contains("sandboxd_sessions_ended_total{reason=\"closed\"} 1"),
        "{m}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn http_session_caps_and_errors() {
    let audit = Arc::new(MemorySink::default());
    let a = app(service(audit, 3));
    // Sessions off in `default` → 403.
    let (s, v) = create(&a, "default", ALICE).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("SESSIONS_DISABLED"))
    );
    // Policy cap (2) then server cap (3) → 429.
    let (s1, v1) = create(&a, "notebook", ALICE).await;
    let (s2, _) = create(&a, "notebook", BOB).await;
    assert_eq!((s1, s2), (StatusCode::CREATED, StatusCode::CREATED));
    let (s, v) = create(&a, "notebook", ALICE).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("SESSION_LIMIT"))
    );
    let (s, _) = create(&a, "short", ALICE).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = create(&a, "short", ALICE).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "server-wide cap");
    // One call at a time → 409.
    let id = v1["session_id"].as_str().expect("id").to_string();
    let a2 = a.clone();
    let id2 = id.clone();
    let slow =
        tokio::spawn(async move { run(&a2, &id2, "import time\ntime.sleep(1.5)", ALICE).await });
    // Wait until the first call holds the session (a fixed head start races on a loaded runner).
    let t = std::time::Instant::now();
    loop {
        let (_, v) = send(&a, req("GET", &format!("/v1/sessions/{id}"), None, ALICE)).await;
        if v["state"] == "busy" {
            break;
        }
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "first call never started: {v}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (s, v) = run(&a, &id, "print(1)", ALICE).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::CONFLICT, Some("SESSION_BUSY"))
    );
    assert_eq!(slow.await.expect("join").0, StatusCode::OK);
    // stdin is refused in sessions; unknown fields are refused.
    let (s, v) = send(
        &a,
        req(
            "POST",
            &format!("/v1/sessions/{id}/runs"),
            Some(json!({"code": "1", "stdin": "x"})),
            ALICE,
        ),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("INVALID_REQUEST"))
    );
    // A limit ends the session; the result says so and the id is gone.
    let (s, v) = send(
        &a,
        req(
            "POST",
            &format!("/v1/sessions/{id}/runs"),
            Some(json!({"code": "while True: pass", "limits": {"wall_clock": "300ms"}})),
            ALICE,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v["outcome"].as_str(), v["session_ended"].as_str()),
        (Some("limit"), Some("limit"))
    );
    let (s, _) = run(&a, &id, "1", ALICE).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_sessions_are_reaped() {
    let audit = Arc::new(MemorySink::default());
    let svc = service(audit.clone(), 16);
    let a = app(svc.clone());
    let (s, v) = create(&a, "short", ALICE).await;
    assert_eq!(s, StatusCode::CREATED);
    let id = v["session_id"].as_str().expect("id").to_string();
    // idle_ttl 1 s, reaper every 5 s.
    let mut gone = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        if svc.session_count() == 0 {
            gone = true;
            break;
        }
    }
    assert!(gone, "idle session reaped");
    // (session.end itself is a runtime event; its reasons are covered in the runtime tests.)
    let (s, _) = run(&a, &id, "1", ALICE).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_session_tools() {
    let svc = service(Arc::new(MemorySink::default()), 16);
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(s) = SandboxMcp::new(svc, "mcp-test").serve(server_io).await {
            let _ = s.waiting().await;
        }
    });
    let client = ().serve(client_io).await.expect("client");
    let tools = client.list_all_tools().await.expect("tools");
    let names: Vec<_> = tools.iter().map(|t| t.name.to_string()).collect();
    assert!(
        names.contains(&"session_create".into()) && names.contains(&"session_close".into()),
        "{names:?}"
    );

    let call = |name: &'static str, v: Value| {
        let p = CallToolRequestParams::new(name)
            .with_arguments(v.as_object().cloned().unwrap_or_default());
        let c = client.clone();
        async move { c.call_tool(p).await.expect("call") }
    };
    let r = call(
        "session_create",
        json!({"language": "javascript", "policy": "notebook"}),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let id = r.structured_content.as_ref().expect("structured")["session_id"]
        .as_str()
        .expect("id")
        .to_string();
    let r = call(
        "run_code",
        json!({"language": "javascript", "code": "var n = 41;", "session_id": id}),
    )
    .await;
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let r = call(
        "run_code",
        json!({"language": "javascript", "code": "console.log(n + 1);", "session_id": id}),
    )
    .await;
    let sc = r.structured_content.clone().expect("structured");
    assert_eq!(
        (sc["stdout"].as_str(), sc["session_id"].as_str()),
        (Some("42\n"), Some(id.as_str())),
        "{r:?}"
    );
    // Wrong language for the session → error.
    let r = call(
        "run_code",
        json!({"language": "python", "code": "print(1)", "session_id": id}),
    )
    .await;
    assert_eq!(r.is_error, Some(true));
    let r = call("session_close", json!({"session_id": id})).await;
    assert_ne!(r.is_error, Some(true), "{r:?}");
    let r = call(
        "run_code",
        json!({"language": "javascript", "code": "1", "session_id": id}),
    )
    .await;
    assert_eq!(r.is_error, Some(true), "closed session");
    // Sessions disabled by the default policy.
    let r = call("session_create", json!({"language": "python"})).await;
    assert_eq!(r.is_error, Some(true));
}
