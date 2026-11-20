//! U5 tests: HTTP API, auth (AC 8), MCP in-process and over HTTP (AC 7), admission, fail-closed.

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use rmcp::{
    ClientHandler, RoleClient, ServiceExt,
    model::{
        CallToolRequestParams, ClientRequest, ContentBlock, ProgressNotificationParam,
        Request as McpRequest,
    },
    service::{NotificationContext, PeerRequestOptions},
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use sandboxd_audit::{AuditEvent, AuditSink, EventKind, MemorySink};
use sandboxd_policy::PolicyDir;
use sandboxd_runtime::{RuntimeConfig, Sandbox};
use sandboxd_server::{
    AdmissionConfig, RunService, SandboxMcp, TokenSet, hash_token,
    http::{AppState, router},
};
use sandboxd_vfs::VfsConfig;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const TOKEN: &str = "sbx_test_token_0123456789abcdef";

fn sandbox() -> &'static Sandbox {
    static S: OnceLock<Sandbox> = OnceLock::new();
    S.get_or_init(|| {
        std::thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().expect("rt");
            // Reuse the runtime tests' cache so modules/bytecode are already compiled.
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

fn service_with(audit: Arc<dyn AuditSink>, admission: AdmissionConfig) -> RunService {
    // Sandbox emits its own events to the sink it was built with (NullSink); the service-level
    // events (policy denials) go to `audit`. Runtime audit content is covered in U4 tests.
    RunService::new(
        sandbox().clone(),
        PolicyDir::builtin_only(),
        audit,
        admission,
    )
}

fn app(service: RunService, tokens: bool, max_body: usize) -> axum::Router {
    let tokens = if tokens {
        TokenSet::new(&[("ci".into(), hash_token(TOKEN))], None).expect("tokens")
    } else {
        TokenSet::default()
    };
    router(
        AppState {
            service,
            tokens: Arc::new(tokens),
            metrics_public: false,
        },
        max_body,
    )
}

fn default_app() -> axum::Router {
    app(
        service_with(Arc::new(MemorySink::default()), AdmissionConfig::default()),
        true,
        1 << 20,
    )
}

fn post(path: &str, body: Value, auth: bool) -> Request<Body> {
    let mut b = Request::post(path).header("content-type", "application/json");
    if auth {
        b = b.header("authorization", format!("Bearer {TOKEN}"));
    }
    b.body(Body::from(body.to_string())).expect("req")
}

async fn json_of(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// ---------- AC 8: auth ----------

#[tokio::test(flavor = "multi_thread")]
async fn ac8_auth_required_and_enforced() {
    let body = json!({"language": "python", "code": "print(1)"});
    let (s, v) = json_of(
        default_app()
            .oneshot(post("/v1/runs", body.clone(), false))
            .await
            .expect("resp"),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"]["code"], "UNAUTHORIZED");
    let mut wrong = post("/v1/runs", body.clone(), false);
    wrong
        .headers_mut()
        .insert("authorization", "Bearer nope".parse().expect("hdr"));
    assert_eq!(
        default_app().oneshot(wrong).await.expect("resp").status(),
        StatusCode::UNAUTHORIZED
    );
    let (s, v) = json_of(
        default_app()
            .oneshot(post("/v1/runs", body, true))
            .await
            .expect("resp"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["stdout"], "1\n");
    // Health is public; metrics and policies are not.
    let h = default_app()
        .oneshot(Request::get("/healthz").body(Body::empty()).expect("req"))
        .await
        .expect("resp");
    assert_eq!(h.status(), StatusCode::OK);
    let m = default_app()
        .oneshot(Request::get("/metrics").body(Body::empty()).expect("req"))
        .await
        .expect("resp");
    assert_eq!(m.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn ac8_bind_safety() {
    let c = sandboxd_server::ServerConfig {
        listen: "0.0.0.0:8080".parse().expect("addr"),
        ..Default::default()
    };
    assert!(
        c.check_bind_safety(false)
            .expect_err("must refuse")
            .contains("refusing")
    );
    assert!(c.check_bind_safety(true).is_ok());
}

// ---------- HTTP API ----------

#[tokio::test(flavor = "multi_thread")]
async fn http_run_with_files_limits_and_artifacts() {
    let body = json!({
        "language": "py",
        "code": "import json\nrows = open('/in/d/x.csv').read().splitlines()\njson.dump({'n': len(rows)}, open('/out/r.json','w'))\nprint(len(rows))",
        "files": [{"name": "d/x.csv", "content": "YSxiCjEsMgo=", "encoding": "base64"}],
        "limits": {"wall_clock": "3s", "memory": "128MiB"}
    });
    let (s, v) = json_of(
        default_app()
            .oneshot(post("/v1/runs", body, true))
            .await
            .expect("resp"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v["outcome"].as_str(), v["stdout"].as_str()),
        (Some("ok"), Some("2\n"))
    );
    assert_eq!(v["artifacts"][0]["name"], "r.json");
    assert_eq!(v["artifacts"][0]["content_base64"], "eyJuIjogMn0="); // {"n": 2}
    assert!(v["timings"]["total_ms"].as_u64().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn http_errors_are_structured() {
    let app = || {
        app(
            service_with(Arc::new(MemorySink::default()), AdmissionConfig::default()),
            true,
            4096,
        )
    };
    let (s, v) = json_of(
        app()
            .oneshot(post(
                "/v1/runs",
                json!({"language":"python","code":"1","policy":"nope"}),
                true,
            ))
            .await
            .expect("r"),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("POLICY_NOT_FOUND"))
    );
    let (s, _) = json_of(
        app()
            .oneshot(post(
                "/v1/runs",
                json!({"language":"cobol","code":"1"}),
                true,
            ))
            .await
            .expect("r"),
    )
    .await;
    assert!(s.is_client_error());
    let (s, _) = json_of(
        app()
            .oneshot(post(
                "/v1/runs",
                json!({"language":"python","code":"1","bogus":1}),
                true,
            ))
            .await
            .expect("r"),
    )
    .await;
    assert!(s.is_client_error(), "unknown fields rejected");
    let big = json!({"language":"python","code": "#".repeat(10_000)});
    let (s, v) = json_of(app().oneshot(post("/v1/runs", big, true)).await.expect("r")).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{v}");
    let (s, v) = json_of(
        app()
            .oneshot(post(
                "/v1/runs",
                json!({"language":"python","code":"1","limits":{"memory":"8GiB"}}),
                true,
            ))
            .await
            .expect("r"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v["error"]["code"], "POLICY_VIOLATION",
        "a guest-side/policy error is a 200 with error, not an HTTP error"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn http_sse_streams_output_then_result() {
    let req = post(
        "/v1/runs?stream=true",
        json!({"language":"python","code":"import sys\nprint('one', flush=True)\nprint('two', file=sys.stderr)"}),
        true,
    );
    let resp = default_app().oneshot(req).await.expect("resp");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap_or("")
            .starts_with("text/event-stream")
    );
    let text = String::from_utf8(
        to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body")
            .to_vec(),
    )
    .expect("utf8");
    let stdout_at = text.find("event: stdout").expect("stdout event");
    let result_at = text.find("event: result").expect("result event");
    assert!(stdout_at < result_at, "{text}");
    assert!(
        text.contains("\"text\":\"one\\n\"") && text.contains("event: stderr"),
        "{text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn overloaded_returns_429() {
    let svc = service_with(
        Arc::new(MemorySink::default()),
        AdmissionConfig {
            max_concurrent: 1,
            queue_depth: 0,
            queue_timeout: Duration::from_millis(100),
            ..AdmissionConfig::default()
        },
    );
    let a = app(svc.clone(), true, 1 << 20);
    let slow = tokio::spawn(a.clone().oneshot(post(
        "/v1/runs",
        json!({"language":"python","code":"import time\ntime.sleep(2)"}),
        true,
    )));
    tokio::time::sleep(Duration::from_millis(600)).await;
    let resp = a
        .oneshot(post(
            "/v1/runs",
            json!({"language":"python","code":"print(1)"}),
            true,
        ))
        .await
        .expect("resp");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key("retry-after"));
    assert_eq!(
        slow.await.expect("join").expect("resp").status(),
        StatusCode::OK
    );
    let metrics = svc.metrics().render();
    assert!(
        metrics.contains("sandboxd_rejected_total{reason=\"overloaded\"} 1"),
        "{metrics}"
    );
    assert!(metrics.contains("sandboxd_runs_total{"), "{metrics}");
}

struct BrokenAudit;
impl AuditSink for BrokenAudit {
    fn emit(&self, _: AuditEvent) {}
    fn is_healthy(&self) -> bool {
        false
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn fails_closed_when_audit_is_broken() {
    let a = app(
        service_with(Arc::new(BrokenAudit), AdmissionConfig::default()),
        true,
        1 << 20,
    );
    let (s, v) = json_of(
        a.clone()
            .oneshot(post(
                "/v1/runs",
                json!({"language":"python","code":"print(1)"}),
                true,
            ))
            .await
            .expect("r"),
    )
    .await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("AUDIT_UNAVAILABLE"))
    );
    let h = a
        .oneshot(Request::get("/healthz").body(Body::empty()).expect("req"))
        .await
        .expect("resp");
    assert_eq!(h.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ---------- AC 7: MCP ----------

#[derive(Default, Clone)]
struct ProgressCollector(Arc<Mutex<Vec<String>>>);
impl ClientHandler for ProgressCollector {
    async fn on_progress(&self, p: ProgressNotificationParam, _c: NotificationContext<RoleClient>) {
        if let Ok(mut v) = self.0.lock() {
            v.push(p.message.unwrap_or_default());
        }
    }
}

fn args(v: Value) -> serde_json::Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

fn texts(r: &rmcp::model::CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| {
            if let ContentBlock::Text(t) = c {
                Some(t.text.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test(flavor = "multi_thread")]
async fn ac7_mcp_tools_artifacts_and_progress() {
    let svc = service_with(Arc::new(MemorySink::default()), AdmissionConfig::default());
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        if let Ok(s) = SandboxMcp::new(svc, "mcp-test").serve(server_io).await {
            let _ = s.waiting().await;
        }
    });
    let collector = ProgressCollector::default();
    let client = collector.clone().serve(client_io).await.expect("client");

    let info = client.peer_info().expect("server info");
    assert!(
        info.instructions
            .as_deref()
            .unwrap_or("")
            .contains("NO network")
    );
    let tools = client.list_all_tools().await.expect("tools");
    let names: Vec<_> = tools.iter().map(|t| t.name.to_string()).collect();
    assert!(
        names.contains(&"run_code".into()) && names.contains(&"list_policies".into()),
        "{names:?}"
    );
    let schema = serde_json::to_string(
        &tools
            .iter()
            .find(|t| t.name == "run_code")
            .expect("run_code")
            .input_schema,
    )
    .expect("schema");
    assert!(
        schema.contains("\"language\"") && schema.contains("\"files\""),
        "{schema}"
    );

    // run_code with a file and an artifact, and with a progress token → streamed output.
    let params = CallToolRequestParams::new("run_code").with_arguments(args(json!({
        "language": "python",
        "code": "import sys\nprint('streamed line', flush=True)\nopen('/out/report.md','w').write('# Report\\n' + open('/in/n.txt').read())",
        "files": [{"name": "n.txt", "content": "42"}]
    })));
    let handle = client
        .send_cancellable_request(
            ClientRequest::CallToolRequest(McpRequest::new(params)),
            PeerRequestOptions::no_options(),
        )
        .await
        .expect("send");
    let resp = handle.await_response().await.expect("response");
    let result: rmcp::model::CallToolResult = match resp {
        rmcp::model::ServerResult::CallToolResult(r) => r,
        other => panic!("unexpected {other:?}"),
    };
    assert_ne!(result.is_error, Some(true));
    let t = texts(&result);
    assert!(
        t.contains("outcome: ok") && t.contains("streamed line") && t.contains("/out/report.md"),
        "{t}"
    );
    let embedded = result.content.iter().find_map(|c| match c {
        ContentBlock::Resource(r) => Some(serde_json::to_value(&r.resource).unwrap_or_default()),
        _ => None,
    });
    let embedded = embedded.expect("artifact as embedded resource");
    assert_eq!(embedded["text"], "# Report\n42");
    assert_eq!(embedded["mimeType"], "text/markdown");
    assert_eq!(
        result
            .structured_content
            .as_ref()
            .map(|s| s["outcome"].clone()),
        Some(json!("ok"))
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    let progress = collector.0.lock().map(|v| v.clone()).unwrap_or_default();
    assert!(
        progress.iter().any(|m| m.contains("streamed line")),
        "progress notifications: {progress:?}"
    );

    // Guest failure is a normal result; numpy gets the explicit error code.
    let r = client
        .call_tool(
            CallToolRequestParams::new("run_code")
                .with_arguments(args(json!({"language":"python","code":"import pandas"}))),
        )
        .await
        .expect("call");
    assert!(
        texts(&r).contains("UNSUPPORTED_NATIVE_EXTENSION"),
        "{}",
        texts(&r)
    );
    // Service error (unknown policy) is a tool error the model can read.
    let r = client
        .call_tool(CallToolRequestParams::new("run_code").with_arguments(args(
            json!({"language":"python","code":"1","policy":"nope"}),
        )))
        .await
        .expect("call");
    assert_eq!(r.is_error, Some(true));
    assert!(texts(&r).contains("POLICY_NOT_FOUND"));
    let r = client
        .call_tool(CallToolRequestParams::new("list_policies"))
        .await
        .expect("call");
    assert!(texts(&r).contains("default"));
    let _ = client.cancel().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ac7_mcp_over_http_with_token_and_principal() {
    // TLS is compiled into reqwest (broker); rmcp's client needs the process crypto provider.
    sandboxd_net::ensure_crypto_provider();
    let audit = Arc::new(MemorySink::default());
    let svc = service_with(audit.clone(), AdmissionConfig::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let a = app(svc, true, 1 << 20);
    tokio::spawn(async move {
        let _ = axum::serve(listener, a).await;
    });
    let url = format!("http://{addr}/mcp");

    // Without a token: the connection is refused.
    let anon = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(url.clone()),
    );
    assert!(
        ().serve(anon).await.is_err(),
        "unauthenticated MCP must fail"
    );

    let t = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(url).auth_header(TOKEN),
    );
    let client = ().serve(t).await.expect("connect");
    let r = client
        .call_tool(CallToolRequestParams::new("run_code").with_arguments(args(
            json!({"language":"javascript","code":"console.log(6*7)","policy":"nope"}),
        )))
        .await
        .expect("call");
    assert!(texts(&r).contains("POLICY_NOT_FOUND"));
    // The service-level denial is audited with the token's *name*, never the token.
    let principals: Vec<_> = audit
        .events()
        .into_iter()
        .filter(|e| matches!(e.kind, EventKind::PolicyDenied { .. }))
        .filter_map(|e| e.principal)
        .collect();
    assert_eq!(principals, vec!["ci".to_string()]);
    let r = client
        .call_tool(CallToolRequestParams::new("run_code").with_arguments(args(
            json!({"language":"javascript","code":"console.log(6*7)"}),
        )))
        .await
        .expect("call");
    assert!(texts(&r).contains("42"), "{}", texts(&r));
    let _ = client.cancel().await;
}
