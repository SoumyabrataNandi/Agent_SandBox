//! C2-U2 integration tests: the broker's devices against real local HTTP, HTTPS and TCP servers.
//! No internet access. Positive cases use `allow_private_ips = true`; SSRF cases use the default
//! and assert the target server never saw a connection.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use sandboxd_audit::{AuditSink, Decision, EventKind, MemorySink, RunId};
use sandboxd_net::*;
use sandboxd_policy::Policy;
use sandboxd_vfs::VirtualDevice;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------- local servers

#[derive(Clone, Default)]
struct Hits(Arc<AtomicUsize>);

async fn echo(State(h): State<Hits>, method: Method, headers: HeaderMap, body: Bytes) -> Response {
    h.0.fetch_add(1, Ordering::SeqCst);
    let hdrs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let j = serde_json::json!({"method": method.as_str(), "headers": hdrs, "body": String::from_utf8_lossy(&body)});
    ([(header::CONTENT_TYPE, "application/json")], j.to_string()).into_response()
}

#[derive(serde::Deserialize)]
struct To {
    to: String,
    code: Option<u16>,
}

async fn redirect(State(h): State<Hits>, Query(q): Query<To>) -> Response {
    h.0.fetch_add(1, Ordering::SeqCst);
    let code = StatusCode::from_u16(q.code.unwrap_or(302)).unwrap_or(StatusCode::FOUND);
    (code, [(header::LOCATION, q.to)]).into_response()
}

async fn big(State(h): State<Hits>) -> Response {
    h.0.fetch_add(1, Ordering::SeqCst);
    vec![b'x'; 300_000].into_response()
}

async fn slow(State(h): State<Hits>) -> Response {
    h.0.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(3)).await;
    "late".into_response()
}

async fn looping(State(h): State<Hits>) -> Response {
    h.0.fetch_add(1, Ordering::SeqCst);
    (StatusCode::FOUND, [(header::LOCATION, "/api/loop")]).into_response()
}

async fn http_server() -> (SocketAddr, Hits) {
    let hits = Hits::default();
    let app = Router::new()
        .route("/api/echo", any(echo))
        .route("/api/redirect", any(redirect))
        .route("/api/big", any(big))
        .route("/api/slow", any(slow))
        .route("/api/loop", any(looping))
        .route("/admin", any(echo))
        .with_state(hits.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = l.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    (addr, hits)
}

/// Minimal HTTPS server signed by a test CA. `/redir-http?port=N` → 302 to http://127.0.0.1:N/api/echo.
async fn https_server() -> (SocketAddr, String, Hits) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "sandboxd test CA");
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).expect("ca");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("leaf params")
            .signed_by(&leaf_key, &ca)
            .expect("leaf");
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
        )
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = l.local_addr().expect("addr");
    let hits = Hits::default();
    let h2 = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = l.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let hits = h2.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                hits.0.fetch_add(1, Ordering::SeqCst);
                let mut buf = vec![0u8; 8192];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let req = String::from_utf8_lossy(&got);
                let resp = if let Some(port) = req
                    .split_whitespace()
                    .nth(1)
                    .and_then(|p| p.strip_prefix("/redir-http?port="))
                {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/api/echo\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
                        .to_string()
                };
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, ca.pem(), hits)
}

async fn tcp_echo_server() -> (SocketAddr, Hits) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = l.local_addr().expect("addr");
    let hits = Hits::default();
    let h2 = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            h2.0.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, hits)
}

// ---------------------------------------------------------------- harness

fn policy(network_toml: &str) -> Policy {
    Policy::from_toml(
        &format!("version = 1\nname = \"net\"\n[network]\n{network_toml}\n"),
        "net.toml",
    )
    .expect("policy")
}

fn run_with(broker: &Broker, p: &Policy, wall: Duration) -> (RunNet, Arc<MemorySink>) {
    let audit = Arc::new(MemorySink::default());
    let ctx = RunCtx {
        run_id: RunId::new(),
        policy: "net".into(),
        deadline: Instant::now() + wall,
        audit: audit.clone() as Arc<dyn AuditSink>,
    };
    (
        broker.for_run(p, ctx).expect("for_run").expect("grants"),
        audit,
    )
}

fn broker() -> Broker {
    Broker::new(BrokerConfig::default()).expect("broker")
}

async fn http_call(
    run: &RunNet,
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (ResponseHeader, Vec<u8>) {
    let mut dev = run.http_device().expect("http granted");
    let h = RequestHeader {
        method: method.into(),
        url: url.into(),
        headers: headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body_len: body.len() as u64,
        timeout_ms: None,
    };
    let frame = encode_request(&h, body);
    for chunk in frame.chunks(7) {
        dev.write(chunk).await.expect("write");
    }
    read_response(dev).await
}

async fn read_response(mut dev: Box<dyn VirtualDevice>) -> (ResponseHeader, Vec<u8>) {
    let mut out = Vec::new();
    let mut buf = [0u8; 1000];
    loop {
        let n = dev.read(&mut buf).await.expect("read");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    let hlen = u32::from_le_bytes([out[0], out[1], out[2], out[3]]) as usize;
    let h: ResponseHeader = serde_json::from_slice(&out[4..4 + hlen]).expect("response header");
    (h, out[4 + hlen..].to_vec())
}

fn net_events(audit: &MemorySink) -> Vec<EventKind> {
    audit
        .events()
        .into_iter()
        .map(|e| e.kind)
        .filter(|k| {
            matches!(
                k,
                EventKind::NetRequest { .. } | EventKind::NetConnect { .. }
            )
        })
        .collect()
}

fn code(h: &ResponseHeader) -> &str {
    h.error.as_ref().map(|e| e.code.as_str()).unwrap_or("")
}

fn rule(port: u16, extra: &str) -> String {
    format!(
        "allow_private_ips = true\nhttp = [{{ scheme = \"http\", host = \"127.0.0.1\", port = {port}, methods = [\"GET\", \"POST\"], path_prefix = \"/api/\" }}]\n{extra}"
    )
}

// ---------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread")]
async fn allowed_request_roundtrip_and_audit() {
    let (addr, hits) = http_server().await;
    let (run, audit) = run_with(
        &broker(),
        &policy(&rule(addr.port(), "")),
        Duration::from_secs(10),
    );
    let (h, body) = http_call(
        &run,
        "POST",
        &format!(
            "http://127.0.0.1:{}/api/echo?token=secret123&x=1",
            addr.port()
        ),
        &[("X-Test", "yes")],
        b"payload",
    )
    .await;
    assert_eq!(h.status, 200, "{h:?}");
    let j: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        (j["method"].as_str(), j["body"].as_str()),
        (Some("POST"), Some("payload"))
    );
    assert!(j["headers"].to_string().contains("x-test"));
    assert_eq!(hits.0.load(Ordering::SeqCst), 1);
    let ev = net_events(&audit);
    let EventKind::NetRequest {
        decision,
        path,
        ip,
        status,
        bytes_out,
        ..
    } = &ev[0]
    else {
        panic!("{ev:?}")
    };
    assert_eq!((*decision, status.as_ref()), (Decision::Allow, Some(&200)));
    assert_eq!(
        path.as_deref(),
        Some("/api/echo?…[2 params]"),
        "query redacted"
    );
    assert_eq!(ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(*bytes_out, 7);
    assert!(
        !format!("{ev:?}").contains("secret123") && !format!("{ev:?}").contains("payload"),
        "no query values or bodies in audit"
    );
    assert_eq!(run.finish().requests, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn non_allowlisted_requests_never_reach_the_server() {
    let (addr, hits) = http_server().await;
    let (other, other_hits) = http_server().await;
    let (run, audit) = run_with(
        &broker(),
        &policy(&rule(addr.port(), "")),
        Duration::from_secs(10),
    );
    let p = addr.port();
    for (m, url) in [
        ("GET", format!("http://127.0.0.1:{}/api/echo", other.port())), // other port
        ("DELETE", format!("http://127.0.0.1:{p}/api/echo")),           // method
        ("GET", format!("http://127.0.0.1:{p}/admin")),                 // path
        ("GET", format!("http://127.0.0.1:{p}/api/../admin")),          // traversal
        ("GET", format!("http://127.0.0.1:{p}/api%2F..%2Fadmin")),      // encoded separator
        ("GET", format!("https://127.0.0.1:{p}/api/echo")),             // scheme
        ("GET", format!("http://localhost:{p}/api/echo")),              // name vs IP rule
        ("GET", format!("http://user:pw@127.0.0.1:{p}/api/echo")),      // userinfo
        ("GET", "file:///etc/passwd".to_string()),
    ] {
        let (h, _) = http_call(&run, m, &url, &[], b"").await;
        assert_eq!(h.status, 0, "{m} {url} must be denied: {h:?}");
        assert_eq!(code(&h), "DENIED", "{m} {url}: {h:?}");
    }
    assert_eq!(
        hits.0.load(Ordering::SeqCst) + other_hits.0.load(Ordering::SeqCst),
        0,
        "no server saw a request"
    );
    assert!(net_events(&audit).iter().all(|e| matches!(
        e,
        EventKind::NetRequest {
            decision: Decision::Deny,
            ..
        }
    )));
}

#[tokio::test(flavor = "multi_thread")]
async fn ssrf_is_blocked_under_the_default_policy() {
    let (addr, hits) = http_server().await;
    let p = addr.port();
    // Same rules but WITHOUT allow_private_ips.
    let pol = policy(&format!(
        "http = [{{ scheme = \"http\", host = \"127.0.0.1\", port = {p}, path_prefix = \"/api/\" }}, {{ scheme = \"http\", host = \"localhost\", port = {p}, path_prefix = \"/api/\" }}, {{ scheme = \"http\", host = \"::ffff:7f00:1\", port = {p} }}]"
    ));
    let (run, _audit) = run_with(&broker(), &pol, Duration::from_secs(10));
    for url in [
        format!("http://127.0.0.1:{p}/api/echo"),
        format!("http://2130706433:{p}/api/echo"),
        format!("http://0x7f.1:{p}/api/echo"),
        format!("http://localhost:{p}/api/echo"), // a NAME that resolves to loopback
        format!("http://[::ffff:127.0.0.1]:{p}/api/echo"),
    ] {
        let (h, _) = http_call(&run, "GET", &url, &[], b"").await;
        assert_eq!(code(&h), "SSRF", "{url}: {h:?}");
    }
    assert_eq!(
        hits.0.load(Ordering::SeqCst),
        0,
        "the loopback server was never contacted"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn redirects_are_rechecked_every_hop() {
    let (a, a_hits) = http_server().await;
    let (b, b_hits) = http_server().await;
    let (run, audit) = run_with(
        &broker(),
        &policy(&rule(a.port(), "")),
        Duration::from_secs(10),
    );
    // allowed → other port (not allowlisted): refused at hop 1, target never contacted.
    let to = format!("http://127.0.0.1:{}/api/echo", b.port());
    let (h, _) = http_call(
        &run,
        "GET",
        &format!("http://127.0.0.1:{}/api/redirect?to={to}", a.port()),
        &[],
        b"",
    )
    .await;
    assert_eq!(code(&h), "DENIED", "{h:?}");
    assert_eq!(
        (
            a_hits.0.load(Ordering::SeqCst),
            b_hits.0.load(Ordering::SeqCst)
        ),
        (1, 0)
    );
    let hops: Vec<(u32, Decision)> = net_events(&audit)
        .iter()
        .filter_map(|e| {
            if let EventKind::NetRequest { hop, decision, .. } = e {
                Some((*hop, *decision))
            } else {
                None
            }
        })
        .collect();
    assert_eq!(hops, vec![(0, Decision::Allow), (1, Decision::Deny)]);

    // Loop: more than 5 redirects.
    let (h, _) = http_call(
        &run,
        "GET",
        &format!("http://127.0.0.1:{}/api/loop", a.port()),
        &[],
        b"",
    )
    .await;
    assert_eq!(code(&h), "TOO_MANY_REDIRECTS", "{h:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_method_rules_and_cross_origin_credential_drop() {
    let (a, _) = http_server().await;
    let (b, _) = http_server().await;
    let net = format!(
        "allow_private_ips = true\nhttp = [{{ scheme = \"http\", host = \"127.0.0.1\", port = {}, methods = [\"GET\", \"POST\"], path_prefix = \"/api/\" }}, {{ scheme = \"http\", host = \"127.0.0.1\", port = {}, methods = [\"GET\", \"POST\"], path_prefix = \"/api/\" }}]",
        a.port(),
        b.port()
    );
    let (run, _) = run_with(&broker(), &policy(&net), Duration::from_secs(10));
    let same = format!("http://127.0.0.1:{}/api/echo", a.port());
    let (h, body) = http_call(
        &run,
        "POST",
        &format!(
            "http://127.0.0.1:{}/api/redirect?code=303&to={same}",
            a.port()
        ),
        &[],
        b"data",
    )
    .await;
    assert_eq!(h.status, 200);
    let j: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        (j["method"].as_str(), j["body"].as_str()),
        (Some("GET"), Some("")),
        "303 → GET without body"
    );
    let (_, body) = http_call(
        &run,
        "POST",
        &format!(
            "http://127.0.0.1:{}/api/redirect?code=307&to={same}",
            a.port()
        ),
        &[],
        b"data",
    )
    .await;
    let j: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(
        (j["method"].as_str(), j["body"].as_str()),
        (Some("POST"), Some("data")),
        "307 keeps method + body"
    );
    // Cross-origin hop drops Authorization/Cookie; same-origin keeps them.
    let cross = format!("http://127.0.0.1:{}/api/echo", b.port());
    let creds = [
        ("Authorization", "Bearer guest-token"),
        ("Cookie", "s=1"),
        ("X-Keep", "1"),
    ];
    let (_, body) = http_call(
        &run,
        "GET",
        &format!("http://127.0.0.1:{}/api/redirect?to={cross}", a.port()),
        &creds,
        b"",
    )
    .await;
    let hdrs =
        serde_json::from_slice::<serde_json::Value>(&body).expect("json")["headers"].to_string();
    assert!(
        !hdrs.contains("guest-token") && !hdrs.contains("s=1") && hdrs.contains("x-keep"),
        "{hdrs}"
    );
    let (_, body) = http_call(
        &run,
        "GET",
        &format!("http://127.0.0.1:{}/api/redirect?to={same}", a.port()),
        &creds,
        b"",
    )
    .await;
    assert!(
        serde_json::from_slice::<serde_json::Value>(&body).expect("json")["headers"]
            .to_string()
            .contains("guest-token")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn header_policy() {
    let (addr, _) = http_server().await;
    let (run, _) = run_with(
        &broker(),
        &policy(&rule(addr.port(), "")),
        Duration::from_secs(10),
    );
    let url = format!("http://127.0.0.1:{}/api/echo", addr.port());
    let (h, _) = http_call(&run, "GET", &url, &[("X-Bad", "a\r\nInjected: 1")], b"").await;
    assert_eq!(code(&h), "PROTOCOL", "CRLF injection refused: {h:?}");
    let (h, _) = http_call(&run, "GET", &url, &[("Bad Name", "x")], b"").await;
    assert_eq!(code(&h), "PROTOCOL");
    let (_, body) = http_call(
        &run,
        "GET",
        &url,
        &[
            ("Host", "evil.example"),
            ("Proxy-Authorization", "x"),
            ("Connection", "X-Secret"),
            ("X-Secret", "s"),
            ("Transfer-Encoding", "chunked"),
        ],
        b"",
    )
    .await;
    let hdrs =
        serde_json::from_slice::<serde_json::Value>(&body).expect("json")["headers"].to_string();
    assert!(
        !hdrs.contains("evil.example")
            && !hdrs.contains("proxy-authorization")
            && !hdrs.contains("x-secret")
            && !hdrs.contains("chunked"),
        "{hdrs}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn quotas_and_timeouts() {
    let (addr, _) = http_server().await;
    let p = addr.port();
    let url = |path: &str| format!("http://127.0.0.1:{p}{path}");
    // max_requests
    let (run, audit) = run_with(
        &broker(),
        &policy(&rule(p, "max_requests = 2")),
        Duration::from_secs(10),
    );
    for _ in 0..2 {
        assert_eq!(
            http_call(&run, "GET", &url("/api/echo"), &[], b"")
                .await
                .0
                .status,
            200
        );
    }
    assert_eq!(
        code(&http_call(&run, "GET", &url("/api/echo"), &[], b"").await.0),
        "QUOTA"
    );
    assert!(run.finish().limit_hit);
    assert!(audit.events().iter().any(|e| matches!(
        e.kind,
        EventKind::LimitHit {
            kind: sandboxd_audit::LimitKind::Network,
            ..
        }
    )));
    // max_response_bytes
    let (run, _) = run_with(
        &broker(),
        &policy(&rule(p, "max_response_bytes = \"100KiB\"")),
        Duration::from_secs(10),
    );
    assert_eq!(
        code(&http_call(&run, "GET", &url("/api/big"), &[], b"").await.0),
        "RESPONSE_TOO_LARGE"
    );
    // max_total_bytes across requests
    let (run, _) = run_with(
        &broker(),
        &policy(&rule(p, "max_total_bytes = \"400KiB\"")),
        Duration::from_secs(10),
    );
    assert_eq!(
        http_call(&run, "GET", &url("/api/big"), &[], b"")
            .await
            .0
            .status,
        200
    );
    assert_eq!(
        code(&http_call(&run, "GET", &url("/api/big"), &[], b"").await.0),
        "QUOTA"
    );
    // request body over max_request_bytes is refused at the frame
    let (run, _) = run_with(
        &broker(),
        &policy(&rule(p, "max_request_bytes = \"10B\"")),
        Duration::from_secs(10),
    );
    assert_eq!(
        code(
            &http_call(&run, "POST", &url("/api/echo"), &[], b"0123456789AB")
                .await
                .0
        ),
        "PROTOCOL"
    );
    // request_timeout
    let (run, _) = run_with(
        &broker(),
        &policy(&rule(p, "request_timeout = \"500ms\"")),
        Duration::from_secs(10),
    );
    let t = Instant::now();
    assert_eq!(
        code(&http_call(&run, "GET", &url("/api/slow"), &[], b"").await.0),
        "TIMEOUT"
    );
    assert!(
        t.elapsed() < Duration::from_millis(1500),
        "{:?}",
        t.elapsed()
    );
    // the run's wall clock bounds network time too
    let (run, _) = run_with(&broker(), &policy(&rule(p, "")), Duration::from_millis(400));
    assert_eq!(
        code(&http_call(&run, "GET", &url("/api/slow"), &[], b"").await.0),
        "TIMEOUT"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_uses_trust_store_plus_extra_ca_and_refuses_downgrade() {
    let (addr, ca_pem, hits) = https_server().await;
    let (plain, plain_hits) = http_server().await;
    let net = format!(
        "allow_private_ips = true\nhttp = [{{ host = \"localhost\", port = {} }}, {{ scheme = \"http\", host = \"127.0.0.1\", port = {}, path_prefix = \"/api/\" }}]",
        addr.port(),
        plain.port()
    );
    let pol = policy(&net);
    let url = format!("https://localhost:{}/", addr.port());
    // Without the test CA: certificate validation fails.
    let (run, _) = run_with(&broker(), &pol, Duration::from_secs(10));
    let (h, _) = http_call(&run, "GET", &url, &[], b"").await;
    assert_eq!(code(&h), "TLS", "{h:?}");
    // With extra_ca_file: succeeds.
    let with_ca = Broker::new(BrokerConfig {
        extra_ca_pem: Some(ca_pem.into_bytes()),
        ..BrokerConfig::default()
    })
    .expect("broker");
    let (run, _) = run_with(&with_ca, &pol, Duration::from_secs(10));
    let (h, body) = http_call(&run, "GET", &url, &[], b"").await;
    assert_eq!(
        (h.status, body.as_slice()),
        (200, b"hello".as_slice()),
        "{h:?}"
    );
    // https → http redirect is refused even though an http rule matches the target.
    let (h, _) = http_call(
        &run,
        "GET",
        &format!(
            "https://localhost:{}/redir-http?port={}",
            addr.port(),
            plain.port()
        ),
        &[],
        b"",
    )
    .await;
    assert_eq!(code(&h), "DENIED", "{h:?}");
    assert!(
        h.error
            .as_ref()
            .is_some_and(|e| e.message.contains("https to http"))
    );
    assert_eq!(plain_hits.0.load(Ordering::SeqCst), 0);
    assert!(hits.0.load(Ordering::SeqCst) >= 2);
    assert!(
        Broker::new(BrokerConfig {
            extra_ca_pem: Some(b"not a pem".to_vec()),
            ..BrokerConfig::default()
        })
        .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_streams_rules_ssrf_and_audit() {
    let (addr, hits) = tcp_echo_server().await;
    let net = format!(
        "allow_private_ips = true\ntcp = [{{ host = \"127.0.0.1\", port = {} }}]",
        addr.port()
    );
    let (run, audit) = run_with(&broker(), &policy(&net), Duration::from_secs(10));
    let mut dev = run
        .tcp_device(&format!("127.0.0.1:{}", addr.port()))
        .expect("allowed");
    dev.opened().await.expect("connect");
    assert_eq!(dev.write(b"ping").await.expect("write"), 4);
    let mut buf = [0u8; 16];
    let n = dev.read(&mut buf).await.expect("read");
    assert_eq!(&buf[..n], b"ping");
    dev.close().await.expect("close");
    let ev = net_events(&audit);
    assert!(
        matches!(
            ev.last(),
            Some(EventKind::NetConnect {
                decision: Decision::Allow,
                bytes_out: 4,
                bytes_in: 4,
                ..
            })
        ),
        "{ev:?}"
    );
    // Unlisted port: refused synchronously by the factory.
    assert!(
        run.tcp_device(&format!("127.0.0.1:{}", addr.port() + 1))
            .is_err()
    );
    // Default policy (no private IPs): refused at open, server untouched.
    let before = hits.0.load(Ordering::SeqCst);
    let (run, _) = run_with(
        &broker(),
        &policy(&format!(
            "tcp = [{{ host = \"127.0.0.1\", port = {} }}]",
            addr.port()
        )),
        Duration::from_secs(10),
    );
    let mut dev = run
        .tcp_device(&format!("127.0.0.1:{}", addr.port()))
        .expect("rule matches");
    assert!(dev.opened().await.is_err(), "SSRF: loopback refused");
    assert_eq!(hits.0.load(Ordering::SeqCst), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn frame_protocol_errors() {
    let (addr, _) = http_server().await;
    let (run, _) = run_with(
        &broker(),
        &policy(&rule(addr.port(), "")),
        Duration::from_secs(10),
    );
    let mut dev = run.http_device().expect("http");
    dev.write(&[5, 0]).await.expect("partial");
    let mut b = [0u8; 8];
    assert!(
        dev.read(&mut b).await.is_err(),
        "read before a complete frame → EINVAL"
    );
    let mut dev = run.http_device().expect("http");
    dev.write(&[3, 0, 0, 0, b'b', b'a', b'd'])
        .await
        .expect("garbage");
    let (h, _) = read_response(dev).await;
    assert_eq!(code(&h), "PROTOCOL");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_grants_means_no_broker_and_overhead_is_small() {
    let none = Policy::from_toml("version = 1\nname = \"n\"", "n.toml").expect("p");
    let ctx = RunCtx {
        run_id: RunId::new(),
        policy: "n".into(),
        deadline: Instant::now() + Duration::from_secs(1),
        audit: Arc::new(MemorySink::default()),
    };
    assert!(
        broker().for_run(&none, ctx).expect("ok").is_none(),
        "no grants → no client, no devices"
    );

    let (addr, _) = http_server().await;
    let t = Instant::now();
    let (run, _) = run_with(
        &broker(),
        &policy(&rule(addr.port(), "max_requests = 1000")),
        Duration::from_secs(30),
    );
    let build = t.elapsed();
    let url = format!("http://127.0.0.1:{}/api/echo", addr.port());
    let _ = http_call(&run, "GET", &url, &[], b"").await; // warm the pool
    let n = 50;
    let t = Instant::now();
    for _ in 0..n {
        assert_eq!(http_call(&run, "GET", &url, &[], b"").await.0.status, 200);
    }
    let per = t.elapsed() / n;
    eprintln!("per-run client build: {build:?}; per request (local, debug build): {per:?}");
    assert!(
        per < Duration::from_millis(25),
        "broker overhead too high: {per:?}"
    );
}
