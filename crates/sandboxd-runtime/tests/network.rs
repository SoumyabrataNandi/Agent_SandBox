//! C2-U3 acceptance tests: real CPython 3.15 and QuickJS-ng guests reaching in-process HTTP,
//! HTTPS (test CA) and TCP servers through the broker. No internet access. Positive policies use
//! `allow_private_ips = true` (the servers are on 127.0.0.1); every denial test asserts that the
//! target server saw no request.

use std::{
    net::SocketAddr,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use sandboxd_audit::{Decision, EventKind, MemorySink};
use sandboxd_net::{Broker, BrokerConfig};
use sandboxd_policy::Policy;
use sandboxd_runtime::*;
use sandboxd_vfs::VfsConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------- test CA

struct TestCa {
    ca_pem: String,
    leaf_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn test_ca() -> &'static TestCa {
    static CA: OnceLock<TestCa> = OnceLock::new();
    CA.get_or_init(|| {
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name
            .push(rcgen::DnType::CommonName, "sandboxd runtime test CA");
        let ca = rcgen::CertifiedIssuer::self_signed(p, ca_key).expect("ca");
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
            .expect("leaf params")
            .signed_by(&leaf_key, &ca)
            .expect("leaf");
        TestCa {
            ca_pem: ca.pem(),
            leaf_der: leaf.der().to_vec(),
            key_der: leaf_key.serialize_der(),
        }
    })
}

// ---------------------------------------------------------------- sandboxes

fn root() -> std::path::PathBuf {
    // Shares the runtime tests' cache (cargo runs test binaries one at a time) to save disk.
    std::env::temp_dir().join("sandboxd-runtime-tests")
}

fn build(broker: Option<Arc<Broker>>) -> (Sandbox, Arc<MemorySink>) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let audit = Arc::new(MemorySink::default());
        let cfg = RuntimeConfig {
            vfs: VfsConfig::under(root()),
            broker,
            ..RuntimeConfig::default()
        };
        let (sb, _) = rt
            .block_on(Sandbox::new(cfg, audit.clone()))
            .expect("sandbox");
        (sb, audit)
    })
    .join()
    .expect("build thread")
}

/// Sandbox with a broker that trusts the test CA (on top of the OS store).
fn sandbox() -> &'static (Sandbox, Arc<MemorySink>) {
    static S: OnceLock<(Sandbox, Arc<MemorySink>)> = OnceLock::new();
    S.get_or_init(|| {
        sandboxd_net::ensure_crypto_provider();
        let broker = Broker::new(BrokerConfig {
            extra_ca_pem: Some(test_ca().ca_pem.clone().into_bytes()),
            ..BrokerConfig::default()
        })
        .expect("broker");
        build(Some(Arc::new(broker)))
    })
}

fn policy(network: &str) -> Arc<Policy> {
    Arc::new(
        Policy::from_toml(
            &format!("version = 1\nname = \"net\"\n[env]\nTZ = \"UTC\"\n[network]\n{network}\n"),
            "net.toml",
        )
        .expect("policy"),
    )
}

fn default_policy() -> Arc<Policy> {
    Arc::new(
        Policy::from_toml("version = 1\nname = \"default\"\n", "default.toml").expect("policy"),
    )
}

async fn run_on(sb: &Sandbox, lang: Language, code: &str, p: Arc<Policy>) -> RunResult {
    sb.execute(RunRequest::new(lang, code), p, "test", None)
        .await
}

async fn py(code: &str, p: Arc<Policy>) -> RunResult {
    run_on(&sandbox().0, Language::Python, code, p).await
}

async fn js(code: &str, p: Arc<Policy>) -> RunResult {
    run_on(&sandbox().0, Language::JavaScript, code, p).await
}

fn out(r: &RunResult) -> String {
    String::from_utf8_lossy(&r.stdout).into_owned()
}

fn err(r: &RunResult) -> String {
    String::from_utf8_lossy(&r.stderr).into_owned()
}

#[track_caller]
fn assert_ok(r: &RunResult) {
    assert_eq!(
        r.outcome,
        Outcome::Ok,
        "stdout:\n{}\nstderr:\n{}\nerror: {:?}",
        out(r),
        err(r),
        r.error
    );
}

// ---------------------------------------------------------------- local servers

#[derive(Clone, Default)]
struct Hits(Arc<AtomicUsize>);
impl Hits {
    fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

async fn echo(State(h): State<Hits>, method: Method, headers: HeaderMap, body: Bytes) -> Response {
    h.0.fetch_add(1, Ordering::SeqCst);
    // Repeated headers are joined with ", " so the test sees every value.
    let mut hdrs = serde_json::Map::new();
    for name in headers.keys() {
        let joined: Vec<String> = headers
            .get_all(name)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect();
        hdrs.insert(name.to_string(), joined.join(", ").into());
    }
    let j = serde_json::json!({
        "method": method.as_str(),
        "headers": hdrs,
        "body": String::from_utf8_lossy(&body),
    });
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::HeaderName::from_static("x-multi"), "a"),
        ],
        j.to_string(),
    )
        .into_response()
}

#[derive(serde::Deserialize)]
struct To {
    to: String,
}

async fn redirect(State(h): State<Hits>, Query(q): Query<To>) -> Response {
    h.0.fetch_add(1, Ordering::SeqCst);
    (StatusCode::FOUND, [(header::LOCATION, q.to)]).into_response()
}

async fn slow(State(h): State<Hits>) -> Response {
    h.0.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(3)).await;
    "late".into_response()
}

async fn missing(State(h): State<Hits>) -> Response {
    h.0.fetch_add(1, Ordering::SeqCst);
    (StatusCode::NOT_FOUND, "nope").into_response()
}

async fn http_server() -> (SocketAddr, Hits) {
    let hits = Hits::default();
    let app = Router::new()
        .route("/api/echo", any(echo))
        .route("/api/redirect", any(redirect))
        .route("/api/slow", any(slow))
        .route("/api/missing", any(missing))
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

/// HTTPS server signed by the test CA; answers `hello <path>`.
async fn https_server() -> (SocketAddr, Hits) {
    sandboxd_net::ensure_crypto_provider();
    let ca = test_ca();
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![ca.leaf_der.clone().into()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(ca.key_der.clone().into()),
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
            let (acceptor, hits) = (acceptor.clone(), h2.clone());
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
                let path = req.split_whitespace().nth(1).unwrap_or("?").to_string();
                let body = format!("hello {path}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, hits)
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

fn http_policy(port: u16, extra: &str) -> Arc<Policy> {
    policy(&format!(
        "allow_private_ips = true\nhttp = [{{ scheme = \"http\", host = \"127.0.0.1\", port = {port}, methods = [\"GET\", \"POST\", \"HEAD\"], path_prefix = \"/api/\" }}]\n{extra}"
    ))
}

fn net_events(audit: &MemorySink) -> Vec<sandboxd_audit::AuditEvent> {
    audit
        .events()
        .into_iter()
        .filter(|e| {
            matches!(
                e.kind,
                EventKind::NetRequest { .. } | EventKind::NetConnect { .. }
            )
        })
        .collect()
}

// ---------------------------------------------------------------- Python

#[tokio::test(flavor = "multi_thread")]
async fn python_urllib_get_post_redirect_and_http_error() {
    let (addr, hits) = http_server().await;
    let code = r#"
import json, urllib.request, urllib.error
base = "http://127.0.0.1:PORT"
with urllib.request.urlopen(base + "/api/echo?q=1") as r:
    print("get", r.status, json.loads(r.read())["method"], r.headers["Content-Type"])
req = urllib.request.Request(base + "/api/echo", data=b'{"a": 1}',
                             headers={"Content-Type": "application/json", "X-Token": "t1"})
with urllib.request.urlopen(req) as r:
    j = json.load(r)
    print("post", j["method"], j["body"], j["headers"]["x-token"], j["headers"]["content-type"])
with urllib.request.urlopen(base + "/api/redirect?to=/api/echo") as r:
    print("redirect", r.status, r.geturl())
try:
    urllib.request.urlopen(base + "/api/missing")
except urllib.error.HTTPError as e:
    print("http-error", e.code, e.read())
"#
    .replace("PORT", &addr.port().to_string());
    let r = py(&code, http_policy(addr.port(), "")).await;
    assert_ok(&r);
    let o = out(&r);
    assert!(o.contains("get 200 GET application/json"), "{o}");
    assert!(
        o.contains(r#"post POST {"a": 1} t1 application/json"#),
        "{o}"
    );
    assert!(
        o.contains(&format!(
            "redirect 200 http://127.0.0.1:{}/api/echo",
            addr.port()
        )),
        "{o}"
    );
    assert!(o.contains("http-error 404 b'nope'"), "{o}");
    assert_eq!(hits.get(), 5, "get + post + redirect(2 hops) + 404");
}

#[tokio::test(flavor = "multi_thread")]
async fn python_http_client_connection_reuse_and_head() {
    let (addr, _) = http_server().await;
    let code = r#"
import http.client, json
c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
for i in range(2):
    c.request("POST", "/api/echo", body=f"n={i}", headers={"X-I": str(i)})
    r = c.getresponse()
    j = json.loads(r.read())
    print("req", i, r.status, r.reason, j["body"], j["headers"]["x-i"], r.getheader("x-multi"))
c.request("HEAD", "/api/echo")
r = c.getresponse()
print("head", r.status, repr(r.read()))
c.close()
"#
    .replace("PORT", &addr.port().to_string());
    let r = py(&code, http_policy(addr.port(), "")).await;
    assert_ok(&r);
    let o = out(&r);
    assert!(o.contains("req 0 200 OK n=0 0 a"), "{o}");
    assert!(o.contains("req 1 200 OK n=1 1 a"), "{o}");
    assert!(o.contains("head 200 b''"), "{o}");
}

#[tokio::test(flavor = "multi_thread")]
async fn python_https_via_urllib_http_client_and_fetch() {
    let (addr, hits) = https_server().await;
    let p = policy(&format!(
        "allow_private_ips = true\nhttp = [{{ host = \"127.0.0.1\", port = {} }}]",
        addr.port()
    ));
    let code = r#"
import urllib.request, http.client, sandbox_net
print("urllib", urllib.request.urlopen("https://127.0.0.1:PORT/a").read().decode())
c = http.client.HTTPSConnection("127.0.0.1", PORT)
c.request("GET", "/b")
print("client", c.getresponse().read().decode())
r = sandbox_net.fetch("https://127.0.0.1:PORT/c?x=1", headers={"Accept": "text/plain"})
print("fetch", r.status, r.ok, r.text(), r.headers.get("content-type"), r.url)
"#
    .replace("PORT", &addr.port().to_string());
    let r = py(&code, p).await;
    assert_ok(&r);
    let o = out(&r);
    assert!(o.contains("urllib hello /a"), "{o}");
    assert!(o.contains("client hello /b"), "{o}");
    assert!(
        o.contains(&format!(
            "fetch 200 True hello /c?x=1 text/plain https://127.0.0.1:{}/c?x=1",
            addr.port()
        )),
        "{o}"
    );
    assert_eq!(hits.get(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn python_socket_create_connection_and_connect() {
    let (addr, hits) = tcp_echo_server().await;
    let p = policy(&format!(
        "allow_private_ips = true\ntcp = [{{ host = \"127.0.0.1\", port = {} }}]",
        addr.port()
    ));
    let code = r#"
import socket, sandbox_net
s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
s.sendall(b"ping\n")
print("recv", s.recv(100))
f = s.makefile("rwb")
f.write(b"line two\n"); f.flush()
print("line", f.readline())
s.close()
with sandbox_net.connect("127.0.0.1", PORT) as c:
    c.sendall("é".encode())
    buf = bytearray(8)
    n = c.recv_into(buf)
    print("into", n, bytes(buf[:n]).decode())
"#
    .replace("PORT", &addr.port().to_string());
    let audit_before = sandbox().1.events().len();
    let r = py(&code, p).await;
    assert_ok(&r);
    let o = out(&r);
    assert!(o.contains("recv b'ping\\n'"), "{o}");
    assert!(o.contains("line b'line two\\n'"), "{o}");
    assert!(o.contains("into 2 é"), "{o}");
    assert_eq!(hits.get(), 2);
    let connects = sandbox().1.events()[audit_before..]
        .iter()
        .filter(|e| {
            e.run_id == Some(r.run_id)
                && matches!(
                    &e.kind,
                    EventKind::NetConnect {
                        decision: Decision::Allow,
                        ..
                    }
                )
        })
        .count();
    assert_eq!(connects, 2, "both TCP sessions audited");
}

#[tokio::test(flavor = "multi_thread")]
async fn python_denials_proxy_and_timeout_never_reach_the_server() {
    let (addr, hits) = http_server().await;
    let (tcp, tcp_hits) = tcp_echo_server().await;
    let p = http_policy(addr.port(), "request_timeout = \"500ms\"");
    let code = r#"
import urllib.request, urllib.error, http.client, socket, sandbox_net
base = "http://127.0.0.1:PORT"
try:
    urllib.request.urlopen(base + "/admin")
except urllib.error.URLError as e:
    print("urllib", type(e.reason).__name__, e.reason.code, "/admin" in str(e.reason))
try:
    sandbox_net.fetch(base + "/api/echo", method="DELETE")
except PermissionError as e:
    print("method", e.code)
c = http.client.HTTPConnection("127.0.0.1", PORT)
try:
    c.set_tunnel("evil.example", 443)
except PermissionError as e:
    print("tunnel", e.code, "prox" in str(e))
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": "http://127.0.0.1:PORT"}))
try:
    opener.open("http://example.com/")
except urllib.error.URLError as e:
    print("proxy", type(e.reason).__name__)
try:
    socket.create_connection(("127.0.0.1", TCP))
except PermissionError as e:
    print("tcp", e)
import time
t = time.monotonic()
try:
    urllib.request.urlopen(base + "/api/slow", timeout=30)
except urllib.error.URLError as e:
    print("slow", type(e.reason).__name__, e.reason.code, time.monotonic() - t < 2.5)
"#
    .replace("PORT", &addr.port().to_string())
    .replace("TCP", &tcp.port().to_string());
    let r = py(&code, p).await;
    // The policy's request_timeout firing is a `network` limit (C2-U2); the program still ran
    // to completion and handled every error itself.
    assert_eq!(r.exit_code, Some(0), "{}", err(&r));
    assert_eq!(r.outcome, Outcome::Limit);
    assert!(
        r.limits_hit.contains(&LimitKind::Network),
        "{:?}",
        r.limits_hit
    );
    let o = out(&r);
    assert!(o.contains("urllib PermissionError DENIED True"), "{o}");
    assert!(o.contains("method DENIED"), "{o}");
    assert!(o.contains("tunnel DENIED True"), "{o}");
    assert!(o.contains("proxy PermissionError"), "{o}");
    assert!(
        o.contains("tcp raw TCP connections are not allowed by policy 'net' (it grants HTTP only)"),
        "{o}"
    );
    assert!(o.contains("slow TimeoutError TIMEOUT True"), "{o}");
    assert_eq!(
        hits.get(),
        1,
        "only the allowed /api/slow request reached the server"
    );
    assert_eq!(tcp_hits.get(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn quota_exhaustion_is_a_network_limit() {
    let (addr, hits) = http_server().await;
    let code = r#"
import sandbox_net
print(sandbox_net.fetch("http://127.0.0.1:PORT/api/echo").status)
try:
    sandbox_net.fetch("http://127.0.0.1:PORT/api/echo")
except OSError as e:
    print("second", type(e).__name__, e.code)
"#
    .replace("PORT", &addr.port().to_string());
    let r = py(&code, http_policy(addr.port(), "max_requests = 1")).await;
    let o = out(&r);
    assert!(o.contains("200"), "{o}\n{}", err(&r));
    assert!(o.contains("second OSError QUOTA"), "{o}");
    assert_eq!(r.outcome, Outcome::Limit);
    assert!(
        r.limits_hit.contains(&LimitKind::Network),
        "{:?}",
        r.limits_hit
    );
    assert_eq!(hits.get(), 1);
}

// ---------------------------------------------------------------- JavaScript

#[tokio::test(flavor = "multi_thread")]
async fn javascript_fetch_get_post_json_headers_and_utf8() {
    let (addr, hits) = http_server().await;
    let code = r#"
const base = "http://127.0.0.1:PORT";
const r = await fetch(base + "/api/echo?x=1");
console.log("get", r.status, r.ok, r.statusText, r.headers.get("content-type"), r.url, r.redirected);
const j = await r.json();
console.log("method", j.method);
const h = new Headers({ "X-Token": "t1" });
h.append("x-token", "t2");
const p = await fetch(base + "/api/echo", { method: "post", headers: h, body: "héllo ✓ 😀" });
const pj = await p.json();
console.log("post", pj.method, pj.body, pj.headers["x-token"], pj.headers["content-type"]);
const bin = await fetch(base + "/api/echo", { method: "POST", body: new Uint8Array([104, 105]) });
console.log("bin", (await bin.json()).body, bin.bodyUsed);
const red = await fetch(base + "/api/redirect?to=/api/echo");
console.log("redirect", red.status, red.redirected, red.url);
const miss = await fetch(base + "/api/missing");
console.log("missing", miss.status, miss.ok, await miss.text());
try {
  await fetch(base + "/admin");
} catch (e) {
  console.log("denied", e.name, e.cause.code);
}
console.log("args", JSON.stringify(scriptArgs), typeof os, typeof std);
"#
    .replace("PORT", &addr.port().to_string());
    let r = js(&code, http_policy(addr.port(), "")).await;
    assert_ok(&r);
    let o = out(&r);
    let port = addr.port();
    assert!(
        o.contains(&format!(
            "get 200 true OK application/json http://127.0.0.1:{port}/api/echo?x=1 false"
        )),
        "{o}"
    );
    assert!(o.contains("method GET"), "{o}");
    assert!(
        o.contains("post POST héllo ✓ 😀 t1, t2 text/plain;charset=UTF-8"),
        "{o}"
    );
    assert!(o.contains("bin hi true"), "{o}");
    assert!(
        o.contains(&format!(
            "redirect 200 true http://127.0.0.1:{port}/api/echo"
        )),
        "{o}"
    );
    assert!(o.contains("missing 404 false nope"), "{o}");
    assert!(o.contains("denied TypeError DENIED"), "{o}");
    assert!(
        o.contains(r#"args ["/code/main.mjs"] undefined undefined"#),
        "no globals leak: {o}"
    );
    assert_eq!(hits.get(), 6, "get, post, bin, redirect (2 hops), missing");
}

#[tokio::test(flavor = "multi_thread")]
async fn javascript_https_fetch_with_test_ca() {
    let (addr, _) = https_server().await;
    let p = policy(&format!(
        "allow_private_ips = true\nhttp = [{{ host = \"127.0.0.1\", port = {} }}]",
        addr.port()
    ));
    let code = format!(
        "const r = await fetch('https://127.0.0.1:{}/js'); console.log(r.status, await r.text());",
        addr.port()
    );
    let r = js(&code, p).await;
    assert_ok(&r);
    assert!(out(&r).contains("200 hello /js"), "{}", out(&r));
}

// ---------------------------------------------------------------- no grants / no broker

#[tokio::test(flavor = "multi_thread")]
async fn no_grant_fails_clearly_in_both_languages() {
    let (addr, hits) = http_server().await;
    let url = format!("http://127.0.0.1:{}/api/echo", addr.port());
    let r = py(
        &format!("import urllib.request\nurllib.request.urlopen({url:?})\n"),
        default_policy(),
    )
    .await;
    assert_eq!(r.outcome, Outcome::Exit);
    let e = err(&r);
    assert!(
        e.contains("network access is not allowed by policy 'default'"),
        "{e}"
    );
    assert!(e.contains("File \"/code/main.py\", line 2"), "{e}");
    assert!(!e.contains("boot.py"), "bootstrap frames are hidden: {e}");

    let r = py(
        "import sandbox_net\nsandbox_net.fetch('https://example.com')\n",
        default_policy(),
    )
    .await;
    assert!(
        err(&r).contains("PermissionError: network access is not allowed by policy 'default'"),
        "{}",
        err(&r)
    );

    let r = js(
        &format!("try {{ await fetch({url:?}); }} catch (e) {{ console.log(e.name + ': ' + e.message); }}"),
        default_policy(),
    )
    .await;
    assert_ok(&r);
    assert!(
        out(&r).contains("TypeError: network access is not allowed by policy 'default'"),
        "{}",
        out(&r)
    );
    assert_eq!(hits.get(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn grants_without_a_broker_are_refused_before_the_guest_runs() {
    static NO_BROKER: OnceLock<(Sandbox, Arc<MemorySink>)> = OnceLock::new();
    let (sb, _) = NO_BROKER.get_or_init(|| build(None));
    let r = run_on(sb, Language::Python, "print('ran')", http_policy(9, "")).await;
    assert_eq!(r.outcome, Outcome::Error);
    assert_eq!(
        r.error.as_ref().map(RunError::code),
        Some("POLICY_VIOLATION")
    );
    assert!(r.stdout.is_empty());
    // A policy without grants runs normally on the same runtime.
    let r = run_on(sb, Language::Python, "print('ran')", default_policy()).await;
    assert_ok(&r);
}

// ---------------------------------------------------------------- compatibility (design §8)

#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_is_invisible_to_programs() {
    // A granting policy forces the Python bootstrap (plain no-grant runs launch natively).
    let p = http_policy(9, "");
    let mut req = RunRequest::new(
        Language::Python,
        "import sys\nprint(sys.argv, __name__, __file__, '/code' in sys.path)\ndef f():\n    1/0\nf()\n",
    );
    req.args = vec!["a".into(), "b".into()];
    let r = sandbox().0.execute(req, p.clone(), "test", None).await;
    assert_eq!(r.exit_code, Some(1));
    assert!(
        out(&r).contains("['/code/main.py', 'a', 'b'] __main__ /code/main.py False"),
        "{}",
        out(&r)
    );
    let expected = "Traceback (most recent call last):\n  File \"/code/main.py\", line 5, in <module>\n    f()\n    ~^^\n  File \"/code/main.py\", line 4, in f\n    1/0\n    ~^~\nZeroDivisionError: division by zero\n";
    assert_eq!(err(&r), expected);

    let r = py("x = (\n", p.clone()).await;
    assert_eq!(
        err(&r),
        "  File \"/code/main.py\", line 1\n    x = (\n        ^\nSyntaxError: '(' was never closed\n"
    );
    let r = py("import sys\nsys.exit(3)\n", p.clone()).await;
    assert_eq!((r.exit_code, r.outcome), (Some(3), Outcome::Exit));

    let r = js(
        "function g() { throw new Error('boom'); }\ng();\n",
        p.clone(),
    )
    .await;
    assert_eq!(r.exit_code, Some(1));
    assert!(
        err(&r).starts_with("Error: boom\n    at g (/code/main.mjs:1:"),
        "{}",
        err(&r)
    );
    assert!(!err(&r).contains("boot.js"), "{}", err(&r));
}

#[tokio::test(flavor = "multi_thread")]
async fn no_network_events_and_quiet_audit_for_plain_runs() {
    let audit = &sandbox().1;
    let r = py("print('hi')", default_policy()).await;
    assert_ok(&r);
    let mine: Vec<_> = audit
        .events()
        .into_iter()
        .filter(|e| e.run_id == Some(r.run_id))
        .collect();
    assert!(net_events(audit).iter().all(|e| e.run_id != Some(r.run_id)));
    // Helper reads are summarized into one event, not logged file by file.
    let helper_events = mine
        .iter()
        .filter(|e| {
            matches!(&e.kind, EventKind::FsAccess { path, .. } if path.starts_with("/usr/local/lib/sandboxd"))
        })
        .count();
    assert!(helper_events <= 1, "{helper_events} helper events");
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_open_with_plain_python_open_and_info_is_minimal() {
    // CPython's open() fstat()s the fd: virtual fds must answer fd_filestat_get (C2-U3 §6).
    let r = py(
        "import json\nwith open('/dev/sandbox/info', 'rb') as f:\n    print(sorted(json.loads(f.read()).items()))\n",
        http_policy(9, ""),
    )
    .await;
    assert_ok(&r);
    assert_eq!(
        out(&r).trim(),
        "[('http', True), ('policy', 'net'), ('tcp', False)]",
        "only the policy name and two booleans are exposed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn python_bootstrap_is_used_only_when_networking_is_possible() {
    // NFR-N3: a plain program without grants launches exactly as in cycle 1 (no bootstrap).
    let plain = py(
        "import sys\nprint('sandboxd_boot' in sys.modules)\n",
        default_policy(),
    )
    .await;
    assert_eq!(out(&plain).trim(), "False");
    // A program that mentions networking gets the bootstrap (and its clear errors, N2.3)...
    let net = py(
        "import sys\nprint('sandboxd_boot' in sys.modules)  # socket\n",
        default_policy(),
    )
    .await;
    assert_eq!(out(&net).trim(), "True");
    // ...and so does every program under a policy that grants network access.
    let granted = py(
        "import sys\nprint('sandboxd_boot' in sys.modules)\n",
        http_policy(9, ""),
    )
    .await;
    assert_eq!(out(&granted).trim(), "True");
    // The bootstrap adds no measurable instructions to plain runs.
    assert!(
        net.fuel_used > plain.fuel_used + 10_000_000,
        "plain {} vs bootstrap {}",
        plain.fuel_used,
        net.fuel_used
    );
}
