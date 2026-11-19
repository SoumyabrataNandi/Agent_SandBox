//! E-NET: release-blocking network escape cases (cycle 2, C2-U5; NFR-N1, threats T13–T18).
//!
//! Black-box through the `RunService`, with real CPython / QuickJS guests and in-process servers
//! on 127.0.0.1 (no internet access). Forbidden servers serve the canary and count every
//! connection; the universal invariants after each case are:
//! * no attack reports `ESCAPED`, and the canary never appears in output, artifacts or audit;
//! * **forbidden destinations were never contacted** (their hit counters stay at 0);
//! * secret query values never reach the audit log; the service stays healthy.

use std::{
    path::Path,
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
use sandboxd_audit::{Decision, EventKind, MemorySink, Redactor};
use sandboxd_net::{Broker, BrokerConfig};
use sandboxd_policy::{LoadOptions, PolicyDir};
use sandboxd_runtime::{LimitKind, Outcome, RunResult, RuntimeConfig, Sandbox};
use sandboxd_server::{
    AdmissionConfig, Principal, RunService,
    api::{ApiLanguage, ApiRunRequest},
};
use sandboxd_vfs::VfsConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Secret-looking query value placed in URLs: it must never reach the audit log.
const QSECRET: &str = "QSECRET9f2c";

#[derive(Clone, Default)]
struct Hits(Arc<AtomicUsize>);
impl Hits {
    fn hit(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// Every server a guest must never reach.
#[derive(Clone, Default)]
struct Forbidden {
    /// HTTP server in no policy.
    f: Hits,
    /// `/secret` on the allowed server (outside the `/api/` prefix).
    a_secret: Hits,
    /// HTTP server allowlisted only in `netdef` (default SSRF rules → loopback blocked).
    d: Hits,
    /// HTTP server allowlisted in `netpos`, reachable only via an https→http downgrade redirect.
    g: Hits,
    /// TCP server in no policy.
    tf: Hits,
    /// TCP server allowlisted only in `netdef`.
    td: Hits,
}

struct Ports {
    a: u16,
    f: u16,
    d: u16,
    g: u16,
    s: u16,
    t: u16,
    tf: u16,
    td: u16,
    slow: u16,
    hang: u16,
}

struct NetWorld {
    service: RunService,
    audit: Arc<MemorySink>,
    canary: String,
    forbidden: Forbidden,
    p: Ports,
    _rt: tokio::runtime::Runtime,
}

// ---------------------------------------------------------------- servers

#[derive(Clone)]
struct AState {
    canary: String,
    secret: Hits,
}

async fn echo(method: Method, headers: HeaderMap, body: Bytes) -> Response {
    let mut h = serde_json::Map::new();
    for name in headers.keys() {
        let v: Vec<String> = headers
            .get_all(name)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
            .collect();
        h.insert(name.to_string(), v.join(", ").into());
    }
    let j = serde_json::json!({"method": method.as_str(), "headers": h, "body": String::from_utf8_lossy(&body)});
    ([(header::CONTENT_TYPE, "application/json")], j.to_string()).into_response()
}

#[derive(serde::Deserialize)]
struct To {
    to: String,
}

async fn redirect(Query(q): Query<To>) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, q.to)]).into_response()
}

async fn looping() -> Response {
    (StatusCode::FOUND, [(header::LOCATION, "/api/loop")]).into_response()
}

async fn big() -> Response {
    vec![b'x'; 200_000].into_response()
}

async fn secret(State(s): State<AState>) -> Response {
    s.secret.hit();
    s.canary.clone().into_response()
}

async fn serve(app: Router) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = l.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let _ = axum::serve(l, app).await;
    });
    port
}

/// Any request: count it and answer with the canary.
async fn canary_http(hits: Hits, canary: String) -> u16 {
    serve(Router::new().fallback(move || {
        let (h, c) = (hits.clone(), canary.clone());
        async move {
            h.hit();
            c.into_response()
        }
    }))
    .await
}

/// Raw TCP server: `mode` = "echo", "canary" (count + send canary), "slow" (HTTP headers, then
/// one body byte every 300 ms) or "hang" (accept, never answer).
async fn tcp_server(mode: &'static str, hits: Hits, canary: String) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = l.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            hits.hit();
            let canary = canary.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                match mode {
                    "echo" => loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    },
                    "canary" => {
                        let _ = s.write_all(canary.as_bytes()).await;
                    }
                    "slow" => {
                        let _ = s.read(&mut buf).await;
                        let _ = s
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
                            .await;
                        for _ in 0..100 {
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            if s.write_all(b"x").await.is_err() {
                                return;
                            }
                        }
                    }
                    _ => {
                        let _ = s.read(&mut buf).await;
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    }
                }
            });
        }
    });
    port
}

struct TestCa {
    pem: String,
    leaf: Vec<u8>,
    key: Vec<u8>,
}

fn test_ca() -> TestCa {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.distinguished_name
        .push(rcgen::DnType::CommonName, "sandboxd E-NET test CA");
    let ca = rcgen::CertifiedIssuer::self_signed(p, ca_key).expect("ca");
    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".into(), "localhost".into()])
        .expect("leaf params")
        .signed_by(&leaf_key, &ca)
        .expect("leaf");
    TestCa {
        pem: ca.pem(),
        leaf: leaf.der().to_vec(),
        key: leaf_key.serialize_der(),
    }
}

/// HTTPS server: `/redir-http` → 302 to the downgrade target `http://127.0.0.1:<g>/api/x`;
/// everything else → `hello`.
async fn https_server(ca: &TestCa, g: u16) -> u16 {
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![ca.leaf.clone().into()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(ca.key.clone().into()),
        )
        .expect("tls config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = l.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = l.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                let mut buf = vec![0u8; 8192];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let req = String::from_utf8_lossy(&got);
                let resp = if req.starts_with("GET /redir-http") {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{g}/api/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".into()
                };
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

// ---------------------------------------------------------------- world

fn policies(dir: &Path, p: &Ports) {
    let base = "version = 1\n[limits]\nwall_clock = \"15s\"\n";
    let common = "max_requests = 100\nmax_response_bytes = \"64KiB\"\nrequest_timeout = \"1s\"\nconnect_timeout = \"1s\"\n";
    let pos_rules = format!(
        "http = [\n  {{ scheme = \"http\", host = \"127.0.0.1\", port = {a}, methods = [\"GET\", \"POST\", \"HEAD\"], path_prefix = \"/api/\" }},\n  {{ host = \"127.0.0.1\", port = {s} }},\n  {{ scheme = \"http\", host = \"127.0.0.1\", port = {g}, path_prefix = \"/api/\" }},\n  {{ scheme = \"http\", host = \"127.0.0.1\", port = {slow} }},\n  {{ scheme = \"http\", host = \"127.0.0.1\", port = {hang} }},\n]\ntcp = [ {{ host = \"127.0.0.1\", port = {t} }} ]\n",
        a = p.a,
        s = p.s,
        g = p.g,
        slow = p.slow,
        hang = p.hang,
        t = p.t
    );
    let w = |name: &str, body: String| {
        std::fs::write(
            dir.join(format!("{name}.toml")),
            format!("name = \"{name}\"\n{base}{body}"),
        )
        .expect("policy");
    };
    w(
        "netpos",
        format!("[env]\nTZ = \"UTC\"\n[network]\nallow_private_ips = true\n{common}{pos_rules}"),
    );
    w(
        "netproxy",
        format!(
            "[env]\nHTTP_PROXY = \"http://127.0.0.1:{f}\"\nHTTPS_PROXY = \"http://127.0.0.1:{f}\"\n[network]\nallow_private_ips = true\n{common}{pos_rules}",
            f = p.f
        ),
    );
    // Default SSRF protection: every rule names a loopback or metadata destination, so every
    // request must be refused by the SSRF layer even though the allowlist matches.
    w(
        "netdef",
        format!(
            "[network]\n{common}http = [\n  {{ scheme = \"http\", host = \"127.0.0.1\", port = {d} }},\n  {{ scheme = \"http\", host = \"localhost\", port = {d} }},\n  {{ scheme = \"http\", host = \"169.254.169.254\", port = 80 }},\n]\ntcp = [ {{ host = \"127.0.0.1\", port = {td} }}, {{ host = \"localhost\", port = {td} }} ]\n",
            d = p.d,
            td = p.td
        ),
    );
    w(
        "netquota",
        format!(
            "[network]\nallow_private_ips = true\nmax_requests = 3\nmax_response_bytes = \"64KiB\"\nhttp = [ {{ scheme = \"http\", host = \"127.0.0.1\", port = {a}, path_prefix = \"/api/\" }} ]\n",
            a = p.a
        ),
    );
    w("nonet", "[env]\nTZ = \"UTC\"\n".into());
}

fn world() -> &'static NetWorld {
    static W: OnceLock<NetWorld> = OnceLock::new();
    W.get_or_init(|| {
        std::thread::spawn(|| {
            sandboxd_net::ensure_crypto_provider();
            let canary = format!("CANARY-NET-{}", uuid::Uuid::new_v4().simple());
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("rt");
            let forbidden = Forbidden::default();
            let ca = test_ca();
            let (p, service, audit) = rt.block_on(async {
                let fb = forbidden.clone();
                let a = serve(
                    Router::new()
                        .route("/api/echo", any(echo))
                        .route("/api/redirect", any(redirect))
                        .route("/api/loop", any(looping))
                        .route("/api/big", any(big))
                        .route("/secret", any(secret))
                        .with_state(AState {
                            canary: canary.clone(),
                            secret: fb.a_secret.clone(),
                        }),
                )
                .await;
                let f = canary_http(fb.f.clone(), canary.clone()).await;
                let d = canary_http(fb.d.clone(), canary.clone()).await;
                let g = canary_http(fb.g.clone(), canary.clone()).await;
                let s = https_server(&ca, g).await;
                let t = tcp_server("echo", Hits::default(), canary.clone()).await;
                let tf = tcp_server("canary", fb.tf.clone(), canary.clone()).await;
                let td = tcp_server("canary", fb.td.clone(), canary.clone()).await;
                let slow = tcp_server("slow", Hits::default(), canary.clone()).await;
                let hang = tcp_server("hang", Hits::default(), canary.clone()).await;
                let p = Ports {
                    a,
                    f,
                    d,
                    g,
                    s,
                    t,
                    tf,
                    td,
                    slow,
                    hang,
                };

                let root = std::env::temp_dir().join("sandboxd-escape-net");
                let _ = std::fs::remove_dir_all(&root);
                let pol = root.join("policies");
                std::fs::create_dir_all(&pol).expect("mkdir");
                policies(&pol, &p);
                let audit = Arc::new(MemorySink::default());
                let broker = Broker::new(BrokerConfig {
                    extra_ca_pem: Some(ca.pem.clone().into_bytes()),
                    ..BrokerConfig::default()
                })
                .expect("broker");
                let cfg = RuntimeConfig {
                    vfs: VfsConfig {
                        cache_dir: std::env::temp_dir()
                            .join("sandboxd-runtime-tests")
                            .join("cache"),
                        work_dir: root.join("work"),
                    },
                    broker: Some(Arc::new(broker)),
                    ..RuntimeConfig::default()
                };
                let (sandbox, _) = Sandbox::new(cfg, audit.clone()).await.expect("sandbox");
                let dir = PolicyDir::load(&pol, &LoadOptions::default()).expect("policies");
                let service = RunService::new(
                    sandbox,
                    dir,
                    audit.clone(),
                    AdmissionConfig {
                        max_concurrent: 8,
                        queue_depth: 64,
                        queue_timeout: Duration::from_secs(120),
                    },
                );
                (p, service, audit)
            });
            NetWorld {
                service,
                audit,
                canary,
                forbidden,
                p,
                _rt: rt,
            }
        })
        .join()
        .expect("world")
    })
}

// ---------------------------------------------------------------- harness

async fn run(policy: &str, lang: ApiLanguage, code: &str) -> RunResult {
    let w = world();
    let code = fill(code, &w.p);
    w.service
        .submit(
            &Principal::local("escape-suite"),
            ApiRunRequest {
                language: lang,
                code,
                policy: Some(policy.into()),
                files: vec![],
                args: vec![],
                stdin: None,
                limits: None,
            },
            None,
        )
        .await
        .expect("service accepted the request")
}

async fn py(policy: &str, code: &str) -> RunResult {
    run(policy, ApiLanguage::Python, &format!("{PY}{code}")).await
}

async fn js(policy: &str, code: &str) -> RunResult {
    run(policy, ApiLanguage::Javascript, &format!("{JS}{code}")).await
}

/// `@A@`-style placeholders → ports.
fn fill(code: &str, p: &Ports) -> String {
    code.replace("@A@", &p.a.to_string())
        .replace("@F@", &p.f.to_string())
        .replace("@D@", &p.d.to_string())
        .replace("@G@", &p.g.to_string())
        .replace("@S@", &p.s.to_string())
        .replace("@T@", &p.t.to_string())
        .replace("@TF@", &p.tf.to_string())
        .replace("@TD@", &p.td.to_string())
        .replace("@SLOW@", &p.slow.to_string())
        .replace("@HANG@", &p.hang.to_string())
        .replace("@Q@", QSECRET)
}

fn out(r: &RunResult) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&r.stdout),
        String::from_utf8_lossy(&r.stderr)
    )
}

/// Python preamble: `attempt(name, fn)` prints `ESCAPED` if `fn` returns, else `blocked <name>
/// <ExceptionType> <code>` (the broker code, also through `URLError.reason`).
const PY: &str = r#"
import os, json, socket, sandbox_net
import urllib.request, urllib.error, http.client
def code_of(e):
    c = getattr(e, "code", None)
    if not isinstance(c, str):
        c = getattr(getattr(e, "reason", None), "code", c)
    return c
def attempt(name, fn):
    try:
        r = fn()
        print("ESCAPED", name, repr(r)[:200])
    except BaseException as e:
        print("blocked", name, type(e).__name__, code_of(e))
"#;

/// JavaScript preamble with the same contract.
const JS: &str = r#"
async function attempt(name, fn) {
  try {
    const r = await fn();
    console.log('ESCAPED', name, String(r).slice(0, 200));
  } catch (e) {
    console.log('blocked', name, e.name, e.cause ? e.cause.code : '');
  }
}
"#;

/// `blocked <name> <Type> <code>` with one of the expected codes.
#[track_caller]
fn expect_blocked(r: &RunResult, name: &str, codes: &[&str]) {
    let text = out(r);
    let line = text
        .lines()
        .find(|l| l.starts_with(&format!("blocked {name} ")))
        .unwrap_or_else(|| panic!("case {name:?} did not report blocked:\n{text}"));
    assert!(
        codes.iter().any(|c| line.ends_with(&format!(" {c}"))),
        "case {name:?}: expected one of {codes:?}, got {line:?}"
    );
}

/// The universal invariants (see module docs).
#[track_caller]
fn assert_contained(r: &RunResult, case: &str) {
    let w = world();
    let text = out(r);
    eprintln!("---- [{case}] guest output\n{text}");
    assert!(
        !text.contains("ESCAPED"),
        "[{case}] attack succeeded:\n{text}"
    );
    assert!(
        !text.contains(&w.canary),
        "[{case}] canary leaked via output:\n{text}"
    );
    let f = &w.forbidden;
    for (name, h) in [
        ("forbidden http server", &f.f),
        ("/secret outside the path prefix", &f.a_secret),
        ("netdef loopback target", &f.d),
        ("downgrade target", &f.g),
        ("forbidden tcp server", &f.tf),
        ("netdef tcp target", &f.td),
    ] {
        assert_eq!(h.get(), 0, "[{case}] {name} was contacted");
    }
    let redactor = Redactor::new();
    for ev in w.audit.events() {
        let line = ev.to_json_line(&redactor);
        assert!(
            !line.contains(&w.canary),
            "[{case}] canary leaked into audit"
        );
        assert!(
            !line.contains(QSECRET),
            "[{case}] query value leaked into audit: {line}"
        );
    }
    assert!(w.service.healthy(), "[{case}] service unhealthy afterwards");
}

fn net_denials(r: &RunResult) -> usize {
    world()
        .audit
        .events()
        .iter()
        .filter(|e| e.run_id == Some(r.run_id))
        .filter(|e| {
            matches!(
                &e.kind,
                EventKind::NetRequest {
                    decision: Decision::Deny,
                    ..
                } | EventKind::NetConnect {
                    decision: Decision::Deny,
                    ..
                }
            )
        })
        .count()
}

// ---------------------------------------------------------------- E-NET-1 allowlist

#[tokio::test(flavor = "multi_thread")]
async fn e_net_1_allowlist_host_port_method_path_scheme() {
    let r = py(
        "netpos",
        r#"
f = sandbox_net.fetch
print("control", f("http://127.0.0.1:@A@/api/echo?token=@Q@").status)
attempt("host", lambda: f("http://localhost:@A@/api/echo"))
attempt("port", lambda: f("http://127.0.0.1:@F@/api/echo"))
attempt("method", lambda: f("http://127.0.0.1:@A@/api/echo", method="DELETE"))
attempt("path", lambda: f("http://127.0.0.1:@A@/secret?token=@Q@"))
attempt("scheme", lambda: f("https://127.0.0.1:@A@/api/echo"))
attempt("file", lambda: f("file:///etc/passwd"))
attempt("userinfo", lambda: f("http://user:pw@127.0.0.1:@A@/api/echo"))
attempt("urllib", lambda: urllib.request.urlopen("http://127.0.0.1:@F@/").read())
def client():
    c = http.client.HTTPConnection("127.0.0.1", @F@)
    c.request("GET", "/")
    return c.getresponse().read()
attempt("http.client", client)
"#,
    )
    .await;
    assert!(out(&r).contains("control 200"), "{}", out(&r));
    for (case, codes) in [
        ("host", &["DENIED"][..]),
        ("port", &["DENIED"]),
        ("method", &["DENIED"]),
        ("path", &["DENIED"]),
        ("scheme", &["DENIED"]),
        ("file", &["DENIED", "PROTOCOL"]),
        ("userinfo", &["DENIED", "PROTOCOL"]),
        ("urllib", &["DENIED"]),
        ("http.client", &["DENIED"]),
    ] {
        expect_blocked(&r, case, codes);
    }
    assert!(net_denials(&r) >= 9, "every denial is audited");
    assert_contained(&r, "E-NET-1");

    let r = js(
        "netpos",
        r#"
await attempt('port', () => fetch('http://127.0.0.1:@F@/'));
await attempt('path', () => fetch('http://127.0.0.1:@A@/secret'));
await attempt('method', () => fetch('http://127.0.0.1:@A@/api/echo', { method: 'PUT', body: 'x' }));
await attempt('host', () => fetch('http://localhost:@A@/api/echo'));
"#,
    )
    .await;
    for case in ["port", "path", "method", "host"] {
        expect_blocked(&r, case, &["DENIED"]);
    }
    assert_contained(&r, "E-NET-1/js");
}

// ---------------------------------------------------------------- E-NET-2 URL traversal

#[tokio::test(flavor = "multi_thread")]
async fn e_net_2_path_traversal_in_urls() {
    let r = py(
        "netpos",
        r#"
base = "http://127.0.0.1:@A@"
for i, p in enumerate(["/api/../secret", "/api/%2e%2e/secret", "/api/%2E%2E/secret", "/api/./../secret",
                       "/api/..%2fsecret", "/api/%2e%2e%2fsecret", "/api/..%5csecret", "/api\\..\\secret",
                       "//api/../secret", "/API/../secret", "/api/%252e%252e/secret"]):
    attempt("t%d" % i, lambda p=p: sandbox_net.fetch(base + p).status)
def raw_client():
    c = http.client.HTTPConnection("127.0.0.1", @A@)
    c.request("GET", "/api/../secret")
    return c.getresponse().status
attempt("http.client", raw_client)
"#,
    )
    .await;
    // Every variant is either refused, or normalized to a path *inside* /api/ (then the server
    // answers 404, which `attempt` reports as ESCAPED only if it is the canary route: /secret is
    // never reached, which the a_secret counter proves).
    let text = out(&r);
    for line in text.lines().filter(|l| l.starts_with("ESCAPED")) {
        assert!(
            line.ends_with(" 404"),
            "a traversal variant reached something other than a 404 under /api/: {line}\n{text}"
        );
    }
    assert_contained_ignoring_404s(&r, "E-NET-2");
}

/// E-NET-2 variant of `assert_contained`: "ESCAPED … 404" lines are normalized-in-prefix
/// requests that reached a 404 under `/api/`, not escapes.
#[track_caller]
fn assert_contained_ignoring_404s(r: &RunResult, case: &str) {
    let mut r2 = r.clone();
    let filtered: String = String::from_utf8_lossy(&r.stdout)
        .lines()
        .filter(|l| !(l.starts_with("ESCAPED") && l.ends_with(" 404")))
        .map(|l| format!("{l}\n"))
        .collect();
    r2.stdout = filtered.into_bytes();
    assert_contained(&r2, case);
}

// ---------------------------------------------------------------- E-NET-3 SSRF

#[tokio::test(flavor = "multi_thread")]
async fn e_net_3_ssrf_ip_literals_metadata_and_dns() {
    let r = py(
        "netdef",
        r#"
f = sandbox_net.fetch
for name, url in [("loopback", "http://127.0.0.1:@D@/"), ("decimal", "http://2130706433:@D@/"),
                  ("hex", "http://0x7f.1:@D@/"), ("octal", "http://0177.0.0.1:@D@/"),
                  ("mapped-v6", "http://[::ffff:127.0.0.1]:@D@/"), ("v6-loopback", "http://[::1]:@D@/"),
                  ("dns-localhost", "http://localhost:@D@/"), ("metadata", "http://169.254.169.254/latest/meta-data/"),
                  ("metadata-decimal", "http://2852039166/latest/meta-data/"), ("zero", "http://0.0.0.0:@D@/")]:
    attempt(name, lambda url=url: f(url).status)
attempt("tcp-loopback", lambda: socket.create_connection(("127.0.0.1", @TD@)).recv(100))
attempt("tcp-dns-localhost", lambda: sandbox_net.connect("localhost", @TD@).recv(100))
"#,
    )
    .await;
    for case in [
        "loopback",
        "decimal",
        "hex",
        "octal",
        "dns-localhost",
        "metadata",
        "metadata-decimal",
    ] {
        expect_blocked(&r, case, &["SSRF"]);
    }
    // No rule names these exact forms; either layer may refuse them.
    for case in ["mapped-v6", "v6-loopback", "zero"] {
        expect_blocked(&r, case, &["SSRF", "DENIED"]);
    }
    expect_blocked(&r, "tcp-loopback", &["DENIED"]);
    expect_blocked(&r, "tcp-dns-localhost", &["DENIED"]);
    assert_contained(&r, "E-NET-3");

    let r = js(
        "netdef",
        r#"
for (const [n, u] of [['loopback', 'http://127.0.0.1:@D@/'], ['decimal', 'http://2130706433:@D@/'], ['dns', 'http://localhost:@D@/']]) {
  await attempt(n, () => fetch(u));
}
"#,
    )
    .await;
    for case in ["loopback", "decimal", "dns"] {
        expect_blocked(&r, case, &["SSRF"]);
    }
    assert_contained(&r, "E-NET-3/js");
}

// ---------------------------------------------------------------- E-NET-4 redirects

#[tokio::test(flavor = "multi_thread")]
async fn e_net_4_redirects_are_rechecked() {
    let r = py(
        "netpos",
        r#"
f = sandbox_net.fetch
r = "http://127.0.0.1:@A@/api/redirect?to="
attempt("other-port", lambda: f(r + "http://127.0.0.1:@F@/x"))
attempt("outside-prefix", lambda: f(r + "/secret"))
attempt("other-host", lambda: f(r + "http://localhost:@A@/api/echo"))
attempt("metadata", lambda: f(r + "http://169.254.169.254/latest/meta-data/"))
attempt("file", lambda: f(r + "file:///etc/passwd"))
attempt("loop", lambda: f("http://127.0.0.1:@A@/api/loop"))
attempt("urllib", lambda: urllib.request.urlopen(r + "http://127.0.0.1:@F@/").read())
attempt("downgrade", lambda: f("https://127.0.0.1:@S@/redir-http").status)
print("https-ok", f("https://127.0.0.1:@S@/").text())
"#,
    )
    .await;
    for case in ["other-port", "outside-prefix", "other-host", "urllib"] {
        expect_blocked(&r, case, &["DENIED"]);
    }
    expect_blocked(&r, "metadata", &["DENIED", "SSRF"]);
    expect_blocked(&r, "file", &["DENIED", "PROTOCOL"]);
    expect_blocked(&r, "loop", &["TOO_MANY_REDIRECTS"]);
    expect_blocked(&r, "downgrade", &["DENIED"]);
    assert!(out(&r).contains("https-ok hello"), "{}", out(&r));
    assert_contained(&r, "E-NET-4");
}

// ---------------------------------------------------------------- E-NET-5 headers

#[tokio::test(flavor = "multi_thread")]
async fn e_net_5_header_injection_and_host_spoofing() {
    let r = py(
        "netpos",
        r#"
f = sandbox_net.fetch
u = "http://127.0.0.1:@A@/api/echo"
attempt("crlf-value", lambda: f(u, headers={"X-A": "v\r\nX-Injected: 1"}))
attempt("crlf-name", lambda: f(u, headers={"X-A\r\nX-Injected": "1"}))
attempt("nul", lambda: f(u, headers={"X-A": "v\x00w"}))
attempt("method-injection", lambda: f(u, method="GET /secret HTTP/1.1\r\nX:"))
def client_crlf():
    c = http.client.HTTPConnection("127.0.0.1", @A@)
    c.putrequest("GET", "/api/echo")
    c.putheader("X-A", "v\r\nX-Injected: 1")
    c.endheaders()
    return c.getresponse().read()
attempt("http.client", client_crlf)
# Spoofing / smuggling attempts that the broker neutralizes: the request succeeds, but the
# server sees broker-controlled values.
j = f(u, method="POST", body=b"hello", headers={
    "Host": "evil.example", "Content-Length": "0", "Transfer-Encoding": "chunked",
    "Connection": "X-Secret", "X-Secret": "s", "Proxy-Authorization": "Basic Zm9vOmJhcg=="}).json()
h = j["headers"]
print("host", h.get("host"))
print("body", j["body"])
print("te", h.get("transfer-encoding"), "pa", h.get("proxy-authorization"), "xs", h.get("x-secret"))
"#,
    )
    .await;
    for case in ["crlf-value", "crlf-name", "nul"] {
        expect_blocked(&r, case, &["PROTOCOL"]);
    }
    // The allowlist's method check or the broker's method validation, whichever comes first.
    expect_blocked(&r, "method-injection", &["DENIED", "PROTOCOL"]);
    // http.client refuses CRLF itself (ValueError) before anything is sent.
    let text = out(&r);
    assert!(text.contains("blocked http.client ValueError"), "{text}");
    let a = world().p.a;
    assert!(
        text.contains(&format!("host 127.0.0.1:{a}")),
        "Host spoofed:\n{text}"
    );
    assert!(text.contains("body hello"), "body smuggled:\n{text}");
    assert!(
        text.contains("te None pa None xs None"),
        "hop-by-hop headers passed:\n{text}"
    );
    assert!(!text.contains("X-Injected") && !text.contains("x-injected"));
    assert_contained(&r, "E-NET-5");

    let r = js(
        "netpos",
        r#"
await attempt('crlf', () => fetch('http://127.0.0.1:@A@/api/echo', { headers: { 'X-A': 'v\r\nX-Injected: 1' } }));
await attempt('name', () => new Headers({ 'Bad Name': 'x' }));
const j = await (await fetch('http://127.0.0.1:@A@/api/echo', { headers: { Host: 'evil.example' } })).json();
console.log('host', j.headers.host);
"#,
    )
    .await;
    expect_blocked(&r, "crlf", &[""]); // Headers() rejects before any request (TypeError)
    expect_blocked(&r, "name", &[""]);
    assert!(
        out(&r).contains(&format!("host 127.0.0.1:{a}")),
        "{}",
        out(&r)
    );
    assert_contained(&r, "E-NET-5/js");
}

// ---------------------------------------------------------------- E-NET-6 quotas and timeouts

#[tokio::test(flavor = "multi_thread")]
async fn e_net_6_quotas_slowloris_and_hangs() {
    let r = py(
        "netquota",
        r#"
f = sandbox_net.fetch
attempt("too-large", lambda: f("http://127.0.0.1:@A@/api/big").status)
print("second", f("http://127.0.0.1:@A@/api/echo").status)
print("third", f("http://127.0.0.1:@A@/api/echo").status)
attempt("fourth", lambda: f("http://127.0.0.1:@A@/api/echo").status)
"#,
    )
    .await;
    expect_blocked(&r, "too-large", &["RESPONSE_TOO_LARGE"]);
    expect_blocked(&r, "fourth", &["QUOTA"]);
    assert!(
        r.limits_hit.contains(&LimitKind::Network),
        "{:?}",
        r.limits_hit
    );
    assert_eq!(r.outcome, Outcome::Limit);
    assert_contained(&r, "E-NET-6/quota");

    let r = py(
        "netpos",
        r#"
import time
for name, port in [("slowloris", @SLOW@), ("hang", @HANG@)]:
    t = time.monotonic()
    attempt(name, lambda port=port: sandbox_net.fetch("http://127.0.0.1:%d/" % port).status)
    print(name, "bounded", time.monotonic() - t < 3.0)
"#,
    )
    .await;
    expect_blocked(&r, "slowloris", &["TIMEOUT"]);
    expect_blocked(&r, "hang", &["TIMEOUT"]);
    let text = out(&r);
    assert!(
        text.contains("slowloris bounded True") && text.contains("hang bounded True"),
        "{text}"
    );
    assert_contained(&r, "E-NET-6/timeouts");
}

// ---------------------------------------------------------------- E-NET-7 raw TCP

#[tokio::test(flavor = "multi_thread")]
async fn e_net_7_tcp_only_to_listed_destinations() {
    let r = py(
        "netpos",
        r#"
s = socket.create_connection(("127.0.0.1", @T@))
s.sendall(b"ping"); print("control", s.recv(10)); s.close()
attempt("port", lambda: socket.create_connection(("127.0.0.1", @TF@)).recv(100))
attempt("host", lambda: sandbox_net.connect("localhost", @T@).recv(100))
attempt("device-path", lambda: os.read(os.open("/dev/sandbox/tcp/127.0.0.1:@TF@", os.O_RDWR), 100))
attempt("device-dotdot", lambda: os.read(os.open("/dev/sandbox/tcp/127.0.0.1:@T@/../127.0.0.1:@TF@", os.O_RDWR), 100))
attempt("device-garbage", lambda: os.open("/dev/sandbox/tcp/;rm -rf /", os.O_RDWR))
attempt("device-unknown", lambda: os.open("/dev/sandbox/udp/127.0.0.1:53", os.O_RDWR))
"#,
    )
    .await;
    assert!(out(&r).contains("control b'ping'"), "{}", out(&r));
    expect_blocked(&r, "port", &["DENIED"]);
    expect_blocked(&r, "host", &["DENIED"]);
    for case in [
        "device-path",
        "device-dotdot",
        "device-garbage",
        "device-unknown",
    ] {
        expect_blocked(&r, case, &["None"]); // PermissionError / FileNotFoundError from the device layer
    }
    assert_contained(&r, "E-NET-7");
}

// ---------------------------------------------------------------- E-NET-8 proxies

#[tokio::test(flavor = "multi_thread")]
async fn e_net_8_guest_cannot_use_a_proxy() {
    // The policy env sets http(s)_proxy to the forbidden server: urllib would send absolute-form
    // requests / CONNECT through it. The shim refuses both; the forbidden server stays at 0 hits.
    let r = py(
        "netproxy",
        r#"
attempt("env-http-proxy", lambda: urllib.request.urlopen("http://127.0.0.1:@A@/api/echo").read())
attempt("env-https-proxy", lambda: urllib.request.urlopen("https://127.0.0.1:@S@/").read())
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": "http://127.0.0.1:@A@"}))
attempt("proxyhandler", lambda: opener.open("http://example.com/").read())
def tunnel():
    c = http.client.HTTPConnection("127.0.0.1", @A@)
    c.set_tunnel("example.com", 443)
    c.request("GET", "/")
    return c.getresponse().read()
attempt("set_tunnel", tunnel)
def absolute_form():
    c = http.client.HTTPConnection("127.0.0.1", @A@)
    c.request("GET", "http://127.0.0.1:@F@/")
    return c.getresponse().read()
attempt("absolute-form", absolute_form)
"#,
    )
    .await;
    for case in [
        "env-http-proxy",
        "env-https-proxy",
        "proxyhandler",
        "set_tunnel",
        "absolute-form",
    ] {
        expect_blocked(&r, case, &["DENIED"]);
    }
    assert_contained(&r, "E-NET-8");
}

// ---------------------------------------------------------------- E-NET-9 device protocol abuse

#[tokio::test(flavor = "multi_thread")]
async fn e_net_9_raw_device_frames_and_shim_tampering() {
    let r = py(
        "netpos",
        r#"
def raw(frame):
    fd = os.open("/dev/sandbox/http", os.O_RDWR)
    try:
        os.write(fd, frame)
        data = b""
        while True:
            c = os.read(fd, 65536)
            if not c:
                break
            data += c
    finally:
        os.close(fd)
    n = int.from_bytes(data[:4], "little")
    meta = json.loads(data[4:4 + n])
    if meta.get("error"):
        e = OSError(meta["error"]["message"]); e.code = meta["error"]["code"]; raise e
    return meta["status"], data[4 + n:]
def frame(h, body=b""):
    b = json.dumps(h).encode()
    return len(b).to_bytes(4, "little") + b + body
base = {"method": "GET", "headers": [], "body_len": 0}
attempt("forbidden-url", lambda: raw(frame(dict(base, url="http://127.0.0.1:@F@/"))))
attempt("unknown-field", lambda: raw(frame(dict(base, url="http://127.0.0.1:@A@/api/echo", proxy="http://127.0.0.1:@F@"))))
attempt("header-crlf", lambda: raw(frame(dict(base, url="http://127.0.0.1:@A@/api/echo", headers=[["X", "a\r\nB: c"]]))))
attempt("huge-header-len", lambda: raw((0xFFFFFFFF).to_bytes(4, "little") + b"{}"))
attempt("garbage", lambda: raw(b"\x05\x00\x00\x00hello"))
attempt("body-len-lie", lambda: raw(frame(dict(base, method="POST", url="http://127.0.0.1:@F@/", body_len=3), b"abcdef")))
attempt("read-before-write", lambda: os.read(os.open("/dev/sandbox/http", os.O_RDWR), 10))
# Tampering with the guest-side shim changes nothing: enforcement is on the host.
sandbox_net._not_allowed = lambda kind: None
http.client.HTTPConnection.set_tunnel = lambda *a, **k: None
attempt("patched-shim", lambda: sandbox_net.fetch("http://127.0.0.1:@F@/").status)
"#,
    )
    .await;
    expect_blocked(&r, "forbidden-url", &["DENIED"]);
    for case in ["unknown-field", "header-crlf", "huge-header-len", "garbage"] {
        expect_blocked(&r, case, &["PROTOCOL"]);
    }
    expect_blocked(&r, "body-len-lie", &["DENIED", "PROTOCOL"]);
    expect_blocked(&r, "read-before-write", &["None"]); // EINVAL
    expect_blocked(&r, "patched-shim", &["DENIED"]);
    assert_contained(&r, "E-NET-9");
}

// ---------------------------------------------------------------- E-NET-10 no grants

#[tokio::test(flavor = "multi_thread")]
async fn e_net_10_no_grant_means_no_network() {
    let r = py(
        "nonet",
        r#"
attempt("fetch", lambda: sandbox_net.fetch("http://127.0.0.1:@F@/"))
attempt("urllib", lambda: urllib.request.urlopen("http://127.0.0.1:@F@/").read())
attempt("socket", lambda: socket.create_connection(("127.0.0.1", @TF@)).recv(10))
attempt("device", lambda: os.open("/dev/sandbox/http", os.O_RDWR))
attempt("tcp-device", lambda: os.open("/dev/sandbox/tcp/127.0.0.1:@TF@", os.O_RDWR))
"#,
    )
    .await;
    for case in ["fetch", "urllib", "socket"] {
        expect_blocked(&r, case, &["NETWORK_DISABLED"]);
    }
    expect_blocked(&r, "device", &["None"]);
    expect_blocked(&r, "tcp-device", &["None"]);
    assert!(
        out(&r).contains("not allowed by policy 'nonet'") || out(&r).contains("NETWORK_DISABLED"),
        "{}",
        out(&r)
    );
    assert_contained(&r, "E-NET-10");

    let r = js(
        "nonet",
        "await attempt('fetch', () => fetch('http://127.0.0.1:@F@/'));",
    )
    .await;
    expect_blocked(&r, "fetch", &["NETWORK_DISABLED"]);
    assert_contained(&r, "E-NET-10/js");
}

// ---------------------------------------------------------------- E-NET-11 isolation between runs

#[tokio::test(flavor = "multi_thread")]
async fn e_net_11_concurrent_hostile_network_runs_stay_isolated() {
    // Many concurrent runs mixing allowed traffic and attacks: per-run clients and quotas
    // (ADR-C2-5, T18) mean no run's grants or connections leak into another's.
    let mut handles = Vec::new();
    for i in 0..12 {
        let (policy, code) = match i % 3 {
            0 => (
                "netpos",
                "print('ok', sandbox_net.fetch('http://127.0.0.1:@A@/api/echo').status)\nattempt('port', lambda: sandbox_net.fetch('http://127.0.0.1:@F@/'))",
            ),
            1 => (
                "netdef",
                "attempt('ssrf', lambda: sandbox_net.fetch('http://127.0.0.1:@D@/'))",
            ),
            _ => (
                "nonet",
                "attempt('none', lambda: sandbox_net.fetch('http://127.0.0.1:@A@/api/echo'))",
            ),
        };
        handles.push(tokio::spawn(async move { (i, py(policy, code).await) }));
    }
    for h in handles {
        let (i, r) = h.await.expect("join");
        match i % 3 {
            0 => {
                assert!(out(&r).contains("ok 200"), "{}", out(&r));
                expect_blocked(&r, "port", &["DENIED"]);
            }
            1 => expect_blocked(&r, "ssrf", &["SSRF"]),
            _ => expect_blocked(&r, "none", &["NETWORK_DISABLED"]),
        }
        assert_contained(&r, "E-NET-11");
    }
}
