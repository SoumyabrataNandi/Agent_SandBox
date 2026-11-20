//! Cycle 3 escape cases (C3-U6; NFR-P2, threat model T19–T23): pooled-instance remnants, session
//! hijacking and probing, leakage between sessions, the session device, snapshot tampering and host
//! data baked into snapshots. Black-box: the HTTP router and the public runtime API only.
//!
//! Every case plants a fresh canary and fails if another run, session or principal can see it.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use sandboxd_audit::{EventKind, MemorySink};
use sandboxd_policy::{LoadOptions, Policy, PolicyDir};
use sandboxd_runtime::{Language, RunRequest, RuntimeConfig, Sandbox, SnapshotMode};
use sandboxd_server::{
    AdmissionConfig, RunService, TokenSet, hash_token,
    http::{AppState, router},
};
use sandboxd_vfs::VfsConfig;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const ALICE: &str = "sbx_cycle3_alice_token_0123456789abcdef";
const BOB: &str = "sbx_cycle3_bob_token_0123456789abcdef00";

struct World {
    service: RunService,
    audit: Arc<MemorySink>,
    root: PathBuf,
    cache: PathBuf,
}

/// Snapshots and pooling on (the production defaults, forced so a fallback can't hide a case).
fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        std::thread::spawn(|| {
            let root = std::env::temp_dir().join("sandboxd-escape-cycle3");
            let _ = std::fs::remove_dir_all(&root);
            let policies = root.join("policies");
            std::fs::create_dir_all(&policies).expect("mkdir");
            std::fs::write(
                policies.join("nb.toml"),
                "version = 1\nname = \"nb\"\n[limits]\nwall_clock = \"3s\"\nmemory = \"256MiB\"\n[session]\nenabled = true\nmax_sessions = 16\n",
            )
            .expect("policy");
            let rt = tokio::runtime::Runtime::new().expect("rt");
            let audit = Arc::new(MemorySink::default());
            let cache = std::env::temp_dir().join("sandboxd-runtime-tests").join("cache");
            let cfg = RuntimeConfig {
                vfs: VfsConfig { cache_dir: cache.clone(), work_dir: root.join("work") },
                snapshots: SnapshotMode::On,
                pool_slots: 24,
                ..RuntimeConfig::default()
            };
            let (sandbox, rep) = rt.block_on(Sandbox::new(cfg, audit.clone())).expect("sandbox");
            assert!(rep.snapshot_python && rep.snapshot_javascript, "{rep:?}");
            let dir = PolicyDir::load(&policies, &LoadOptions::default()).expect("policies");
            let admission = AdmissionConfig {
                max_concurrent: 8,
                queue_depth: 64,
                queue_timeout: Duration::from_secs(60),
                max_sessions: 16,
            };
            let service = RunService::new(sandbox, dir, audit.clone(), admission);
            World { service, audit, root, cache }
        })
        .join()
        .expect("world")
    })
}

fn app() -> axum::Router {
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
            service: world().service.clone(),
            tokens: Arc::new(tokens),
            metrics_public: false,
        },
        2 << 20,
    )
}

async fn call(method: &str, uri: &str, token: &str, body: Option<Value>) -> (StatusCode, Value) {
    let b = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json");
    let req = b
        .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
        .expect("req");
    let resp = app().oneshot(req).await.expect("resp");
    let s = resp.status();
    let bytes = to_bytes(resp.into_body(), 8 << 20).await.expect("body");
    (s, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn open(token: &str, lang: &str) -> String {
    let (s, v) = call(
        "POST",
        "/v1/sessions",
        token,
        Some(json!({"language": lang, "policy": "nb"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    v["session_id"].as_str().expect("id").to_string()
}

async fn cell(token: &str, id: &str, code: &str) -> (StatusCode, Value) {
    call(
        "POST",
        &format!("/v1/sessions/{id}/runs"),
        token,
        Some(json!({"code": code})),
    )
    .await
}

async fn run(token: &str, lang: &str, code: &str) -> Value {
    let (s, v) = call(
        "POST",
        "/v1/runs",
        token,
        Some(json!({"language": lang, "code": code, "policy": "nb"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

fn text(v: &Value) -> String {
    format!(
        "{}{}",
        v["stdout"].as_str().unwrap_or(""),
        v["stderr"].as_str().unwrap_or("")
    )
}

fn canary() -> String {
    format!("CANARY{}", uuid::Uuid::new_v4().simple())
}

/// Python probe: looks for `needle` in everything a fresh interpreter can reach. The needle is
/// embedded reversed, and the probe skips its own copy, so it never finds itself.
fn py_probe(needle: &str) -> String {
    let rev: String = needle.chars().rev().collect();
    format!(
        r#"
import gc, os, sys
needle = {rev:?}[::-1]
hits = []
def scan(o, where):
    try:
        if o is needle:
            return
        if isinstance(o, str):
            if needle in o: hits.append(where)
        elif isinstance(o, (bytes, bytearray)):
            if needle.encode() in o: hits.append(where)
    except Exception:
        pass
for name, v in list(globals().items()):
    scan(name, "globals-key"); scan(v, "globals")
for m in list(sys.modules): scan(m, "sys.modules")
for o in gc.get_objects():
    if isinstance(o, dict):
        for k, v in list(o.items()): scan(k, "dict-key"); scan(v, "dict")
    elif isinstance(o, (list, tuple, set, frozenset)):
        for v in list(o): scan(v, "seq")
for d in ("/", "/tmp", "/work", "/out", "/in", "/code"):
    try:
        for root, dirs, files in os.walk(d):
            for f in files:
                p = os.path.join(root, f)
                scan(p, "path")
                try:
                    with open(p, "rb") as fh: scan(fh.read(1 << 20), "file " + p)
                except Exception: pass
    except Exception:
        pass
print("ESCAPED" if hits else "clean", sorted(set(hits))[:5])
"#
    )
}

fn js_probe(needle: &str) -> String {
    let rev: String = needle.chars().rev().collect();
    format!(
        r#"
const needle = [...{rev:?}].reverse().join("");
const hits = [];
for (const k of Object.getOwnPropertyNames(globalThis)) {{
  let v; try {{ v = globalThis[k]; }} catch (e) {{ continue; }}
  if (k.includes(needle)) hits.push("key " + k);
  if (typeof v === "string" && v.includes(needle)) hits.push("value " + k);
}}
console.log(hits.length ? "ESCAPED " + hits.join(",") : "clean");
"#
    )
}

fn assert_clean(v: &Value, case: &str) {
    let t = text(v);
    assert!(
        t.contains("clean") && !t.contains("ESCAPED"),
        "[{case}] {t}"
    );
}

// ---------------- E-POOL-1 (T19): nothing survives a pooled run ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_pool_1_no_remnants_between_pooled_runs() {
    // Interleave planting and probing runs so every pool slot is reused many times, concurrently.
    for round in 0..4 {
        let c = canary();
        let plant_py = format!(
            "import os\nsecret = {c:?}\nkeep = [secret * 64 for _ in range(256)]\nbuf = bytearray(secret.encode() * 4096)\nos.environ['LEAK'] = secret\nopen('/out/leak.txt', 'w').write(secret)\nimport sys\nsys.modules['leak_' + secret] = sys\nprint('planted')\n"
        );
        let plant_js = format!(
            "globalThis.leak = {c:?}; globalThis[{c:?}] = 1; var big = {c:?}.repeat(100000); console.log('planted');"
        );
        let mut tasks = Vec::new();
        for i in 0..8 {
            let (pp, pj, probe_py, probe_js) = (
                plant_py.clone(),
                plant_js.clone(),
                py_probe(&c),
                js_probe(&c),
            );
            tasks.push(tokio::spawn(async move {
                if i % 2 == 0 {
                    assert!(text(&run(ALICE, "python", &pp).await).contains("planted"));
                    assert!(text(&run(ALICE, "javascript", &pj).await).contains("planted"));
                }
                assert_clean(
                    &run(BOB, "python", &probe_py).await,
                    &format!("E-POOL-1 py r{round} t{i}"),
                );
                assert_clean(
                    &run(BOB, "javascript", &probe_js).await,
                    &format!("E-POOL-1 js r{round} t{i}"),
                );
            }));
        }
        for t in tasks {
            t.await.expect("task");
        }
    }
    assert!(world().service.healthy());
}

// ---------------- E-SES-1 (T20): sessions belong to their principal ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_ses_1_other_principals_and_guessed_ids_get_not_found() {
    let id = open(ALICE, "python").await;
    assert!(id.starts_with("ses_") && id.len() == 36, "{id}");
    let (s, _) = cell(ALICE, &id, "x = 41").await;
    assert_eq!(s, StatusCode::OK);

    // Bob's view of Alice's session is exactly the view of a session that doesn't exist.
    let unknown = format!("ses_{}", uuid::Uuid::new_v4().simple());
    let (s1, v1) = cell(BOB, &id, "print('ESCAPED', x)").await;
    let (s2, v2) = cell(BOB, &unknown, "print('ESCAPED', x)").await;
    assert_eq!((s1, s2), (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND));
    assert_eq!(v1, v2, "responses must not reveal that the session exists");
    assert_eq!(
        call("GET", &format!("/v1/sessions/{id}"), BOB, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call("DELETE", &format!("/v1/sessions/{id}"), BOB, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (s, v) = call(
        "POST",
        "/v1/runs",
        BOB,
        Some(json!({"language": "python", "code": "print('ESCAPED', x)", "session_id": id})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");

    // Bob's attempts didn't touch it: Alice's state is intact.
    let (s, v) = cell(ALICE, &id, "x += 1\nprint(x)").await;
    assert_eq!(
        (s, v["stdout"].as_str()),
        (StatusCode::OK, Some("42\n")),
        "{v}"
    );

    // Malformed and hostile ids: never a server error, never someone's session.
    for bad in [
        "ses_".to_string(),
        "ses_00000000000000000000000000000000".into(),
        id.to_uppercase(),
        format!("{id}%00"),
        format!("{id}/../{id}"),
        "..%2f..%2fv1%2fruns".into(),
        format!("ses_{}", "a".repeat(8192)),
    ] {
        let (s, _) = cell(ALICE, &bad, "print('ESCAPED')").await;
        assert!(
            s == StatusCode::NOT_FOUND
                || s == StatusCode::BAD_REQUEST
                || s == StatusCode::URI_TOO_LONG,
            "{bad:.80} → {s}"
        );
    }

    // Probes are audited under the prober's name.
    let denials = world()
        .audit
        .events()
        .into_iter()
        .filter(|e| e.principal.as_deref() == Some("bob"))
        .filter(|e| matches!(&e.kind, EventKind::PolicyDenied { what, requested } if what.contains("another principal") && requested.as_deref() == Some(id.as_str())))
        .count();
    assert!(denials >= 4, "bob's probes audited: {denials}");
    assert_eq!(
        call("DELETE", &format!("/v1/sessions/{id}"), ALICE, None)
            .await
            .0,
        StatusCode::OK
    );
}

// ---------------- E-SES-2 (T19/T20): no leakage between sessions ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_ses_2_sessions_do_not_share_state() {
    let c = canary();
    let a = open(ALICE, "python").await;
    let plant = format!(
        "import os, sys\nsecret = {c:?}\nopen('/work/secret.txt', 'w').write(secret)\nos.environ['LEAK'] = secret\nsys.modules['leak_' + secret] = sys\nkeep = [secret * 64 for _ in range(256)]\nprint('planted')\n"
    );
    let (s, v) = cell(ALICE, &a, &plant).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(text(&v).contains("planted"), "{v}");

    // Another live session of the same principal and policy, and a plain run.
    let b = open(ALICE, "python").await;
    let (_, v) = cell(ALICE, &b, &py_probe(&c)).await;
    assert_clean(&v, "E-SES-2 live sibling");
    assert_clean(
        &run(ALICE, "python", &py_probe(&c)).await,
        "E-SES-2 plain run",
    );

    // The planting session still has its state, and the probe finds it there (positive control:
    // a probe that can't see a planted canary would pass every case above).
    let (_, v) = cell(
        ALICE,
        &a,
        "print(open('/work/secret.txt').read() == secret)",
    )
    .await;
    assert_eq!(v["stdout"].as_str(), Some("True\n"), "{v}");
    let (_, v) = cell(ALICE, &a, &py_probe(&c)).await;
    assert!(
        text(&v).contains("ESCAPED"),
        "control probe must see its own session's canary: {v}"
    );

    // After it ends, sessions that likely reuse its pool slot and /work see nothing.
    assert_eq!(
        call("DELETE", &format!("/v1/sessions/{a}"), ALICE, None)
            .await
            .0,
        StatusCode::OK
    );
    for _ in 0..3 {
        let n = open(ALICE, "python").await;
        let (_, v) = cell(ALICE, &n, &py_probe(&c)).await;
        assert_clean(&v, "E-SES-2 after close");
        call("DELETE", &format!("/v1/sessions/{n}"), ALICE, None).await;
    }
    // Nothing of the closed session remains on the host either.
    let leftovers: Vec<_> = walk(&world().root.join("work"))
        .into_iter()
        .filter(|p| std::fs::read(p).is_ok_and(|b| String::from_utf8_lossy(&b).contains(&c)))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // JavaScript globals.
    let j1 = open(ALICE, "javascript").await;
    let (_, v) = cell(
        ALICE,
        &j1,
        &format!("var leak = {c:?}; globalThis[{c:?}] = 1; console.log('planted')"),
    )
    .await;
    assert!(text(&v).contains("planted"), "{v}");
    let j2 = open(ALICE, "javascript").await;
    let (_, v) = cell(ALICE, &j2, &js_probe(&c)).await;
    assert_clean(&v, "E-SES-2 js");
    for id in [b, j1, j2] {
        call("DELETE", &format!("/v1/sessions/{id}"), ALICE, None).await;
    }
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

// ---------------- E-SES-3 (T23): the session channel is not a capability ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_ses_3_the_session_device_cannot_be_reopened_or_abused() {
    let id = open(ALICE, "python").await;
    let (_, v) = cell(
        ALICE,
        &id,
        "import os\ntry:\n    fd = os.open('/dev/sandbox/session', os.O_RDWR)\n    print('ESCAPED reopened', fd)\nexcept OSError as e:\n    print('blocked', type(e).__name__)\n",
    )
    .await;
    assert!(
        text(&v).contains("blocked") && !text(&v).contains("ESCAPED"),
        "{v}"
    );

    // Forge "call finished" on every plausible fd, then spin: whether or not a forgery lands, the
    // session must end on a limit quickly instead of computing unbudgeted.
    let t = Instant::now();
    let (s, v) = cell(
        ALICE,
        &id,
        "import os\nfor fd in range(3, 64):\n    try:\n        os.write(fd, b'{\"status\":\"done\",\"exit_code\":0}\\n')\n    except OSError:\n        pass\nwhile True:\n    pass\n",
    )
    .await;
    assert!(s == StatusCode::OK || s == StatusCode::NOT_FOUND, "{s} {v}");
    let mut state = Value::Null;
    while t.elapsed() < Duration::from_secs(10) {
        let (s, v) = call("GET", &format!("/v1/sessions/{id}"), ALICE, None).await;
        if s == StatusCode::NOT_FOUND || v["state"] == "ended" {
            state = v;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        t.elapsed() < Duration::from_secs(10),
        "session still computing after forging: {state}"
    );
    let (s, _) = cell(ALICE, &id, "print('ESCAPED still running')").await;
    assert_eq!(s, StatusCode::NOT_FOUND, "an ended session takes no calls");
    let ended = world().audit.events().into_iter().any(|e| {
        matches!(&e.kind, EventKind::SessionEnd { reason, .. } if reason == "limit")
            && e.session_id.as_deref() == Some(id.as_str())
    });
    assert!(ended, "session.end{{reason=limit}} audited");
    assert!(world().service.healthy());
}

// ---------------- E-SNAP-1 (T21): tampered snapshots are rebuilt, never loaded ----------------

#[test]
fn e_snap_1_tampered_snapshot_cache_is_rebuilt() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let dir = std::env::temp_dir().join(format!("sandboxd-escape-snap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = || RuntimeConfig {
            vfs: VfsConfig::under(&dir),
            snapshots: SnapshotMode::On,
            precompile_stdlib: false,
            ..RuntimeConfig::default()
        };
        let audit = || Arc::new(MemorySink::default()) as Arc<dyn sandboxd_audit::AuditSink>;
        drop(rt.block_on(Sandbox::new(cfg(), audit())).expect("first"));
        let modules = dir.join("cache").join("modules");
        let find = |prefix: &str| {
            std::fs::read_dir(&modules)
                .expect("modules")
                .filter_map(Result::ok)
                .map(|e| e.path())
                .find(|p| {
                    p.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with(prefix))
                        && p.extension().is_some_and(|x| x == "cwasm")
                })
                .unwrap_or_else(|| panic!("{prefix} cwasm"))
        };
        let snap_py = find("snapshot-python-");
        let snap_js = find("snapshot-javascript-");
        let good_py = std::fs::read(&snap_py).expect("read");
        // 1. A flipped byte. 2. A different, valid module swapped in (the upstream interpreter).
        let mut flipped = good_py.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 0x5a;
        std::fs::write(&snap_py, flipped).expect("tamper py");
        std::fs::copy(find("quickjs-"), &snap_js).expect("swap js");

        let (sb, rep) = rt.block_on(Sandbox::new(cfg(), audit())).expect("rebuilt");
        assert!(rep.snapshot_python && rep.snapshot_javascript, "{rep:?}");
        let sidecar =
            |p: &Path| std::fs::read_to_string(p.with_extension("sha256")).expect("sidecar");
        for p in [&snap_py, &snap_js] {
            let bytes = std::fs::read(p).expect("read");
            assert!(
                sidecar(p).contains(&sha256_hex(&bytes)),
                "{} rebuilt and re-hashed",
                p.display()
            );
        }
        let pol = Arc::new(
            Policy::from_toml(
                "version = 1\nname = \"t\"\n[limits]\nmemory = \"256MiB\"\n",
                "t.toml",
            )
            .expect("policy"),
        );
        for (lang, code) in [
            (Language::Python, "print(6 * 7)"),
            (Language::JavaScript, "console.log(6 * 7)"),
        ] {
            let r = rt.block_on(sb.execute(RunRequest::new(lang, code), pol.clone(), "t", None));
            assert_eq!(
                String::from_utf8_lossy(&r.stdout),
                "42\n",
                "{lang:?}: {}",
                String::from_utf8_lossy(&r.stderr)
            );
        }
        drop(sb);
        let _ = std::fs::remove_dir_all(&dir);
    })
    .join()
    .expect("thread");
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

// ---------------- E-SNAP-2 (T22): nothing of the host is baked into a snapshot ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_snap_2_snapshots_hold_no_host_paths_or_environment() {
    let w = world();
    let mut needles: Vec<String> = Vec::new();
    for p in [&w.cache, &w.root, &std::env::temp_dir()] {
        let s = p.display().to_string();
        needles.push(s.clone());
        needles.push(s.replace('\\', "/"));
    }
    for var in ["PATH", "HOME", "USERPROFILE", "USERNAME", "USER"] {
        if let Ok(v) = std::env::var(var)
            && v.len() >= 6
        {
            needles.push(v);
        }
    }
    for n in needles {
        assert_clean(
            &run(ALICE, "python", &py_probe(&n)).await,
            &format!("E-SNAP-2 py {n:.60}"),
        );
        assert_clean(
            &run(ALICE, "javascript", &js_probe(&n)).await,
            &format!("E-SNAP-2 js {n:.60}"),
        );
    }
    // And it really ran on the snapshot interpreter.
    let v = run(ALICE, "python", "print(1)").await;
    let run_id = v["run_id"].as_str().expect("run id").to_string();
    let interp = w.audit.events().into_iter().find_map(|e| match e.kind {
        EventKind::RunStart { interpreter, .. }
            if e.run_id.map(|r| r.to_string()) == Some(run_id.clone()) =>
        {
            interpreter
        }
        _ => None,
    });
    assert_eq!(interp.as_deref(), Some("snapshot"), "{interp:?}");
}
