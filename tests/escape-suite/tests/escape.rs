//! Release-blocking escape suite (U6 design §1). Black-box: only public APIs of the service.
//!
//! Every case plants random canaries on the host and fails if one leaks into any output,
//! artifact or audit line, if an attack reports `ESCAPED`, or if the service is unhealthy afterwards.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::Engine as _;
use sandboxd_audit::{AuditEvent, EventKind, MemorySink, Redactor};
use sandboxd_policy::{LoadOptions, PolicyDir};
use sandboxd_runtime::{LimitKind, Outcome, RunError, RunResult, RuntimeConfig, Sandbox};
use sandboxd_server::{
    AdmissionConfig, Principal, RunService, TokenSet,
    api::{ApiFile, ApiLanguage, ApiLimits, ApiRunRequest},
    hash_token,
    http::{AppState, router},
};
use sandboxd_vfs::VfsConfig;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const TOKEN: &str = "sbx_escape_suite_token_0123456789";

struct World {
    service: RunService,
    audit: Arc<MemorySink>,
    canary: String,
    root: PathBuf,
    data: PathBuf,
    work: PathBuf,
}

/// One hostile world per test binary: canaries, a data mount, a policy dir, a warmed sandbox.
fn world() -> &'static World {
    static W: OnceLock<World> = OnceLock::new();
    W.get_or_init(|| {
        std::thread::spawn(|| {
            let canary = format!("CANARY-{}", uuid::Uuid::new_v4().simple());
            let root = std::env::temp_dir().join("sandboxd-escape"); // fixed name: wiped on start, at most one copy
            let _ = std::fs::remove_dir_all(&root);
            let data = root.join("data");
            std::fs::create_dir_all(data.join("sub")).expect("mkdir");
            std::fs::write(data.join("ref.txt"), "reference").expect("w");
            std::fs::write(root.join("canary.txt"), &canary).expect("w"); // outside every mount
            std::fs::write(root.join("canary-sibling.txt"), &canary).expect("w");
            #[cfg(unix)]
            {
                let _ = std::os::unix::fs::symlink(root.join("canary.txt"), data.join("link_out"));
                let _ = std::os::unix::fs::symlink(&root, data.join("dirlink_out"));
            }
            let policies = root.join("policies");
            std::fs::create_dir_all(&policies).expect("mkdir");
            let host = data.display().to_string().replace('\\', "/");
            std::fs::write(
                policies.join("esc.toml"),
                format!(
                    "version = 1\nname = \"esc\"\n[limits]\nwall_clock = \"3s\"\nmemory = \"128MiB\"\nstdout = \"64KiB\"\nstderr = \"64KiB\"\nartifact_count = 20\nartifact_bytes = \"1MiB\"\ninput_bytes = \"1MiB\"\n[[filesystem.mount]]\nguest = \"/data\"\nhost = \"{host}\"\nmode = \"ro\"\n[env]\nTZ = \"UTC\"\n[audit]\nlog_code = true\n"
                ),
            )
            .expect("policy");
            let rt = tokio::runtime::Runtime::new().expect("rt");
            let audit = Arc::new(MemorySink::default());
            let shared = std::env::temp_dir().join("sandboxd-runtime-tests").join("cache");
            let work = root.join("work");
            let cfg = RuntimeConfig { vfs: VfsConfig { cache_dir: shared, work_dir: work.clone() }, ..RuntimeConfig::default() };
            let (sandbox, _) = rt.block_on(Sandbox::new(cfg, audit.clone())).expect("sandbox");
            let dir = PolicyDir::load(&policies, &LoadOptions::default()).expect("policies");
            let admission = AdmissionConfig { max_concurrent: 8, queue_depth: 64, queue_timeout: Duration::from_secs(60) };
            let service = RunService::new(sandbox, dir, audit.clone(), admission);
            World { service, audit, canary, root, data, work }
        })
        .join()
        .expect("world")
    })
}

fn req(lang: ApiLanguage, code: &str) -> ApiRunRequest {
    ApiRunRequest {
        language: lang,
        code: code.into(),
        policy: Some("esc".into()),
        files: vec![],
        args: vec![],
        stdin: None,
        limits: None,
    }
}

async fn run(r: ApiRunRequest) -> RunResult {
    world()
        .service
        .submit(&Principal::local("escape-suite"), r, None)
        .await
        .expect("service accepted the request")
}

async fn py(code: &str) -> RunResult {
    run(req(ApiLanguage::Python, code)).await
}

async fn js(code: &str) -> RunResult {
    run(req(ApiLanguage::Javascript, code)).await
}

fn out(r: &RunResult) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&r.stdout),
        String::from_utf8_lossy(&r.stderr)
    )
}

/// The universal invariants.
fn assert_contained(r: &RunResult, case: &str) {
    let w = world();
    let text = out(r);
    assert!(
        !text.contains("ESCAPED"),
        "[{case}] attack succeeded:\n{text}"
    );
    assert!(
        !text.contains(&w.canary),
        "[{case}] canary leaked via output:\n{text}"
    );
    for a in &r.artifacts {
        assert!(
            !String::from_utf8_lossy(&a.bytes).contains(&w.canary),
            "[{case}] canary leaked via artifact {}",
            a.name
        );
    }
    let redactor = Redactor::new();
    for ev in w.audit.events() {
        assert!(
            !ev.to_json_line(&redactor).contains(&w.canary),
            "[{case}] canary leaked into audit"
        );
    }
    assert!(w.service.healthy(), "[{case}] service unhealthy afterwards");
}

/// Python preamble: `attempt(name, fn)` prints ESCAPED if `fn` returns without raising.
const ATTEMPT: &str = r#"
def attempt(name, fn):
    try:
        r = fn()
        print("ESCAPED", name, repr(r)[:300])
    except BaseException as e:
        print("blocked", name, type(e).__name__)
"#;

fn pyq(s: &str) -> String {
    format!("{s:?}") // Rust debug-escaping is a valid Python string literal
}

// ---------------- E-FS-1 traversal ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_fs_1_path_traversal() {
    let w = world();
    let host_canary = w.root.join("canary.txt").display().to_string();
    let paths = [
        "/etc/passwd".to_string(),
        "../canary.txt".into(),
        "/data/../canary.txt".into(),
        "/data/sub/../../canary.txt".into(),
        format!("/data/{}canary.txt", "../".repeat(50)),
        "/data/%2e%2e/canary.txt".into(),
        "/data/..%2fcanary.txt".into(),
        "..\\canary.txt".into(),
        "C:\\Windows\\win.ini".into(),
        "\\\\?\\C:\\Windows\\win.ini".into(),
        host_canary.clone(),
        host_canary.replace('\\', "/"),
        format!("/{}", "a".repeat(4096)),
    ];
    let mut code = String::from(ATTEMPT);
    for (i, p) in paths.iter().enumerate() {
        code.push_str(&format!(
            "attempt('p{i}', lambda: open({}).read())\n",
            pyq(p)
        ));
    }
    code.push_str("attempt('nul', lambda: open('/data/ref.txt\\x00/../../canary.txt').read())\n");
    let r = py(&code).await;
    assert_eq!(
        out(&r).matches("blocked").count(),
        paths.len() + 1,
        "{}",
        out(&r)
    );
    assert_contained(&r, "E-FS-1");
    let denied: Vec<_> = w
        .audit
        .events()
        .into_iter()
        .filter(|e| e.run_id == Some(r.run_id))
        .filter_map(|e| match e.kind {
            EventKind::FsAccess {
                path,
                decision: sandboxd_audit::Decision::Deny,
                ..
            } => Some(path),
            _ => None,
        })
        .collect();
    assert!(denied.iter().any(|p| p == "/etc/passwd"), "{denied:?}");
    assert!(
        denied.iter().any(|p| p.contains("canary.txt")),
        "{denied:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn e_fs_1_javascript_traversal() {
    let r = js(
        "import * as std from 'qjs:std';\nimport * as os from 'qjs:os';\nfor (const p of ['/etc/passwd', '/data/../canary.txt', '../canary.txt']) {\n  const t = std.loadFile(p);\n  if (t !== null) console.log('ESCAPED', p, t);\n}\nconst [names, err] = os.readdir('/');\nconsole.log('root', JSON.stringify(names), err);",
    )
    .await;
    assert_contained(&r, "E-FS-1/js");
}

// ---------------- E-FS-2 symlinks ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_fs_2_symlinks() {
    let code = format!(
        "{ATTEMPT}import os\nattempt('host_link_file', lambda: open('/data/link_out').read())\nattempt('host_link_dir', lambda: open('/data/dirlink_out/canary.txt').read())\nattempt('host_link_list', lambda: os.listdir('/data/dirlink_out'))\ndef mk(target, at):\n    try:\n        os.symlink(target, at)\n    except OSError:\n        pass\nmk('/etc', '/out/s1')\nmk('../../..', '/out/s2')\nmk('/data/../..', '/out/s3')\nattempt('guest_link_abs', lambda: open('/out/s1/passwd').read())\nattempt('guest_link_up', lambda: open('/out/s2/canary.txt').read())\nattempt('guest_link_up2', lambda: os.listdir('/out/s3'))\n"
    );
    let r = py(&code).await;
    assert_contained(&r, "E-FS-2");
    assert!(
        r.artifacts.iter().all(|a| !a.name.starts_with('s')),
        "symlinks are never collected: {:?}",
        r.artifacts.iter().map(|a| &a.name).collect::<Vec<_>>()
    );
}

// ---------------- E-FS-3 links / renames ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_fs_3_links_and_renames() {
    let code = format!(
        "{ATTEMPT}import os\nattempt('hardlink_ro_into_out', lambda: os.link('/data/ref.txt', '/out/l.txt'))\nattempt('rename_ro_to_out', lambda: os.rename('/data/ref.txt', '/out/r.txt'))\nattempt('rename_out_root', lambda: os.rename('/out', '/gone'))\nattempt('rename_into_data', lambda: (open('/out/x','w').write('x'), os.rename('/out/x', '/data/x')))\n"
    );
    let r = py(&code).await;
    assert_contained(&r, "E-FS-3");
    assert_eq!(
        std::fs::read_to_string(world().data.join("ref.txt")).expect("ref"),
        "reference"
    );
    assert!(!world().data.join("x").exists());
}

// ---------------- E-FS-4 write protection ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_fs_4_read_only_everywhere_but_out() {
    let mut r = req(
        ApiLanguage::Python,
        &format!(
            "{ATTEMPT}import os\nfor p in ['/in/in.txt', '/code/main.py', '/usr/local/lib/python3.15/os.py', '/data/ref.txt', '/new.txt', '/data/new.txt', '/in/new.txt']:\n    attempt('write ' + p, lambda p=p: open(p, 'a').write('x'))\nattempt('unlink', lambda: os.unlink('/data/ref.txt'))\nattempt('rmdir', lambda: os.rmdir('/data/sub'))\nattempt('mkdir', lambda: os.mkdir('/data/d'))\nattempt('truncate', lambda: os.truncate('/data/ref.txt', 0))\nattempt('chmod', lambda: os.chmod('/data/ref.txt', 0o777))\nattempt('utime', lambda: os.utime('/data/ref.txt', (0, 0)))\n"
        ),
    );
    r.files = vec![ApiFile {
        name: "in.txt".into(),
        content: "input".into(),
        encoding: Default::default(),
    }];
    let r = run(r).await;
    let text = out(&r);
    // chmod/utime may be no-ops on some hosts; everything else must be blocked.
    for line in text.lines().filter(|l| l.starts_with("ESCAPED")) {
        assert!(line.contains("chmod") || line.contains("utime"), "{text}");
    }
    let r2 = RunResult {
        stdout: text
            .lines()
            .filter(|l| !(l.contains("chmod") || l.contains("utime")))
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes(),
        ..r
    };
    assert_contained(&r2, "E-FS-4");
    assert_eq!(
        std::fs::read_to_string(world().data.join("ref.txt")).expect("ref"),
        "reference"
    );
    assert!(world().data.join("sub").is_dir());
}

// ---------------- E-FS-5 info leaks ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_fs_5_no_host_paths_leak() {
    let r = py("import os, sys\nprint(os.getcwd(), sys.path, sys.executable, sys.prefix, os.listdir('/'), os.listdir('/data'))\nraise RuntimeError('trace')").await;
    let text = out(&r);
    let w = world();
    let mut needles = vec![
        w.root.display().to_string(),
        w.root.display().to_string().replace('\\', "/"),
        std::env::temp_dir().display().to_string(),
    ];
    for k in ["HOME", "USERPROFILE", "USERNAME", "USER"] {
        if let Ok(v) = std::env::var(k)
            && v.len() > 3
        {
            needles.push(v);
        }
    }
    for n in needles {
        assert!(!text.contains(&n), "host detail {n:?} leaked:\n{text}");
    }
    assert!(!text.contains(":\\"), "drive path leaked:\n{text}");
    assert_contained(&r, "E-FS-5");
}

// ---------------- E-ENV ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_env_only_policy_variables() {
    let r = py("import os, json\nprint(json.dumps(dict(os.environ)))").await;
    let env: Value = serde_json::from_slice(&r.stdout).unwrap_or_else(|e| {
        panic!(
            "json env: {e}; outcome {:?} exit {:?} error {:?}\n{}",
            r.outcome,
            r.exit_code,
            r.error,
            out(&r)
        )
    });
    assert_eq!(
        env,
        json!({"TZ": "UTC"}),
        "guest env must be exactly the policy env"
    );
    if let Ok(path) = std::env::var("PATH") {
        assert!(!out(&r).contains(&path));
    }
    let r =
        js("import * as std from 'qjs:std';\nconsole.log(JSON.stringify(std.getenviron()))").await;
    let env: Value = serde_json::from_slice(&r.stdout).expect("json env");
    assert_eq!(env, json!({"TZ": "UTC"}));
    assert_contained(&r, "E-ENV");
}

// ---------------- E-CPU ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_cpu_runaway_code_is_stopped() {
    let cases: [(ApiLanguage, &str); 5] = [
        (ApiLanguage::Python, "while True:\n    pass"),
        (
            ApiLanguage::Python,
            "import re\nre.match(r'(a+)+$', 'a' * 40 + 'b')",
        ),
        (ApiLanguage::Python, "print(sum(range(10**12)))"),
        (
            ApiLanguage::Python,
            "try:\n    raise ValueError()\nexcept ValueError:\n    pass\nfinally:\n    while True:\n        pass",
        ),
        (ApiLanguage::Javascript, "for(;;){}"),
    ];
    for (lang, code) in cases {
        let r = run(req(lang, code)).await;
        assert_eq!(
            r.outcome,
            Outcome::Limit,
            "{code}: {:?} {}",
            r.outcome,
            out(&r)
        );
        assert!(
            r.limits_hit
                .iter()
                .any(|k| matches!(k, LimitKind::Cpu | LimitKind::WallClock)),
            "{code}"
        );
        assert!(
            r.timings.run_ms <= 3_000 + 900,
            "{code}: ran {} ms",
            r.timings.run_ms
        );
        assert_contained(&r, "E-CPU");
    }
}

// ---------------- E-MEM ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_mem_bombs_are_contained() {
    let cases: [(ApiLanguage, &str); 5] = [
        (ApiLanguage::Python, "x = bytearray(2**31)"),
        (ApiLanguage::Python, "x = [0]\nwhile True:\n    x = x + x"),
        (ApiLanguage::Python, "s = 'a'\nwhile True:\n    s = s + s"),
        (
            ApiLanguage::Python,
            "import sys\nsys.setrecursionlimit(10**6)\ndef f(n):\n    return f(n + 1)\nf(0)",
        ),
        (
            ApiLanguage::Javascript,
            "const a = [];\nfor (;;) a.push(new Array(1e6).fill(1));",
        ),
    ];
    for (lang, code) in cases {
        let r = run(req(lang, code)).await;
        assert_ne!(r.outcome, Outcome::Ok, "{code} must not succeed");
        assert!(r.peak_memory <= 128 << 20, "{code}: peak {}", r.peak_memory);
        assert!(
            !matches!(r.error, Some(RunError::Internal(_))),
            "{code}: host-side failure {:?}",
            r.error
        );
        assert_contained(&r, "E-MEM");
    }
    assert_eq!(
        String::from_utf8_lossy(&py("print('alive')").await.stdout),
        "alive\n"
    );
}

// ---------------- E-OUT ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_out_floods_are_capped() {
    let r = py("import sys\nwhile True:\n    sys.stdout.write('x' * 65536)").await;
    assert!(
        r.stdout.len() <= 64 << 10
            && r.stdout_truncated
            && r.limits_hit.contains(&LimitKind::Stdout)
    );
    let r = py("import sys\nwhile True:\n    sys.stderr.write('e' * 65536)").await;
    assert!(r.stderr.len() <= 64 << 10 && r.limits_hit.contains(&LimitKind::Stderr));
    let r = py("f = open('/out/big.bin', 'wb')\nwhile True:\n    f.write(b'x' * 65536)").await;
    assert!(r.limits_hit.contains(&LimitKind::Artifacts));
    assert!(r.artifacts.iter().map(|a| a.bytes.len()).sum::<usize>() <= 1 << 20);
    let r = py("for i in range(10000):\n    open(f'/out/f{i}', 'w').write('x')").await;
    assert!(r.artifacts.len() <= 20 && r.limits_hit.contains(&LimitKind::Artifacts));
    let r = py("import os\np = '/out' + '/d' * 100\nos.makedirs(p)\nopen(p + '/x' * 1 + '.txt', 'w').write('deep')\nopen('/out/' + 'n' * 200, 'w').write('long')").await;
    assert!(
        r.artifacts
            .iter()
            .all(|a| !a.name.contains("..") && !a.name.starts_with('/'))
    );
    assert_contained(&r, "E-OUT");
}

// ---------------- E-PROC ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_proc_no_processes_threads_or_network() {
    let code = format!(
        "{ATTEMPT}import os\ndef system():\n    rc = os.system('echo pwned')\n    if rc != 0:\n        raise OSError(rc)\n    return rc\nattempt('system', system)\nattempt('subprocess', lambda: __import__('subprocess').run(['ls'], capture_output=True))\nattempt('fork', lambda: os.fork())\nattempt('socket', lambda: __import__('socket').create_connection(('1.1.1.1', 80), timeout=2))\nattempt('urllib', lambda: __import__('urllib.request').request.urlopen('http://example.com', timeout=2).read())\nattempt('thread', lambda: __import__('threading').Thread(target=print).start())\nattempt('ctypes', lambda: __import__('ctypes').CDLL(None))\nattempt('kill', lambda: os.kill(1, 9))\n"
    );
    let r = py(&code).await;
    assert!(!out(&r).contains("pwned"));
    assert_contained(&r, "E-PROC");
    let r = js("import * as os from 'qjs:os';\nlet rc;\ntry { rc = os.exec(['ls']); } catch (e) { rc = 'threw'; }\nif (rc === 0) console.log('ESCAPED exec');\nconsole.log('exec ->', rc);").await;
    assert_contained(&r, "E-PROC/js");
}

// ---------------- E-POL ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_pol_cannot_widen_or_pick_unknown_policies() {
    let w = world();
    let mut r = req(ApiLanguage::Python, "print(1)");
    r.limits = Some(ApiLimits {
        memory: Some("8GiB".into()),
        ..Default::default()
    });
    let res = run(r).await;
    assert!(matches!(res.error, Some(RunError::PolicyViolation(_))));
    assert!(res.stdout.is_empty(), "nothing ran");
    assert!(
        w.audit
            .events()
            .iter()
            .any(|e| e.run_id == Some(res.run_id)
                && matches!(e.kind, EventKind::PolicyDenied { .. }))
    );
    for name in ["nope", "../esc", "esc/../default", ""] {
        let mut r = req(ApiLanguage::Python, "print(1)");
        r.policy = Some(name.into());
        let got = w
            .service
            .submit(&Principal::local("escape-suite"), r, None)
            .await;
        if name.is_empty() {
            assert!(got.is_ok(), "empty policy → default");
        } else {
            assert!(
                matches!(got, Err(sandboxd_server::ServiceError::PolicyNotFound(_))),
                "{name:?}: {got:?}"
            );
        }
    }
}

// ---------------- E-AUTH / E-INPUT (HTTP) ----------------

fn app() -> axum::Router {
    let tokens = TokenSet::new(&[("suite".into(), hash_token(TOKEN))], None).expect("tokens");
    router(
        AppState {
            service: world().service.clone(),
            tokens: Arc::new(tokens),
            metrics_public: false,
        },
        2 << 20,
    )
}

async fn call(r: Request<Body>) -> (StatusCode, Value) {
    let resp = app().oneshot(r).await.expect("resp");
    let s = resp.status();
    let b = to_bytes(resp.into_body(), 8 << 20).await.expect("body");
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

fn post(uri: &str, auth: Option<&str>, body: Value) -> Request<Body> {
    let mut b = Request::post(uri).header("content-type", "application/json");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    b.body(Body::from(body.to_string())).expect("req")
}

#[tokio::test(flavor = "multi_thread")]
async fn e_auth_bypass_attempts() {
    let body =
        json!({"language": "python", "code": "print('ESCAPED unauthenticated')", "policy": "esc"});
    let mut off_by_one = TOKEN.to_string();
    off_by_one.pop();
    off_by_one.push('X');
    for auth in [
        None,
        Some(format!("Basic {TOKEN}")),
        Some(format!("Bearer {off_by_one}")),
        Some("Bearer ".into()),
        Some(format!("Bearer {}", "a".repeat(32 << 10))),
    ] {
        let (s, _) = call(post("/v1/runs", auth.as_deref(), body.clone())).await;
        assert!(
            s == StatusCode::UNAUTHORIZED || s == StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "{auth:?} → {s}"
        );
    }
    let (s, _) = call(post(
        &format!("/v1/runs?token={TOKEN}&access_token={TOKEN}"),
        None,
        body.clone(),
    ))
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "query-string tokens are ignored"
    );
    let mcp = Request::post("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Body::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        ))
        .expect("req");
    let (s, _) = call(mcp).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // An authenticated run: the token never reaches the audit log.
    let (s, _) = call(post(
        "/v1/runs",
        Some(&format!("Bearer {TOKEN}")),
        json!({"language":"python","code":"print(1)","policy":"esc"}),
    ))
    .await;
    assert_eq!(s, StatusCode::OK);
    let redactor = Redactor::new();
    assert!(
        world()
            .audit
            .events()
            .iter()
            .all(|e| !e.to_json_line(&redactor).contains(TOKEN))
    );
    assert!(
        world()
            .audit
            .events()
            .iter()
            .any(|e| e.principal.as_deref() == Some("suite"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn e_input_abuse_is_rejected_before_disk() {
    let auth = format!("Bearer {TOKEN}");
    let file = |n: &str| json!({"name": n, "content": "x"});
    let bad_sets = vec![
        vec![file("../x")],
        vec![file("/abs")],
        vec![file("CON")],
        vec![file("a/../../b")],
        vec![file("a.txt"), file("A.TXT")],
        vec![json!({"name": "b.bin", "content": "!!!not base64", "encoding": "base64"})],
        (0..1001).map(|i| file(&format!("f{i}"))).collect(),
    ];
    for files in bad_sets {
        let n = files.len();
        let (s, v) = call(post("/v1/runs", Some(&auth), json!({"language":"python","code":"print('ESCAPED ran')","policy":"esc","files": files}))).await;
        let rejected = s == StatusCode::BAD_REQUEST || v["error"]["code"] == "INVALID_REQUEST";
        assert!(rejected, "{n} files → {s} {v}");
        assert!(!v["stdout"].as_str().unwrap_or("").contains("ESCAPED"));
        if let Some(id) = v["run_id"].as_str() {
            assert!(
                !world().work.join("runs").join(id).exists(),
                "rejected run left a dir behind"
            );
        }
    }
    let (s, _) = call(post(
        "/v1/runs",
        Some(&auth),
        json!({"language":"python","code": "#".repeat(3 << 20),"policy":"esc"}),
    ))
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    let (s, _) = call(post(
        "/v1/runs",
        Some(&auth),
        json!({"language":"python","code":"1","policy":"esc","mounts":[{"guest":"/h","host":"/"}]}),
    ))
    .await;
    assert!(s.is_client_error(), "requests cannot add mounts");
    let big = base64::engine::general_purpose::STANDARD.encode(vec![0u8; (1 << 20) + 1]);
    let (_, v) = call(post("/v1/runs", Some(&auth), json!({"language":"python","code":"1","policy":"esc","files":[{"name":"big","content": big,"encoding":"base64"}]}))).await;
    assert_eq!(
        v["error"]["code"], "INVALID_REQUEST",
        "input_bytes enforced: {v}"
    );
}

// ---------------- E-CRASH ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_crash_hostile_concurrency_then_normal_run() {
    let hostile = [
        "while True: pass",
        "x = bytearray(2**31)",
        "import sys\nwhile True: sys.stdout.write('x'*65536)",
        "for i in range(10000): open(f'/out/{i}','w').write('x')",
        "open('/etc/passwd').read()",
        "import sys\nsys.setrecursionlimit(10**6)\ndef f(n): return f(n+1)\nf(0)",
    ];
    let mut handles = Vec::new();
    let mut ids = Vec::new();
    for i in 0..30 {
        let code = hostile[i % hostile.len()].to_string();
        handles.push(tokio::spawn(async move { py(&code).await }));
    }
    for h in handles {
        let r = h.await.expect("no panic escaped the sandbox");
        ids.push(r.run_id);
        assert!(
            !matches!(r.error, Some(RunError::Internal(_))),
            "{:?}",
            r.error
        );
        assert_contained(&r, "E-CRASH");
    }
    let r = py("print(sum(range(10)))").await;
    assert_eq!(String::from_utf8_lossy(&r.stdout), "45\n");
    // Other tests share this world and may be mid-run, so check only this test's runs.
    let runs = world().work.join("runs");
    let leftovers: Vec<_> = ids
        .iter()
        .filter(|id| runs.join(id.to_string()).exists())
        .collect();
    assert!(
        leftovers.is_empty(),
        "per-run directories not removed: {leftovers:?}"
    );
}

// ---------------- E-AUDIT ----------------

#[tokio::test(flavor = "multi_thread")]
async fn e_audit_secrets_are_redacted() {
    let secret = "sk-ant-api03-ESCAPESUITESECRETVALUE1234567890";
    let r = py(&format!("KEY = {secret:?}\nimport sys\nprint('token=hunter2-escape', file=sys.stderr)\nopen('/out/{secret}.txt'[:60], 'w').write('x')")).await;
    let redactor = Redactor::new();
    let lines: Vec<String> = world()
        .audit
        .events()
        .iter()
        .filter(|e| e.run_id == Some(r.run_id))
        .map(|e: &AuditEvent| e.to_json_line(&redactor))
        .collect();
    assert!(
        lines
            .iter()
            .any(|l| l.contains("run.start") && l.contains("REDACTED")),
        "code logged with log_code=true, redacted"
    );
    for l in &lines {
        assert!(
            !l.contains("ESCAPESUITESECRETVALUE"),
            "secret in audit: {l}"
        );
    }
    assert_contained(&r, "E-AUDIT");
}

#[test]
fn canary_files_untouched_after_suite_world_creation() {
    let w = world();
    assert_eq!(
        std::fs::read_to_string(w.root.join("canary.txt")).expect("canary"),
        w.canary
    );
    let _ = Path::new(&w.root);
}
