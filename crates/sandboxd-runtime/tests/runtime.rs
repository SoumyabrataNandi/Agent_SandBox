//! U4 acceptance tests against real CPython 3.15 and QuickJS-ng (WASI).

use std::{
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use sandboxd_audit::{EventKind, MemorySink};
use sandboxd_policy::{ByteSize, Overrides, Policy};
use sandboxd_runtime::*;
use sandboxd_vfs::VfsConfig;

fn root() -> std::path::PathBuf {
    std::env::temp_dir().join("sandboxd-runtime-tests")
}

/// One warmed Sandbox per test binary (first run compiles modules + stdlib bytecode).
fn sandbox() -> &'static (Sandbox, Arc<MemorySink>, WarmupReport) {
    static S: OnceLock<(Sandbox, Arc<MemorySink>, WarmupReport)> = OnceLock::new();
    S.get_or_init(|| {
        // Tests run inside tokio runtimes, so build on a separate OS thread with its own runtime.
        std::thread::spawn(|| {
            let rt = tokio::runtime::Runtime::new().expect("rt");
            let audit = Arc::new(MemorySink::default());
            let cfg = RuntimeConfig {
                vfs: VfsConfig::under(root()),
                ..RuntimeConfig::default()
            };
            let (sb, rep) = rt
                .block_on(Sandbox::new(cfg, audit.clone()))
                .expect("sandbox");
            eprintln!("warmup: {rep:?}");
            (sb, audit, rep)
        })
        .join()
        .expect("warmup thread")
    })
}

fn pol(limits: &str) -> Arc<Policy> {
    Arc::new(
        Policy::from_toml(
            &format!("version = 1\nname = \"t\"\n[limits]\n{limits}\n[env]\nTZ = \"UTC\"\n"),
            "t.toml",
        )
        .expect("policy"),
    )
}

async fn py(code: &str, limits: &str) -> RunResult {
    sandbox()
        .0
        .execute(
            RunRequest::new(Language::Python, code),
            pol(limits),
            "test",
            None,
        )
        .await
}

async fn js(code: &str, limits: &str) -> RunResult {
    sandbox()
        .0
        .execute(
            RunRequest::new(Language::JavaScript, code),
            pol(limits),
            "test",
            None,
        )
        .await
}

fn out(r: &RunResult) -> String {
    String::from_utf8_lossy(&r.stdout).into_owned()
}
fn err(r: &RunResult) -> String {
    String::from_utf8_lossy(&r.stderr).into_owned()
}

// ---------- AC1 ----------

#[tokio::test(flavor = "multi_thread")]
async fn ac1_hello_python() {
    let r = py("print('hello from python')", "").await;
    assert_eq!(out(&r), "hello from python\n", "stderr: {}", err(&r));
    assert_eq!((r.outcome, r.exit_code), (Outcome::Ok, Some(0)));
    assert!(r.error.is_none() && r.limits_hit.is_empty());
    assert!(r.fuel_used > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn ac1_hello_javascript_es_module() {
    let r = js(
        "import * as std from 'qjs:std';\nconst x = await Promise.resolve(21);\nconsole.log('hello from js', x * 2);\nstd.out.puts('std ok\\n');",
        "",
    )
    .await;
    assert_eq!(out(&r), "hello from js 42\nstd ok\n", "stderr: {}", err(&r));
    assert_eq!((r.outcome, r.exit_code), (Outcome::Ok, Some(0)));
}

// ---------- AC2 ----------

#[tokio::test(flavor = "multi_thread")]
async fn ac2_wall_clock_busy_loop() {
    let t = Instant::now();
    let r = py(
        "while True:\n    pass",
        "wall_clock = \"2s\"\nfuel = \"1T\"",
    )
    .await;
    let el = t.elapsed();
    assert_eq!(r.outcome, Outcome::Limit);
    assert_eq!(r.limits_hit, vec![LimitKind::WallClock]);
    assert!(
        el < Duration::from_millis(2200) + Duration::from_millis(300),
        "took {el:?} (setup included)"
    );
    assert!(r.timings.run_ms <= 2200, "run took {}ms", r.timings.run_ms);
}

#[tokio::test(flavor = "multi_thread")]
async fn ac2_wall_clock_while_sleeping_in_host() {
    let r = py("import time\ntime.sleep(30)", "wall_clock = \"1s\"").await;
    assert_eq!(r.limits_hit, vec![LimitKind::WallClock]);
    assert!(r.timings.run_ms < 1500, "{}ms", r.timings.run_ms);
}

#[tokio::test(flavor = "multi_thread")]
async fn ac2_fuel_exhaustion_is_cpu() {
    let r = py(
        "n = 0\nwhile True:\n    n += 1",
        "fuel = \"200M\"\nwall_clock = \"30s\"",
    )
    .await;
    assert_eq!(
        (r.outcome, r.limits_hit.clone()),
        (Outcome::Limit, vec![LimitKind::Cpu])
    );
    assert!(r.fuel_used >= 199_000_000);
}

#[tokio::test(flavor = "multi_thread")]
async fn ac2_javascript_infinite_loop() {
    let r = js("for(;;){}", "wall_clock = \"1s\"\nfuel = \"1T\"").await;
    assert_eq!(r.limits_hit, vec![LimitKind::WallClock]);
}

// ---------- AC3 ----------

#[tokio::test(flavor = "multi_thread")]
async fn ac3_memory_bomb_is_contained() {
    let r = py(
        "x = bytearray(1 << 30)\nprint('allocated')",
        "memory = \"128MiB\"",
    )
    .await;
    assert!(!out(&r).contains("allocated"));
    assert_eq!(r.outcome, Outcome::Limit, "stderr: {}", err(&r));
    assert!(r.limits_hit.contains(&LimitKind::Memory));
    assert!(r.peak_memory <= 128 << 20);
    // The sandbox is still healthy afterwards.
    assert_eq!(out(&py("print(1)", "").await), "1\n");
}

// ---------- AC6 ----------

#[tokio::test(flavor = "multi_thread")]
async fn ac6_numpy_is_unsupported_native_extension() {
    let r = py("import numpy as np\nprint(np.zeros(3))", "").await;
    assert_eq!(
        r.error,
        Some(RunError::UnsupportedNativeExtension {
            module: "numpy".into()
        })
    );
    assert_eq!(
        r.error.as_ref().map(RunError::code),
        Some("UNSUPPORTED_NATIVE_EXTENSION")
    );
    assert_eq!(r.outcome, Outcome::Exit);
    // A comment mentioning numpy is not a false positive.
    assert!(
        py("# import numpy\nprint('fine')", "")
            .await
            .error
            .is_none()
    );
}

// ---------- limits & outcomes ----------

#[tokio::test(flavor = "multi_thread")]
async fn stdout_cap_truncates() {
    let r = py(
        "import sys\nfor _ in range(1000):\n    sys.stdout.write('x' * 100)",
        "stdout = \"1KiB\"",
    )
    .await;
    assert_eq!(r.stdout.len(), 1024);
    assert!(r.stdout_truncated && r.limits_hit.contains(&LimitKind::Stdout));
    assert_eq!(r.outcome, Outcome::Limit);
}

#[tokio::test(flavor = "multi_thread")]
async fn exit_codes_and_tracebacks() {
    let r = py("import sys\nsys.exit(3)", "").await;
    assert_eq!((r.outcome, r.exit_code), (Outcome::Exit, Some(3)));
    let r = py("x = 1\nraise ValueError('nope')", "").await;
    assert_eq!(r.exit_code, Some(1));
    assert!(
        err(&r).contains("File \"/code/main.py\", line 2"),
        "{}",
        err(&r)
    );
    let r = js("throw new Error('boom')", "").await;
    assert_eq!(r.outcome, Outcome::Exit);
    assert!(err(&r).contains("boom"), "{}", err(&r));
}

#[tokio::test(flavor = "multi_thread")]
async fn stdin_args_env_and_readonly_code() {
    let mut req = RunRequest::new(
        Language::Python,
        "import sys, os\nprint(sys.stdin.read().strip(), sys.argv[1:], os.environ.get('TZ'), sorted(os.environ))\ntry:\n    open('/code/main.py','w')\nexcept OSError as e:\n    print('code ro')",
    );
    req.stdin = Some(b"from-stdin\n".to_vec());
    req.args = vec!["a".into(), "b c".into()];
    let r = sandbox().0.execute(req, pol(""), "test", None).await;
    assert_eq!(
        out(&r),
        "from-stdin ['a', 'b c'] UTC ['TZ']\ncode ro\n",
        "stderr: {}",
        err(&r)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn inputs_and_artifacts_round_trip() {
    let mut req = RunRequest::new(
        Language::Python,
        "import csv, json\nrows = list(csv.DictReader(open('/in/sales.csv')))\ntotal = sum(int(r['amount']) for r in rows)\njson.dump({'total': total}, open('/out/summary.json','w'))\nprint(total)",
    );
    req.files = vec![InputFile {
        name: "sales.csv".into(),
        bytes: b"region,amount\neu,5\nus,7\n".to_vec(),
    }];
    let r = sandbox().0.execute(req, pol(""), "test", None).await;
    assert_eq!(out(&r), "12\n", "stderr: {}", err(&r));
    assert_eq!(r.artifacts.len(), 1);
    assert_eq!(r.artifacts[0].name, "summary.json");
    assert_eq!(r.artifacts[0].bytes, br#"{"total": 12}"#);
}

#[tokio::test(flavor = "multi_thread")]
async fn overrides_cannot_widen() {
    let mut req = RunRequest::new(Language::Python, "print(1)");
    req.overrides = Overrides {
        memory: Some(ByteSize::gib(2)),
        ..Default::default()
    };
    let r = sandbox().0.execute(req, pol(""), "test", None).await;
    assert!(
        matches!(r.error, Some(RunError::PolicyViolation(_))),
        "{:?}",
        r.error
    );
    assert!(r.stdout.is_empty());
    let mut req = RunRequest::new(Language::Python, "print(1)");
    req.overrides = Overrides {
        wall_clock: Some(Duration::from_secs(1)),
        ..Default::default()
    };
    assert_eq!(
        out(&sandbox().0.execute(req, pol(""), "test", None).await),
        "1\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_requests_and_sessions() {
    let mut req = RunRequest::new(Language::Python, "print(1)");
    req.session = Some(SessionId("s".into()));
    let r = sandbox().0.execute(req, pol(""), "test", None).await;
    assert_eq!(
        r.error,
        Some(RunError::NotImplemented("persistent sessions"))
    );
    let big = "#".repeat(2 << 20);
    assert!(matches!(
        py(&big, "").await.error,
        Some(RunError::InvalidRequest(_))
    ));
    let mut req = RunRequest::new(Language::Python, "print(1)");
    req.files = vec![InputFile {
        name: "../escape".into(),
        bytes: vec![],
    }];
    assert!(matches!(
        sandbox().0.execute(req, pol(""), "test", None).await.error,
        Some(RunError::InvalidRequest(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn events_stream_then_finished() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let r = sandbox()
        .0
        .execute(
            RunRequest::new(
                Language::Python,
                "import sys\nprint('a', flush=True)\nprint('b', file=sys.stderr)",
            ),
            pol(""),
            "test",
            Some(tx),
        )
        .await;
    let mut evs = Vec::new();
    while let Some(e) = rx.recv().await {
        evs.push(e);
    }
    assert!(matches!(evs.last(), Some(RunEvent::Finished(f)) if f.run_id == r.run_id));
    let streamed: Vec<u8> = evs
        .iter()
        .filter_map(|e| {
            if let RunEvent::Stdout(b) = e {
                Some(b.to_vec())
            } else {
                None
            }
        })
        .flatten()
        .collect();
    assert_eq!(streamed, b"a\n");
    assert!(evs.iter().any(|e| matches!(e, RunEvent::Stderr(_))));
}

#[tokio::test(flavor = "multi_thread")]
async fn twenty_concurrent_runs() {
    let t = Instant::now();
    let runs = (0..20).map(|i| {
        let code = format!("import json\nprint(json.dumps({{'i': {i}}}))");
        tokio::spawn(async move { py(&code, "").await })
    });
    let results = futures_join(runs.collect()).await;
    for (i, r) in results.iter().enumerate() {
        assert_eq!(
            out(r),
            format!("{{\"i\": {i}}}\n"),
            "run {i}: outcome {:?}, error {:?}, limits {:?}, run_ms {}, stderr {}",
            r.outcome,
            r.error,
            r.limits_hit,
            r.timings.run_ms,
            err(r)
        );
    }
    eprintln!("20 concurrent python runs: {:?}", t.elapsed());
}

async fn futures_join(hs: Vec<tokio::task::JoinHandle<RunResult>>) -> Vec<RunResult> {
    let mut v = Vec::new();
    for h in hs {
        v.push(h.await.expect("join"));
    }
    v
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_trail_for_a_run() {
    let r = py("print(1)", "").await;
    let evs: Vec<_> = sandbox()
        .1
        .events()
        .into_iter()
        .filter(|e| e.run_id == Some(r.run_id))
        .collect();
    assert!(matches!(
        evs.first().map(|e| &e.kind),
        Some(EventKind::RunStart { .. })
    ));
    assert!(matches!(
        evs.last().map(|e| &e.kind),
        Some(EventKind::RunEnd { .. })
    ));
    assert!(
        evs.iter().all(|e| e.principal.as_deref() == Some("test")
            || matches!(e.kind, EventKind::FsAccess { .. }))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn performance_and_fuel_calibration_report() {
    let _ = sandbox();
    let cases = [
        ("python print(1)", Language::Python, "print(1)"),
        (
            "python import json,csv,re,datetime",
            Language::Python,
            "import json, csv, re, datetime\nprint(1)",
        ),
        (
            "python 1M-iteration loop",
            Language::Python,
            "n=0\nfor i in range(1_000_000):\n    n+=i\nprint(n)",
        ),
        ("js console.log", Language::JavaScript, "console.log(1)"),
        (
            "js 1M-iteration loop",
            Language::JavaScript,
            "let n=0; for (let i=0;i<1e6;i++) n+=i; console.log(n)",
        ),
    ];
    eprintln!(
        "\n{:<38} {:>9} {:>9} {:>14}",
        "workload", "total ms", "run ms", "fuel"
    );
    for (label, lang, code) in cases {
        let mut best: Option<RunResult> = None;
        for _ in 0..3 {
            let r = sandbox()
                .0
                .execute(
                    RunRequest::new(lang, code),
                    pol("wall_clock = \"30s\"\nfuel = \"1T\""),
                    "bench",
                    None,
                )
                .await;
            assert_eq!(r.outcome, Outcome::Ok, "{label}: {}", err(&r));
            if best
                .as_ref()
                .is_none_or(|b| r.timings.total_ms < b.timings.total_ms)
            {
                best = Some(r);
            }
        }
        let b = best.expect("ran");
        eprintln!(
            "{label:<38} {:>9} {:>9} {:>14}",
            b.timings.total_ms, b.timings.run_ms, b.fuel_used
        );
    }
}

#[test]
fn tampered_module_cache_is_detected_and_rebuilt() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let dir =
            std::env::temp_dir().join(format!("sandboxd-cache-tamper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = || RuntimeConfig {
            vfs: VfsConfig::under(&dir),
            precompile_stdlib: false,
            ..RuntimeConfig::default()
        };
        let audit = || Arc::new(MemorySink::default()) as Arc<dyn sandboxd_audit::AuditSink>;

        let (_, first) = rt.block_on(Sandbox::new(cfg(), audit())).expect("first");
        assert!(!first.python_cached && !first.javascript_cached);
        let (_, second) = rt.block_on(Sandbox::new(cfg(), audit())).expect("second");
        assert!(
            second.python_cached && second.javascript_cached,
            "warm start uses the cache"
        );

        // Flip one byte in the QuickJS artifact: the hash check must reject it (never deserialize).
        let modules = dir.join("cache").join("modules");
        let cwasm = std::fs::read_dir(&modules)
            .expect("modules dir")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("quickjs-"))
                    && p.extension().is_some_and(|x| x == "cwasm")
            })
            .expect("quickjs cwasm");
        let mut bytes = std::fs::read(&cwasm).expect("read");
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        std::fs::write(&cwasm, bytes).expect("tamper");

        let (sb, third) = rt.block_on(Sandbox::new(cfg(), audit())).expect("third");
        assert!(third.python_cached, "untouched entry still cached");
        assert!(
            !third.javascript_cached,
            "tampered entry recompiled, not loaded"
        );
        let r = rt.block_on(sb.execute(
            RunRequest::new(Language::JavaScript, "console.log('ok')"),
            pol(""),
            "t",
            None,
        ));
        assert_eq!(String::from_utf8_lossy(&r.stdout), "ok\n");
        drop(sb);
        let _ = std::fs::remove_dir_all(&dir);
    })
    .join()
    .expect("thread");
}

/// Regression (found by the U6 escape suite): deep guest recursion overflowed the *host* fiber
/// stack and crashed the process when `max_wasm_stack` == `async_stack_size`.
#[tokio::test(flavor = "multi_thread")]
async fn deep_recursion_is_contained_not_a_host_crash() {
    for code in [
        "import sys\nsys.setrecursionlimit(10**6)\ndef f(n):\n    return f(n + 1)\nf(0)",
        "import json\nx = []\nfor _ in range(100000):\n    x = [x]\nprint(len(json.dumps(x)))",
    ] {
        let r = py(code, "").await;
        assert_ne!(r.outcome, Outcome::Ok, "{code}");
        assert!(
            !matches!(r.error, Some(RunError::Internal(_))),
            "{:?}",
            r.error
        );
    }
    assert_eq!(out(&py("print('still alive')", "").await), "still alive\n");
}
