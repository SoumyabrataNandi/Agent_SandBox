//! C3-U4 persistent session tests (FR-SE1, AC 5–8), on both interpreter paths.

use std::{
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use sandboxd_audit::{EventKind, MemorySink};
use sandboxd_policy::{Overrides, Policy};
use sandboxd_runtime::*;
use sandboxd_vfs::VfsConfig;

fn root() -> std::path::PathBuf {
    std::env::temp_dir().join("sandboxd-runtime-tests")
}

type Built = (Sandbox, Arc<MemorySink>, WarmupReport);

fn build(snapshots: SnapshotMode) -> Built {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let audit = Arc::new(MemorySink::default());
        let cfg = RuntimeConfig {
            vfs: VfsConfig::under(root()),
            snapshots,
            ..RuntimeConfig::default()
        };
        let (sb, rep) = rt
            .block_on(Sandbox::new(cfg, audit.clone()))
            .expect("sandbox");
        (sb, audit, rep)
    })
    .join()
    .expect("thread")
}

fn snap() -> &'static Built {
    static S: OnceLock<Built> = OnceLock::new();
    S.get_or_init(|| build(SnapshotMode::On))
}

fn upstream() -> &'static Built {
    static S: OnceLock<Built> = OnceLock::new();
    S.get_or_init(|| build(SnapshotMode::Off))
}

fn policy(extra: &str) -> Arc<Policy> {
    Arc::new(
        Policy::from_toml(
            &format!(
                "version = 1\nname = \"s\"\n[limits]\nwall_clock = \"10s\"\n[session]\nenabled = true\n{extra}"
            ),
            "s.toml",
        )
        .expect("policy"),
    )
}

async fn open(b: &Built, lang: Language, extra: &str) -> Session {
    b.0.open_session(SessionOptions::new(lang), policy(extra), "alice")
        .await
        .expect("open session")
}

async fn call(s: &Session, code: &str) -> CallOutcome {
    s.call(CallRequest::new(code), None).await.expect("call")
}

fn out(o: &CallOutcome) -> String {
    String::from_utf8_lossy(&o.result.stdout).into_owned()
}

fn err(o: &CallOutcome) -> String {
    String::from_utf8_lossy(&o.result.stderr).into_owned()
}

async fn python_state_persists(b: &Built) {
    let s = open(b, Language::Python, "").await;
    let r = call(
        &s,
        "import json\nx = 41\ndef inc(v):\n    return v + 1\nprint('one')",
    )
    .await;
    assert_eq!(out(&r), "one\n", "{}", err(&r));
    assert_eq!(r.result.exit_code, Some(0));
    let r = call(&s, "print(inc(x), json.dumps([x]))").await;
    assert_eq!(out(&r), "42 [41]\n", "{}", err(&r));
    // An exception continues the session; output is per call.
    let r = call(&s, "y = 1\nraise ValueError('boom')").await;
    assert_eq!(r.result.outcome, Outcome::Exit);
    assert_eq!(r.result.exit_code, Some(1));
    assert!(err(&r).contains("ValueError: boom"), "{}", err(&r));
    assert!(
        !err(&r).contains("sandboxd_session"),
        "loop frames trimmed: {}",
        err(&r)
    );
    assert!(out(&r).is_empty());
    // sys.exit(n) ends the call, not the session.
    let r = call(&s, "import sys\nprint(y)\nsys.exit(3)").await;
    assert_eq!((r.result.exit_code, r.ended), (Some(3), None));
    assert_eq!(out(&r), "1\n");
    // /work persists, /out is per call.
    let r = call(
        &s,
        "open('/work/n.txt', 'w').write('kept')\nopen('/out/a.txt', 'w').write('A')",
    )
    .await;
    assert_eq!(r.result.artifacts.len(), 1, "{}", err(&r));
    let r = call(
        &s,
        "import os\nprint(open('/work/n.txt').read(), os.listdir('/out'), __file__)",
    )
    .await;
    assert_eq!(out(&r), "kept [] /code/cell_6.py\n", "{}", err(&r));
    assert!(r.result.artifacts.is_empty());
    let info = s.info();
    assert_eq!((info.calls, info.ended, info.busy), (6, None, false));
    s.close(SessionEnd::Closed).await;
    assert!(matches!(
        s.call(CallRequest::new("print(1)"), None).await,
        Err(SessionError::Ended(SessionEnd::Closed))
    ));
}

async fn javascript_state_persists(b: &Built) {
    let s = open(b, Language::JavaScript, "").await;
    let r = call(
        &s,
        "var a = 40; let b = 2; function add(x, y) { return x + y; }\nconsole.log('one');",
    )
    .await;
    assert_eq!(out(&r), "one\n", "{}", err(&r));
    let r = call(&s, "console.log(add(a, b));").await;
    assert_eq!(out(&r), "42\n", "{}", err(&r));
    let r = call(
        &s,
        "const v = await Promise.resolve(7); console.log(v * 6);",
    )
    .await;
    assert_eq!(out(&r), "42\n", "top-level await: {}", err(&r));
    let r = call(&s, "throw new Error('boom');").await;
    assert_eq!((r.result.exit_code, r.ended), (Some(1), None));
    assert!(err(&r).contains("boom"), "{}", err(&r));
    let r = call(&s, "console.log(typeof add, scriptArgs[0]);").await;
    assert_eq!(out(&r), "function /code/cell_5.js\n", "{}", err(&r));
    s.close(SessionEnd::Closed).await;
}

async fn limits_end_the_session(b: &Built) {
    let s = open(b, Language::Python, "").await;
    let r = call(&s, "x = 1").await;
    assert_eq!(r.result.outcome, Outcome::Ok);
    let r = call(
        &s,
        "n = 0
for i in range(200000):
    n += i",
    )
    .await;
    assert!(
        r.result.fuel_used > 10_000_000,
        "per-call fuel is counted: {}",
        r.result.fuel_used
    );
    // Per-call fuel budget, tighter than the session's.
    let mut req = CallRequest::new("while True:\n    pass");
    req.overrides = Overrides {
        fuel: Some(50_000_000),
        ..Overrides::default()
    };
    let t = Instant::now();
    let r = s.call(req, None).await.expect("call");
    assert_eq!(r.result.outcome, Outcome::Limit);
    assert_eq!(r.result.limits_hit, vec![LimitKind::Cpu]);
    assert_eq!(r.ended, Some(SessionEnd::Limit));
    assert!(t.elapsed() < Duration::from_secs(5));
    assert!(matches!(
        s.call(CallRequest::new("print(x)"), None).await,
        Err(SessionError::Ended(SessionEnd::Limit))
    ));

    let s = open(b, Language::JavaScript, "").await;
    let mut req = CallRequest::new("for (;;) {}");
    req.overrides = Overrides {
        wall_clock: Some(Duration::from_millis(300)),
        ..Overrides::default()
    };
    let r = s.call(req, None).await.expect("call");
    assert_eq!(r.result.limits_hit, vec![LimitKind::WallClock]);
    assert_eq!(r.ended, Some(SessionEnd::Limit));
}

async fn guest_exit_ends_the_session(b: &Built) {
    let s = open(b, Language::Python, "").await;
    let r = call(&s, "import os\nprint('bye', flush=True)\nos._exit(4)").await;
    assert_eq!(r.result.exit_code, Some(4));
    assert_eq!(r.ended, Some(SessionEnd::Exited));
    assert_eq!(out(&r), "bye\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn python_sessions_keep_state_snapshot() {
    python_state_persists(snap()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn python_sessions_keep_state_upstream() {
    python_state_persists(upstream()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn javascript_sessions_keep_state_snapshot() {
    javascript_state_persists(snap()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn javascript_sessions_keep_state_upstream() {
    javascript_state_persists(upstream()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn limits_end_sessions() {
    limits_end_the_session(snap()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn guest_exit_ends_sessions() {
    guest_exit_ends_the_session(snap()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_must_be_enabled_and_calls_are_validated() {
    let b = snap();
    let off = Arc::new(Policy::from_toml("version = 1\nname = \"off\"", "off.toml").expect("p"));
    assert_eq!(
        b.0.open_session(SessionOptions::new(Language::Python), off, "a")
            .await
            .err(),
        Some(SessionError::Disabled)
    );
    let s = open(b, Language::Python, "").await;
    let mut req = CallRequest::new("print(1)");
    req.stdin = Some(b"x".to_vec());
    assert!(matches!(
        s.call(req, None).await,
        Err(SessionError::InvalidRequest(_))
    ));
    let mut req = CallRequest::new("print(1)");
    req.overrides.memory = Some(sandboxd_policy::ByteSize(1 << 20));
    assert!(matches!(
        s.call(req, None).await,
        Err(SessionError::InvalidRequest(_))
    ));
    let mut req = CallRequest::new("print(1)");
    req.overrides.fuel = Some(u64::MAX);
    assert!(matches!(
        s.call(req, None).await,
        Err(SessionError::PolicyViolation(_))
    ));
    // Files sent with a call appear under /in.
    let mut req = CallRequest::new("print(open('/in/d.txt').read())");
    req.files.push(InputFile {
        name: "d.txt".into(),
        bytes: b"data".to_vec(),
    });
    let r = s.call(req, None).await.expect("call");
    assert_eq!(out(&r), "data\n", "{}", err(&r));
}

#[tokio::test(flavor = "multi_thread")]
async fn one_call_at_a_time_and_max_calls() {
    let b = snap();
    let s = open(b, Language::Python, "max_calls = 2").await;
    let s2 = s.clone();
    let slow = tokio::spawn(async move { call(&s2, "import time\ntime.sleep(1.5)").await });
    // Wait until the first call holds the session (a fixed head start races on a loaded runner).
    let t = Instant::now();
    while !s.info().busy {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "first call never started"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        s.call(CallRequest::new("print(1)"), None).await.err(),
        Some(SessionError::Busy)
    );
    assert_eq!(slow.await.expect("join").ended, None);
    let r = call(&s, "print(2)").await;
    assert_eq!(r.ended, Some(SessionEnd::MaxCalls));
    assert_eq!(out(&r), "2\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_events_carry_the_session_id() {
    let b = snap();
    let s = open(b, Language::Python, "").await;
    let r = call(&s, "print(1)").await;
    s.close(SessionEnd::Closed).await;
    let id = s.id().to_string();
    assert!(id.starts_with("ses_") && id.len() == 36, "{id}");
    let evs: Vec<_> =
        b.1.events()
            .into_iter()
            .filter(|e| e.session_id.as_deref() == Some(id.as_str()))
            .collect();
    assert!(
        evs.iter()
            .any(|e| matches!(&e.kind, EventKind::SessionStart { lang } if lang == "python"))
    );
    assert!(
        evs.iter()
            .any(|e| matches!(e.kind, EventKind::RunStart { .. })
                && e.run_id == Some(r.result.run_id))
    );
    assert!(
        evs.iter().any(
            |e| matches!(e.kind, EventKind::RunEnd { .. }) && e.run_id == Some(r.result.run_id)
        )
    );
    assert!(evs.iter().any(
        |e| matches!(&e.kind, EventKind::SessionEnd { reason, calls: 1, .. } if reason == "closed")
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn session_call_overhead() {
    // NFR-P1: a session call costs little more than the code it runs. Report, don't gate
    // (Windows has no copy-on-write images; the benchmark job measures on Linux).
    let b = snap();
    let s = open(b, Language::Python, "").await;
    call(&s, "x = 0").await;
    let n = 20;
    let t = Instant::now();
    for _ in 0..n {
        let r = call(&s, "x += 1").await;
        assert_eq!(r.result.outcome, Outcome::Ok);
    }
    let per = t.elapsed() / n;
    eprintln!("session call: {per:?} per call");
    assert!(per < Duration::from_millis(250), "{per:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn busy_loops_are_stopped_by_the_call_budgets() {
    // Hot loops without host calls: the fuel counter must be synced for the budget check
    // (fuel_async_yield_interval), and the epoch deadline must fire.
    let b = snap();
    for (lang, code) in [
        (Language::JavaScript, "for (;;) {}"),
        (
            Language::Python,
            "while True:
    pass",
        ),
    ] {
        for by_fuel in [false, true] {
            let s = open(b, lang, "").await;
            call(&s, "1").await;
            let mut req = CallRequest::new(code);
            if by_fuel {
                req.overrides.fuel = Some(50_000_000);
            } else {
                req.overrides.wall_clock = Some(Duration::from_millis(300));
            }
            let r = s.call(req, None).await.expect("call");
            let want = if by_fuel {
                LimitKind::Cpu
            } else {
                LimitKind::WallClock
            };
            assert_eq!(
                r.result.limits_hit,
                vec![want],
                "{lang:?} by_fuel={by_fuel}"
            );
            assert_eq!(r.ended, Some(SessionEnd::Limit));
            if by_fuel {
                // Overshoot is bounded by the sync interval plus one epoch tick of work.
                assert!(
                    r.result.fuel_used < 50_000_000 + 100_000_000,
                    "{}",
                    r.result.fuel_used
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forged_reply_cannot_buy_unbudgeted_cpu() {
    // A cell writes the loop's reply itself (the device fd is guessable) and keeps computing:
    // the call returns, but the idle guard stops the guest; the session ends on a CPU limit.
    let b = snap();
    let s = open(b, Language::Python, "").await;
    let r = call(
        &s,
        "import os
for fd in range(0x40000000, 0x40000008):
    try:
        os.write(fd, b'{\"status\": \"ok\", \"exit_code\": 0}')
        break
    except OSError:
        pass
while True:
    pass",
    )
    .await;
    assert_eq!(
        r.result.exit_code,
        Some(0),
        "forged reply accepted for this call"
    );
    let t = Instant::now();
    let next = s.call(CallRequest::new("print(1)"), None).await;
    match next {
        Ok(o) => {
            assert_eq!(o.ended, Some(SessionEnd::Limit), "{:?}", o.result);
            assert_eq!(o.result.limits_hit, vec![LimitKind::Cpu]);
        }
        Err(e) => assert_eq!(e, SessionError::Ended(SessionEnd::Limit)),
    }
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
}
