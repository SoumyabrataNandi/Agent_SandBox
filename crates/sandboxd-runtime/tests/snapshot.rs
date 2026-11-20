//! C3-U3 snapshot integration tests (FR-S1, AC 3).

use std::sync::{Arc, OnceLock};

use sandboxd_audit::{EventKind, MemorySink};
use sandboxd_policy::Policy;
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

fn policy(memory: &str) -> Arc<Policy> {
    Arc::new(
        Policy::from_toml(
            &format!("version = 1\nname = \"t\"\n[limits]\nmemory = \"{memory}\"\n[env]\nTZ = \"UTC\"\nFOO = \"bar\"\n"),
            "t.toml",
        )
        .expect("policy"),
    )
}

async fn run(b: &Built, lang: Language, code: &str, args: &[&str], memory: &str) -> RunResult {
    let mut req = RunRequest::new(lang, code);
    req.args = args.iter().map(|s| s.to_string()).collect();
    b.0.execute(req, policy(memory), "t", None).await
}

fn interpreter_of(b: &Built, r: &RunResult) -> Option<String> {
    b.1.events().into_iter().find_map(|e| match e.kind {
        EventKind::RunStart { interpreter, .. } if e.run_id == Some(r.run_id) => interpreter,
        _ => None,
    })
}

const PY: &[&str] = &[
    "print(1)",
    "def f():\n    return 1 / 0\n\ndef g():\n    f()\n\ng()\n",
    "x = (\n",
    "import sys\nprint('bye')\nsys.exit(3)\n",
    "import sys\nsys.exit('fatal: message')\n",
    "import sys, os\nprint(sys.argv)\nprint(os.environ.get('FOO'), os.environ.get('TZ'), sorted(os.environ))\n",
    "import sys\nprint(__name__, __file__, '/code' in sys.path, sys.flags.isolated, sys.flags.no_site)\n",
    "import json, csv, io, statistics\nrows = list(csv.reader(io.StringIO('a,b\\n1,2\\n')))\nprint(json.dumps(rows), statistics.mean([1, 2, 3]))\n",
    "import atexit, sys\natexit.register(lambda: print('atexit ran'))\nprint('err', file=sys.stderr)\n",
    "try:\n    {}['k']\nexcept KeyError as e:\n    raise ValueError('wrapped') from e\n",
    "import numpy\n",
    "import os\nprint(sorted(os.listdir('/code')), os.listdir('/out'))\nopen('/out/r.txt', 'w').write('ok')\n",
];

const JS: &[&str] = &[
    "console.log(1);",
    "console.log(JSON.stringify(scriptArgs));",
    "function g() { throw new Error('boom'); }\ng();",
    "console.log(typeof fetch, typeof Headers, typeof std, typeof os);",
    "await Promise.resolve(); console.log('awaited');",
    "import * as std from 'qjs:std';\nconsole.log(JSON.stringify(std.getenviron()), std.getenv('FOO'));",
];

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_and_upstream_paths_are_indistinguishable() {
    let (s, u) = (snap(), upstream());
    assert!(
        s.2.snapshot_python && s.2.snapshot_javascript,
        "{:?}",
        s.2.snapshot_fallback
    );
    assert!(!u.2.snapshot_python && !u.2.snapshot_javascript);
    for (lang, programs) in [(Language::Python, PY), (Language::JavaScript, JS)] {
        for code in programs {
            let a = run(u, lang, code, &["a1", "b2"], "256MiB").await;
            let b = run(s, lang, code, &["a1", "b2"], "256MiB").await;
            assert_eq!(interpreter_of(u, &a).as_deref(), Some("upstream"));
            assert_eq!(interpreter_of(s, &b).as_deref(), Some("snapshot"));
            let show = |r: &RunResult| {
                format!(
                    "outcome {:?} exit {:?} error {:?}\nstdout {:?}\nstderr {:?}",
                    r.outcome,
                    r.exit_code,
                    r.error,
                    String::from_utf8_lossy(&r.stdout),
                    String::from_utf8_lossy(&r.stderr)
                )
            };
            assert_eq!(
                (
                    a.outcome,
                    a.exit_code,
                    &a.stdout,
                    &a.stderr,
                    a.error.as_ref().map(RunError::code)
                ),
                (
                    b.outcome,
                    b.exit_code,
                    &b.stdout,
                    &b.stderr,
                    b.error.as_ref().map(RunError::code)
                ),
                "{lang} program {code:?}\n--- upstream ---\n{}\n--- snapshot ---\n{}",
                show(&a),
                show(&b)
            );
            let names = |r: &RunResult| {
                r.artifacts
                    .iter()
                    .map(|x| x.name.clone())
                    .collect::<Vec<_>>()
            };
            assert_eq!(names(&a), names(&b), "{code:?}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_never_see_state_from_previous_runs() {
    let s = snap();
    let set = "import sys, os, random\nglobal_leak = 42\nsys.modules['leaked_mod'] = sys\nos.environ['LEAK'] = '1'\nsys.path.append('/leak')\nrandom.seed(7)\nprint(random.random())\n";
    let check = "import sys, os, random\nprint('global_leak' in globals(), 'leaked_mod' in sys.modules, 'LEAK' in os.environ, '/leak' in sys.path, random.random() == __import__('random').Random(7).random())\n";
    let a = run(s, Language::Python, set, &[], "256MiB").await;
    assert_eq!(
        a.outcome,
        Outcome::Ok,
        "{}",
        String::from_utf8_lossy(&a.stderr)
    );
    for _ in 0..3 {
        let b = run(s, Language::Python, check, &[], "256MiB").await;
        assert_eq!(
            String::from_utf8_lossy(&b.stdout).trim(),
            "False False False False False",
            "{}",
            String::from_utf8_lossy(&b.stderr)
        );
    }
    let j = run(
        s,
        Language::JavaScript,
        "globalThis.leak = 1; console.log('set');",
        &[],
        "256MiB",
    )
    .await;
    assert_eq!(j.outcome, Outcome::Ok);
    let k = run(
        s,
        Language::JavaScript,
        "console.log(typeof globalThis.leak);",
        &[],
        "256MiB",
    )
    .await;
    assert_eq!(String::from_utf8_lossy(&k.stdout).trim(), "undefined");
}

#[tokio::test(flavor = "multi_thread")]
async fn policies_below_the_memory_floor_use_the_upstream_interpreter() {
    let s = snap();
    let (py, js) = (s.2.snapshot_floor_python, s.2.snapshot_floor_javascript);
    eprintln!(
        "snapshot memory floors: python {} KiB, javascript {} KiB",
        py >> 10,
        js >> 10
    );
    assert!(py > 0 && js > 0);
    // At the floor: snapshot. Just below it: the upstream interpreter, which still runs (JS is
    // small; upstream CPython itself needs about as much memory as its snapshot).
    let at = run(
        s,
        Language::JavaScript,
        "console.log('at')",
        &[],
        &format!("{}KiB", js >> 10),
    )
    .await;
    assert_eq!(interpreter_of(s, &at).as_deref(), Some("snapshot"));
    assert_eq!(String::from_utf8_lossy(&at.stdout).trim(), "at");
    // Just below the floor the upstream interpreter is chosen. The floors equal what the upstream
    // interpreters need themselves (same initial memory), so such a run may also hit the memory
    // limit there: the floor never makes a runnable policy unrunnable.
    let below_kib = (js >> 10).saturating_sub(64);
    if below_kib >= 1024 {
        let r = run(
            s,
            Language::JavaScript,
            "console.log('below')",
            &[],
            &format!("{below_kib}KiB"),
        )
        .await;
        assert_eq!(interpreter_of(s, &r).as_deref(), Some("upstream"));
        assert!(
            matches!(r.outcome, Outcome::Ok | Outcome::Limit),
            "{:?}",
            r.outcome
        );
    }
    let r = run(
        s,
        Language::Python,
        "print('py')",
        &[],
        &format!("{}KiB", (py >> 10).saturating_sub(64)),
    )
    .await;
    assert_eq!(
        interpreter_of(s, &r).as_deref(),
        Some("upstream"),
        "below the Python floor"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn restored_runs_use_far_fewer_instructions() {
    let (s, u) = (snap(), upstream());
    let a = run(u, Language::Python, "print(1)", &[], "256MiB").await;
    let b = run(s, Language::Python, "print(1)", &[], "256MiB").await;
    let c = run(u, Language::JavaScript, "console.log(1)", &[], "256MiB").await;
    let d = run(s, Language::JavaScript, "console.log(1)", &[], "256MiB").await;
    eprintln!(
        "fuel: python upstream {} snapshot {} | javascript upstream {} snapshot {} | os {}",
        a.fuel_used,
        b.fuel_used,
        c.fuel_used,
        d.fuel_used,
        std::env::consts::OS
    );
    // Linux maps the snapshot's memory copy-on-write (no per-run cost). Windows (measured here)
    // and macOS copy the data segments on each instantiation through fuel-charged code, so there
    // the snapshot is cheaper but not by the full factor (C3-U3 finding).
    if cfg!(target_os = "linux") {
        assert!(
            b.fuel_used * 5 < a.fuel_used,
            "python {} vs {}",
            b.fuel_used,
            a.fuel_used
        );
    } else {
        assert!(
            b.fuel_used < a.fuel_used,
            "python {} vs {}",
            b.fuel_used,
            a.fuel_used
        );
    }
    assert!(
        d.fuel_used < c.fuel_used,
        "javascript {} vs {}",
        d.fuel_used,
        c.fuel_used
    );
}

#[test]
fn snapshot_mode_parses() {
    assert_eq!(SnapshotMode::parse("auto"), Some(SnapshotMode::Auto));
    assert_eq!(SnapshotMode::parse("ON"), Some(SnapshotMode::On));
    assert_eq!(SnapshotMode::parse("off"), Some(SnapshotMode::Off));
    assert_eq!(SnapshotMode::parse("perhaps"), None);
}
