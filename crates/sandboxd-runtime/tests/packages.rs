//! C5-U2 operator wheelhouse (FR-PK1, AC 3): pure-Python wheels importable in fresh, snapshot and
//! session runs; read-only; after the stdlib; per-policy opt-out; JavaScript unaffected.

use std::{
    io::Write,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use sandboxd_audit::{EventKind, MemorySink};
use sandboxd_policy::Policy;
use sandboxd_runtime::*;
use sandboxd_vfs::VfsConfig;

fn wheel(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default();
        for (name, content) in entries {
            z.start_file(*name, opts).expect("start");
            z.write_all(content.as_bytes()).expect("write");
        }
        z.finish().expect("finish");
    }
    buf.into_inner()
}

/// A wheelhouse with a package and a module that tries to shadow the stdlib. Created once per
/// process: the snapshot and upstream fixtures are built in parallel.
fn wheelhouse() -> PathBuf {
    static D: OnceLock<PathBuf> = OnceLock::new();
    D.get_or_init(make_wheelhouse).clone()
}

fn make_wheelhouse() -> PathBuf {
    let d = std::env::temp_dir().join(format!("sandboxd-pkg-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    std::fs::write(
        d.join("tabula_demo-1.2.0-py3-none-any.whl"),
        wheel(&[
            (
                "tabula_demo/__init__.py",
                "from .core import table\n__version__ = '1.2.0'\n",
            ),
            (
                "tabula_demo/core.py",
                "def table(rows):\n    w = max(len(str(r)) for r in rows)\n    return '\\n'.join(str(r).rjust(w) for r in rows)\n",
            ),
            ("tabula_demo-1.2.0.dist-info/METADATA", "Name: tabula-demo\nVersion: 1.2.0\n"),
        ]),
    )
    .expect("wheel");
    // `json` is in the stdlib: the wheel's copy must never win.
    std::fs::write(
        d.join("shadow-0.1-py3-none-any.whl"),
        wheel(&[("json/__init__.py", "SHADOWED = True\n")]),
    )
    .expect("wheel");
    d
}

type Built = (Sandbox, Arc<MemorySink>, WarmupReport, PathBuf);

fn build(snapshots: SnapshotMode, tag: &str) -> Built {
    let tag = tag.to_string();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let audit = Arc::new(MemorySink::default());
        let house = wheelhouse();
        // Share the compiled-module cache with the other runtime tests (it's keyed by content);
        // the package set gets its own directory under it.
        let cfg = RuntimeConfig {
            vfs: VfsConfig::under(std::env::temp_dir().join("sandboxd-runtime-tests")),
            snapshots,
            packages: Some(PackageConfig {
                dir: house.clone(),
                sha256: Default::default(),
            }),
            ..RuntimeConfig::default()
        };
        let (sb, rep) = rt
            .block_on(Sandbox::new(cfg, audit.clone()))
            .unwrap_or_else(|e| panic!("sandbox ({tag}): {e}"));
        (sb, audit, rep, house)
    })
    .join()
    .expect("thread")
}

fn snap() -> &'static Built {
    static S: OnceLock<Built> = OnceLock::new();
    S.get_or_init(|| build(SnapshotMode::On, "snapshot"))
}

fn upstream() -> &'static Built {
    static S: OnceLock<Built> = OnceLock::new();
    S.get_or_init(|| build(SnapshotMode::Off, "upstream"))
}

fn policy(extra: &str) -> Arc<Policy> {
    Arc::new(
        Policy::from_toml(
            &format!(
                "version = 1\nname = \"p\"\n[limits]\nwall_clock = \"10s\"\n[session]\nenabled = true\n{extra}"
            ),
            "p.toml",
        )
        .expect("policy"),
    )
}

async fn run(b: &Built, lang: Language, code: &str, extra: &str) -> RunResult {
    b.0.execute(RunRequest::new(lang, code), policy(extra), "alice", None)
        .await
}

fn out(r: &RunResult) -> String {
    String::from_utf8_lossy(&r.stdout).into_owned()
}

fn err(r: &RunResult) -> String {
    String::from_utf8_lossy(&r.stderr).into_owned()
}

fn interpreter(b: &Built, r: &RunResult) -> Option<String> {
    b.1.events().into_iter().find_map(|e| match e.kind {
        EventKind::RunStart { interpreter, .. } if e.run_id == Some(r.run_id) => interpreter,
        _ => None,
    })
}

const IMPORT: &str = "import tabula_demo, json\n\
print(tabula_demo.__version__)\n\
print(tabula_demo.table([1, 22, 333]))\n\
print(hasattr(json, 'SHADOWED'))\n";

async fn imports_work(b: &Built, want_interp: &str) {
    assert_eq!(b.2.packages.as_ref().map(|p| p.0), Some(2), "{:?}", b.2);
    let r = run(b, Language::Python, IMPORT, "").await;
    assert_eq!(r.exit_code, Some(0), "stderr: {}", err(&r));
    assert_eq!(
        out(&r),
        "1.2.0\n  1\n 22\n333\nFalse\n",
        "stderr: {}",
        err(&r)
    );
    assert_eq!(interpreter(b, &r).as_deref(), Some(want_interp));

    // Packages come after the stdlib on sys.path, and the helpers still work.
    let r = run(
        b,
        Language::Python,
        "import sys, tabula_demo\n\
         i = [p for p in sys.path if 'python3' in p][0]\n\
         print(sys.path.index(i) < sys.path.index('/usr/local/lib/sandboxd'))\n\
         print(tabula_demo.__file__)\n",
        "",
    )
    .await;
    assert_eq!(
        out(&r),
        "True\n/usr/local/lib/sandboxd/tabula_demo/__init__.py\n",
        "stderr: {}",
        err(&r)
    );

    // Read-only: a program can't change a package for later runs.
    let r = run(
        b,
        Language::Python,
        "import tabula_demo\n\
         try:\n    open(tabula_demo.__file__, 'a').write('X = 1')\n    print('wrote')\n\
         except OSError as e:\n    print('refused')\n",
        "",
    )
    .await;
    assert_eq!(out(&r), "refused\n", "stderr: {}", err(&r));

    // FR-PK1.5: a policy can opt out.
    let r = run(
        b,
        Language::Python,
        "import tabula_demo",
        "[python]\npackages = false\n",
    )
    .await;
    assert_eq!(r.exit_code, Some(1));
    assert!(
        err(&r).contains("No module named 'tabula_demo'"),
        "{}",
        err(&r)
    );

    // JavaScript runs are unaffected.
    let r = run(b, Language::JavaScript, "console.log(1 + 1)", "").await;
    assert_eq!(out(&r), "2\n", "stderr: {}", err(&r));
}

#[tokio::test(flavor = "multi_thread")]
async fn packages_import_on_the_snapshot_path() {
    let b = snap();
    assert!(b.2.snapshot_python, "{:?}", b.2);
    imports_work(b, "snapshot").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn packages_import_on_the_upstream_path() {
    imports_work(upstream(), "upstream").await;
}

async fn session_imports(b: &Built) {
    let s =
        b.0.open_session(SessionOptions::new(Language::Python), policy(""), "alice")
            .await
            .expect("session");
    let r = s
        .call(CallRequest::new("import tabula_demo"), None)
        .await
        .expect("call");
    assert_eq!(
        r.result.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&r.result.stderr)
    );
    let r = s
        .call(CallRequest::new("print(tabula_demo.table([5, 55]))"), None)
        .await
        .expect("call");
    assert_eq!(
        String::from_utf8_lossy(&r.result.stdout),
        " 5\n55\n",
        "{}",
        String::from_utf8_lossy(&r.result.stderr)
    );
    s.close(SessionEnd::Closed).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn packages_import_in_sessions() {
    session_imports(snap()).await;
    session_imports(upstream()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_wheel_stops_startup() {
    let d = std::env::temp_dir().join(format!("sandboxd-pkg-bad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    std::fs::write(
        d.join("speedy-1.0-py3-none-any.whl"),
        wheel(&[("speedy/_c.cpython-315-wasm32-wasi.so", "\0asm")]),
    )
    .expect("wheel");
    let cfg = RuntimeConfig {
        vfs: VfsConfig::under(std::env::temp_dir().join("sandboxd-runtime-tests")),
        snapshots: SnapshotMode::Off,
        packages: Some(PackageConfig {
            dir: d.clone(),
            sha256: Default::default(),
        }),
        ..RuntimeConfig::default()
    };
    let e = Sandbox::new(cfg, Arc::new(MemorySink::default()))
        .await
        .expect_err("refused");
    let msg = e.to_string();
    assert!(
        msg.contains("speedy-1.0-py3-none-any.whl") && msg.contains("native code"),
        "{msg}"
    );
    let _ = std::fs::remove_dir_all(&d);
}
