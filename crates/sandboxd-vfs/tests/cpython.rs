//! End-to-end VFS tests with real CPython 3.15 (WASI) running through `RunFs` + `Interposer`.
//! The module is compiled once per test binary (several seconds).

use std::{
    io::Read,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use sandboxd_audit::{AuditEvent, Decision, EventKind, FsOp, LimitKind, MemorySink, RunId};
use sandboxd_policy::Policy;
use sandboxd_vfs::*;
use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::{WasiCtxBuilder, p1::wasi_snapshot_preview1 as p1, p2::pipe::MemoryOutputPipe};

fn engine_and_module() -> &'static (Engine, Module) {
    static M: OnceLock<(Engine, Module)> = OnceLock::new();
    M.get_or_init(|| {
        let engine = Engine::default();
        let mut zip =
            zip::ZipArchive::new(std::io::Cursor::new(sandboxd_assets::PYTHON.bytes)).expect("zip");
        let mut wasm = Vec::new();
        zip.by_name("python.wasm")
            .expect("python.wasm")
            .read_to_end(&mut wasm)
            .expect("read");
        let module = Module::new(&engine, &wasm).expect("compile python.wasm");
        (engine, module)
    })
}

struct Env {
    cfg: VfsConfig,
    data: PathBuf,
    root: PathBuf,
}

fn env(tag: &str) -> Env {
    let root = std::env::temp_dir().join(format!("sandboxd-vfs-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let data = root.join("data");
    std::fs::create_dir_all(data.join("sub")).expect("mkdir");
    std::fs::write(data.join("ref.txt"), "reference").expect("w");
    std::fs::write(data.join("sub/deep.txt"), "deep").expect("w");
    std::fs::write(root.join("outside.txt"), "HOST SECRET").expect("w");
    Env {
        cfg: VfsConfig::under(root.join("sbx")),
        data,
        root,
    }
}

fn policy(e: &Env, extra_limits: &str) -> Policy {
    let host = e.data.display().to_string().replace('\\', "/");
    Policy::from_toml(
        &format!(
            "version = 1\nname = \"t\"\n[limits]\n{extra_limits}\n[[filesystem.mount]]\nguest = \"/data\"\nhost = \"{host}\"\nmode = \"ro\"\n"
        ),
        "t.toml",
    )
    .expect("policy")
}

struct Outcome {
    stdout: String,
    stderr: String,
    report: InterposerReport,
    collected: Collected,
    events: Vec<AuditEvent>,
    run_dir: PathBuf,
}

async fn run_py(
    e: &Env,
    pol: &Policy,
    inputs: Vec<InputFile>,
    code: &str,
    vfds: VirtualFdTable,
) -> Outcome {
    let (engine, module) = engine_and_module();
    let audit = Arc::new(MemorySink::default());
    let stdlib = ensure_stdlib(&e.cfg.cache_dir, &sandboxd_assets::PYTHON).expect("stdlib");
    let fs = RunFs::create(
        &e.cfg,
        pol,
        RunId::new(),
        inputs,
        Some(&stdlib),
        audit.clone(),
    )
    .expect("runfs");
    let (out, err) = (
        MemoryOutputPipe::new(1 << 20),
        MemoryOutputPipe::new(1 << 20),
    );
    let mut b = WasiCtxBuilder::new();
    b.args(&["python", "-I", "-B", "-S", "-c", code])
        .env("PYTHONHOME", "/usr/local")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdout(out.clone())
        .stderr(err.clone());
    fs.preopen(&mut b, pol).expect("preopen");
    let interposer = fs.interposer(b.build_p1(), vfds);

    let mut linker: Linker<Interposer> = Linker::new(engine);
    p1::add_to_linker(&mut linker, |s: &mut Interposer| s).expect("link");
    let mut store = Store::new(engine, interposer);
    let inst = linker
        .instantiate_async(&mut store, module)
        .await
        .expect("instantiate");
    let start = inst
        .get_typed_func::<(), ()>(&mut store, "_start")
        .expect("_start");
    if let Err(err) = start.call_async(&mut store, ()).await {
        let code = err.downcast_ref::<wasmtime_wasi::I32Exit>().map(|c| c.0);
        assert!(code.is_some(), "guest trapped: {err:?}");
    }
    let report = store.data_mut().finish();
    let collected = fs.collect_artifacts().expect("collect");
    let run_dir = fs.run_dir().to_path_buf();
    drop(store);
    drop(fs);
    Outcome {
        stdout: String::from_utf8_lossy(&out.contents()).into_owned(),
        stderr: String::from_utf8_lossy(&err.contents()).into_owned(),
        report,
        collected,
        events: audit.events(),
        run_dir,
    }
}

fn fs_events(o: &Outcome) -> Vec<(FsOp, String, Decision, Option<String>)> {
    o.events
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::FsAccess {
                op,
                path,
                decision,
                reason,
                ..
            } => Some((*op, path.clone(), *decision, reason.clone())),
            _ => None,
        })
        .collect()
}

fn has(o: &Outcome, path: &str, d: Decision, reason_part: &str) -> bool {
    fs_events(o).iter().any(|(_, p, dd, r)| {
        p == path && *dd == d && r.as_deref().unwrap_or("").contains(reason_part)
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn functional_io_artifacts_and_audit() {
    let e = env("func");
    let pol = policy(&e, "");
    let code = r#"
import os, json, csv, pathlib
rows = list(csv.reader(open("/in/data/sales.csv")))
ref = open("/data/ref.txt").read()
deep = sorted(str(p) for p in pathlib.Path("/data").rglob("*.txt"))
os.makedirs("/out/report", exist_ok=True)
open("/out/tmp.json", "w").write(json.dumps({"rows": len(rows)}))
os.rename("/out/tmp.json", "/out/report/summary.json")
open("/out/b.txt", "w").write("bee")
print(json.dumps({"rows": rows, "ref": ref, "deep": deep, "root": os.listdir("/")}))
"#;
    let inputs = vec![InputFile {
        name: "data/sales.csv".into(),
        bytes: b"a,b\n1,2\n".to_vec(),
    }];
    let o = run_py(&e, &pol, inputs, code, VirtualFdTable::default()).await;
    assert!(o.stderr.is_empty(), "stderr: {}", o.stderr);
    assert!(
        o.stdout.trim_start().starts_with('{'),
        "not JSON: {}",
        o.stdout
    );
    assert!(
        o.stdout.contains(r#""rows": [["a", "b"], ["1", "2"]]"#),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains(r#""ref": "reference""#));
    assert!(o.stdout.contains("/data/sub/deep.txt"));
    assert!(
        o.stdout.contains(r#""root": []"#),
        "catch-all / lists as empty: {}",
        o.stdout
    );

    let names: Vec<_> = o
        .collected
        .artifacts
        .iter()
        .map(|a| a.name.as_str())
        .collect();
    assert_eq!(names, vec!["b.txt", "report/summary.json"]);
    assert_eq!(o.collected.artifacts[0].bytes, b"bee");
    assert_eq!(
        o.collected.artifacts[0].sha256,
        sandboxd_audit::sha256_hex(b"bee")
    );
    assert!(o.collected.limit_hit.is_none());

    assert!(has(&o, "/in/data/sales.csv", Decision::Allow, ""));
    assert!(has(&o, "/data/ref.txt", Decision::Allow, ""));
    // V5: stdlib reads are summarized, not logged individually.
    assert!(
        o.report.stdlib_reads > 20,
        "stdlib reads counted: {}",
        o.report.stdlib_reads
    );
    let stdlib_events: Vec<_> = fs_events(&o)
        .into_iter()
        .filter(|(_, p, _, _)| p.starts_with(STDLIB_GUEST))
        .collect();
    assert_eq!(stdlib_events.len(), 1, "{stdlib_events:?}");
    assert!(
        stdlib_events[0]
            .3
            .as_deref()
            .unwrap_or("")
            .contains("(summary)")
    );
    let denials: Vec<_> = fs_events(&o)
        .into_iter()
        .filter(|(_, _, d, _)| *d == Decision::Deny)
        .collect();
    let (summaries, individual): (Vec<_>, Vec<_>) = denials
        .into_iter()
        .partition(|(_, _, _, r)| r.as_deref().unwrap_or("").contains("(summary)"));
    assert!(
        individual.is_empty(),
        "a clean run must not produce individual denials: {individual:#?}"
    );
    assert_eq!(
        summaries.len(),
        1,
        "start-up probes are summarized once: {summaries:#?}"
    );
    assert!(
        o.report.quiet_denials >= 5,
        "probes counted: {}",
        o.report.quiet_denials
    );
    assert!(!o.run_dir.exists(), "run dir removed on drop");
    let _ = std::fs::remove_dir_all(&e.root);
}

#[tokio::test(flavor = "multi_thread")]
async fn denials_are_audited_with_final_outcome() {
    let e = env("deny");
    let pol = policy(&e, "");
    let code = r#"
import json
r = {}
for name, path, mode in [
    ("passwd", "/etc/passwd", "r"),
    ("escape", "/data/../outside.txt", "r"),
    ("deep_escape", "/data/sub/../../outside.txt", "r"),
    ("write_ro", "/data/new.txt", "w"),
    ("write_in", "/in/new.txt", "w"),
    ("device", "/dev/sandbox/http", "r"),
    ("root_create", "/evil.txt", "w"),
]:
    try:
        open(path, mode).close(); r[name] = "OPENED"
    except OSError as ex:
        r[name] = type(ex).__name__
print(json.dumps(r))
"#;
    let o = run_py(&e, &pol, vec![], code, VirtualFdTable::default()).await;
    assert!(
        !o.stdout.contains("OPENED"),
        "nothing may open: {}",
        o.stdout
    );
    assert!(
        has(&o, "/etc/passwd", Decision::Deny, "outside mounts"),
        "{:#?}",
        fs_events(&o)
    );
    assert!(has(&o, "/evil.txt", Decision::Deny, "outside mounts"));
    assert!(has(&o, "/dev/sandbox/http", Decision::Deny, "device"));
    assert!(
        fs_events(&o)
            .iter()
            .any(|(_, p, d, r)| p.contains("outside.txt")
                && *d == Decision::Deny
                && r.as_deref().unwrap_or("").contains("escapes mount"))
    );
    // V3: wasmtime's refusal (read-only preopen) is recorded as the final outcome.
    assert!(
        fs_events(&o)
            .iter()
            .any(|(_, p, d, _)| p == "/data/new.txt" && *d == Decision::Deny),
        "{:#?}",
        fs_events(&o)
    );
    assert!(
        fs_events(&o)
            .iter()
            .any(|(_, p, d, _)| p == "/in/new.txt" && *d == Decision::Deny)
    );
    assert!(!o.stdout.contains("HOST SECRET"));
    let _ = std::fs::remove_dir_all(&e.root);
}

#[tokio::test(flavor = "multi_thread")]
async fn out_byte_quota_is_enforced_live() {
    let e = env("qbytes");
    let pol = policy(&e, "artifact_bytes = \"1MiB\"");
    let code = r#"
import errno
f = open("/out/big.bin", "wb", buffering=0)
written = 0
try:
    for _ in range(64):
        written += f.write(b"x" * 65536)
    print("NO-LIMIT", written)
except OSError as ex:
    print("ENOSPC" if ex.errno == errno.ENOSPC else "OTHER", written)
"#;
    let o = run_py(&e, &pol, vec![], code, VirtualFdTable::default()).await;
    assert!(
        o.stdout.starts_with("ENOSPC"),
        "{} / {}",
        o.stdout,
        o.stderr
    );
    assert_eq!(o.report.limit_hit, Some(LimitKind::Artifacts));
    assert!(o.report.out_bytes_written <= 1 << 20);
    assert!(o.events.iter().any(|ev| matches!(
        ev.kind,
        EventKind::LimitHit {
            kind: LimitKind::Artifacts,
            ..
        }
    )));
    let _ = std::fs::remove_dir_all(&e.root);
}

#[tokio::test(flavor = "multi_thread")]
async fn out_file_count_quota_is_enforced_live() {
    let e = env("qfiles");
    let pol = policy(&e, "artifact_count = 3");
    let code = r#"
made = 0
try:
    for i in range(10):
        open(f"/out/f{i}.txt", "w").write("x"); made += 1
except OSError:
    pass
open("/out/f0.txt", "w").write("rewrite ok")  # rewriting an existing file is not a new artifact
print(made)
"#;
    let o = run_py(&e, &pol, vec![], code, VirtualFdTable::default()).await;
    assert_eq!(o.stdout.trim(), "3", "stderr: {}", o.stderr);
    assert_eq!(o.collected.artifacts.len(), 3);
    assert_eq!(o.report.limit_hit, Some(LimitKind::Artifacts));
    let _ = std::fs::remove_dir_all(&e.root);
}

/// Echo device: proves the ADR-002 seam end to end.
struct Echo(Vec<u8>);
impl VirtualDevice for Echo {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> DeviceFuture<'a, usize> {
        Box::pin(async move {
            let n = self.0.len().min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0.drain(..n);
            Ok(n)
        })
    }
    fn write<'a>(&'a mut self, buf: &'a [u8]) -> DeviceFuture<'a, usize> {
        Box::pin(async move {
            self.0.extend(buf.iter().map(u8::to_ascii_uppercase));
            Ok(buf.len())
        })
    }
    fn close(&mut self) -> DeviceFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn virtual_device_seam_works() {
    let e = env("vfd");
    let pol = policy(&e, "");
    let mut vfds = VirtualFdTable::default();
    vfds.register(
        "echo",
        Box::new(|_rel: &str| Ok(Box::new(Echo(Vec::new())) as Box<dyn VirtualDevice>)),
    );
    let code = r#"
import os
fd = os.open("/dev/sandbox/echo", os.O_RDWR)
os.write(fd, b"hello device")
print(os.read(fd, 100).decode())
os.close(fd)
"#;
    let o = run_py(&e, &pol, vec![], code, vfds).await;
    assert_eq!(o.stdout.trim(), "HELLO DEVICE", "stderr: {}", o.stderr);
    assert!(has(&o, "/dev/sandbox/echo", Decision::Allow, "device"));
    let _ = std::fs::remove_dir_all(&e.root);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn symlinks_in_out_are_skipped() {
    let e = env("symlink");
    let pol = policy(&e, "");
    let code = "import os\nopen('/out/real.txt','w').write('r')\nos.symlink('real.txt', '/out/link.txt')\nprint('ok')";
    let o = run_py(&e, &pol, vec![], code, VirtualFdTable::default()).await;
    assert_eq!(
        o.collected.artifacts.len(),
        1,
        "{:?} {}",
        o.collected,
        o.stderr
    );
    assert!(
        o.collected
            .skipped
            .iter()
            .any(|(n, why)| n == "link.txt" && why == "symlink")
    );
    let _ = std::fs::remove_dir_all(&e.root);
}

#[test]
fn input_validation_happens_before_disk() {
    let e = env("inputs");
    let pol = policy(&e, "input_bytes = \"10B\"");
    let audit: Arc<dyn sandboxd_audit::AuditSink> = Arc::new(MemorySink::default());
    let mk = |name: &str, n: usize| InputFile {
        name: name.into(),
        bytes: vec![b'x'; n],
    };
    let cases = [
        (vec![mk("../x", 1)], "invalid input"),
        (vec![mk("a.txt", 1), mk("A.TXT", 1)], "duplicate"),
        (
            vec![mk("a", 1), mk("a/b", 1)],
            "both a file and a directory",
        ),
        (vec![mk("a.txt", 11)], "exceed"),
    ];
    for (inputs, want) in cases {
        let err = RunFs::create(&e.cfg, &pol, RunId::new(), inputs, None, audit.clone())
            .expect_err("must fail");
        assert!(err.to_string().contains(want), "{err} (wanted {want:?})");
    }
    let runs = e.cfg.work_dir.join("runs");
    assert!(
        !runs.exists()
            || std::fs::read_dir(&runs)
                .map(|mut d| d.next().is_none())
                .unwrap_or(true)
    );
    let _ = std::fs::remove_dir_all(&e.root);
}
