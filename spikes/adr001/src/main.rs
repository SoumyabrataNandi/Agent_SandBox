//! ADR-001 spike (throwaway): can we interpose on WASI p1 path/fd calls of wasmtime-wasi 50,
//! audit + deny them, and delegate the rest unchanged, while running real CPython 3.15?
//!
//! Approach "B-trait": wasmtime-wasi's wiggle-generated `add_to_linker` is generic over any
//! `U: WasiSnapshotPreview1`. We wrap `WasiP1Ctx` in `Interposer`, implement the trait by
//! delegation, and intercept the path-taking calls. No `Func` re-wrapping, no unsafe.
//!
//! Exit criteria (ADR-001): Python open()/os.listdir()/pathlib work; denied paths produce an
//! audit event; overhead < 5% on a stdlib-import benchmark.

#![allow(
    clippy::all,
    clippy::unwrap_used,
    unused,
    missing_debug_implementations
)]

use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, Instant},
};

use wasmtime::{Config, Engine, Linker, Module, Result, Store};
use wasmtime_wasi::{
    FsPerms, WasiCtxBuilder,
    p1::{
        WasiP1Ctx,
        types::{self, Errno},
        wasi_snapshot_preview1::{self as p1, WasiSnapshotPreview1},
    },
    p2::pipe::MemoryOutputPipe,
};
use wiggle::{GuestMemory, GuestPtr};

// ------------------------------------------------------------------------------------------
// Interposer
// ------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct FdInfo {
    /// Guest path of the mount root this fd lives under.
    mount: String,
    /// Normalized guest path this fd refers to.
    path: String,
}

struct Interposer {
    inner: WasiP1Ctx,
    fds: HashMap<u32, FdInfo>,
    deny_prefixes: Vec<String>,
    events: Vec<String>,
    enabled: bool,
}

/// Lexically join `rel` onto `base` within `mount`. `Err` if it climbs above the mount root.
fn resolve(mount: &str, base: &str, rel: &str) -> Result<String, String> {
    let mut parts: Vec<&str> = if rel.starts_with('/') {
        Vec::new() // absolute relative to a dirfd is not meaningful in p1; treat as rooted at "/"
    } else {
        base.split('/').filter(|s| !s.is_empty()).collect()
    };
    let floor = mount.split('/').filter(|s| !s.is_empty()).count();
    for c in rel.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                if parts.len() <= floor {
                    return Err(format!("{rel:?} escapes mount {mount}"));
                }
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

impl Interposer {
    fn check(
        &mut self,
        op: &str,
        memory: &GuestMemory<'_>,
        dirfd: types::Fd,
        path: GuestPtr<str>,
    ) -> Result<Option<(String, String)>, types::Error> {
        if !self.enabled {
            return Ok(None);
        }
        let rel = memory.as_cow_str(path)?.into_owned();
        let Some(info) = self.fds.get(&u32::from(dirfd)).cloned() else {
            // Not a directory we know (e.g. stdio or an fd opened before tracking): let wasmtime decide.
            self.events.push(format!(
                "{op} fd={} {rel:?} -> passthrough (untracked fd)",
                u32::from(dirfd)
            ));
            return Ok(None);
        };
        match resolve(&info.mount, &info.path, &rel) {
            Err(why) => {
                self.events.push(format!("DENY {op} {rel:?} ({why})"));
                Err(Errno::Notcapable.into())
            }
            Ok(full) => {
                if let Some(p) = self
                    .deny_prefixes
                    .iter()
                    .find(|p| full == **p || full.starts_with(&format!("{p}/")))
                {
                    self.events
                        .push(format!("DENY {op} {full} (policy deny {p})"));
                    return Err(Errno::Acces.into());
                }
                self.events.push(format!("ALLOW {op} {full}"));
                Ok(Some((info.mount, full)))
            }
        }
    }
}

macro_rules! check_path {
    ($s:ident, $op:literal, $mem:ident, $fd:ident, $p:ident) => {
        $s.check($op, $mem, $fd, $p)?
    };
}

impl WasiSnapshotPreview1 for Interposer {
    fn set_hostcall_fuel(&mut self, fuel: usize) {
        self.inner.set_hostcall_fuel(fuel)
    }
    fn args_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        a: GuestPtr<GuestPtr<u8>>,
        b: GuestPtr<u8>,
    ) -> Result<(), types::Error> {
        self.inner.args_get(m, a, b)
    }
    fn args_sizes_get(
        &mut self,
        m: &mut GuestMemory<'_>,
    ) -> Result<(types::Size, types::Size), types::Error> {
        self.inner.args_sizes_get(m)
    }
    fn environ_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        a: GuestPtr<GuestPtr<u8>>,
        b: GuestPtr<u8>,
    ) -> Result<(), types::Error> {
        self.inner.environ_get(m, a, b)
    }
    fn environ_sizes_get(
        &mut self,
        m: &mut GuestMemory<'_>,
    ) -> Result<(types::Size, types::Size), types::Error> {
        self.inner.environ_sizes_get(m)
    }
    fn clock_res_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        id: types::Clockid,
    ) -> Result<types::Timestamp, types::Error> {
        self.inner.clock_res_get(m, id)
    }
    fn clock_time_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        id: types::Clockid,
        p: types::Timestamp,
    ) -> Result<types::Timestamp, types::Error> {
        self.inner.clock_time_get(m, id, p)
    }
    async fn fd_advise(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        o: types::Filesize,
        l: types::Filesize,
        a: types::Advice,
    ) -> Result<(), types::Error> {
        self.inner.fd_advise(m, fd, o, l, a).await
    }
    fn fd_allocate(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        o: types::Filesize,
        l: types::Filesize,
    ) -> Result<(), types::Error> {
        self.inner.fd_allocate(m, fd, o, l)
    }
    async fn fd_close(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<(), types::Error> {
        let r = self.inner.fd_close(m, fd).await;
        if r.is_ok() {
            self.fds.remove(&u32::from(fd));
        }
        r
    }
    async fn fd_datasync(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<(), types::Error> {
        self.inner.fd_datasync(m, fd).await
    }
    async fn fd_fdstat_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<types::Fdstat, types::Error> {
        self.inner.fd_fdstat_get(m, fd).await
    }
    fn fd_fdstat_set_flags(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        f: types::Fdflags,
    ) -> Result<(), types::Error> {
        self.inner.fd_fdstat_set_flags(m, fd, f)
    }
    fn fd_fdstat_set_rights(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        a: types::Rights,
        b: types::Rights,
    ) -> Result<(), types::Error> {
        self.inner.fd_fdstat_set_rights(m, fd, a, b)
    }
    async fn fd_filestat_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<types::Filestat, types::Error> {
        self.inner.fd_filestat_get(m, fd).await
    }
    async fn fd_filestat_set_size(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        s: types::Filesize,
    ) -> Result<(), types::Error> {
        self.inner.fd_filestat_set_size(m, fd, s).await
    }
    async fn fd_filestat_set_times(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        a: types::Timestamp,
        b: types::Timestamp,
        f: types::Fstflags,
    ) -> Result<(), types::Error> {
        self.inner.fd_filestat_set_times(m, fd, a, b, f).await
    }
    async fn fd_read(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        i: types::IovecArray,
    ) -> Result<types::Size, types::Error> {
        self.inner.fd_read(m, fd, i).await
    }
    async fn fd_pread(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        i: types::IovecArray,
        o: types::Filesize,
    ) -> Result<types::Size, types::Error> {
        self.inner.fd_pread(m, fd, i, o).await
    }
    async fn fd_write(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        c: types::CiovecArray,
    ) -> Result<types::Size, types::Error> {
        self.inner.fd_write(m, fd, c).await
    }
    async fn fd_pwrite(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        c: types::CiovecArray,
        o: types::Filesize,
    ) -> Result<types::Size, types::Error> {
        self.inner.fd_pwrite(m, fd, c, o).await
    }
    fn fd_prestat_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<types::Prestat, types::Error> {
        self.inner.fd_prestat_get(m, fd)
    }
    fn fd_prestat_dir_name(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        p: GuestPtr<u8>,
        l: types::Size,
    ) -> Result<(), types::Error> {
        self.inner.fd_prestat_dir_name(m, fd, p, l)
    }
    async fn fd_renumber(
        &mut self,
        m: &mut GuestMemory<'_>,
        from: types::Fd,
        to: types::Fd,
    ) -> Result<(), types::Error> {
        let r = self.inner.fd_renumber(m, from, to).await;
        if r.is_ok() {
            if let Some(i) = self.fds.remove(&u32::from(from)) {
                self.fds.insert(u32::from(to), i);
            } else {
                self.fds.remove(&u32::from(to));
            }
        }
        r
    }
    async fn fd_seek(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        o: types::Filedelta,
        w: types::Whence,
    ) -> Result<types::Filesize, types::Error> {
        self.inner.fd_seek(m, fd, o, w).await
    }
    async fn fd_sync(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<(), types::Error> {
        self.inner.fd_sync(m, fd).await
    }
    fn fd_tell(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<types::Filesize, types::Error> {
        self.inner.fd_tell(m, fd)
    }
    async fn fd_readdir(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        b: GuestPtr<u8>,
        l: types::Size,
        c: types::Dircookie,
    ) -> Result<types::Size, types::Error> {
        self.inner.fd_readdir(m, fd, b, l, c).await
    }

    async fn path_create_directory(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        p: GuestPtr<str>,
    ) -> Result<(), types::Error> {
        check_path!(self, "mkdir", m, fd, p);
        self.inner.path_create_directory(m, fd, p).await
    }
    async fn path_filestat_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        f: types::Lookupflags,
        p: GuestPtr<str>,
    ) -> Result<types::Filestat, types::Error> {
        check_path!(self, "stat", m, fd, p);
        self.inner.path_filestat_get(m, fd, f, p).await
    }
    async fn path_filestat_set_times(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        f: types::Lookupflags,
        p: GuestPtr<str>,
        a: types::Timestamp,
        b: types::Timestamp,
        s: types::Fstflags,
    ) -> Result<(), types::Error> {
        check_path!(self, "set_times", m, fd, p);
        self.inner
            .path_filestat_set_times(m, fd, f, p, a, b, s)
            .await
    }
    async fn path_link(
        &mut self,
        m: &mut GuestMemory<'_>,
        sfd: types::Fd,
        sf: types::Lookupflags,
        sp: GuestPtr<str>,
        tfd: types::Fd,
        tp: GuestPtr<str>,
    ) -> Result<(), types::Error> {
        check_path!(self, "link_src", m, sfd, sp);
        check_path!(self, "link_dst", m, tfd, tp);
        self.inner.path_link(m, sfd, sf, sp, tfd, tp).await
    }
    async fn path_open(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        df: types::Lookupflags,
        p: GuestPtr<str>,
        of: types::Oflags,
        rb: types::Rights,
        ri: types::Rights,
        ff: types::Fdflags,
    ) -> Result<types::Fd, types::Error> {
        let seen = check_path!(self, "open", m, fd, p);
        let new_fd = self.inner.path_open(m, fd, df, p, of, rb, ri, ff).await?;
        if let Some((mount, path)) = seen {
            self.fds.insert(u32::from(new_fd), FdInfo { mount, path });
        }
        Ok(new_fd)
    }
    async fn path_readlink(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        p: GuestPtr<str>,
        b: GuestPtr<u8>,
        l: types::Size,
    ) -> Result<types::Size, types::Error> {
        check_path!(self, "readlink", m, fd, p);
        self.inner.path_readlink(m, fd, p, b, l).await
    }
    async fn path_remove_directory(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        p: GuestPtr<str>,
    ) -> Result<(), types::Error> {
        check_path!(self, "rmdir", m, fd, p);
        self.inner.path_remove_directory(m, fd, p).await
    }
    async fn path_rename(
        &mut self,
        m: &mut GuestMemory<'_>,
        sfd: types::Fd,
        sp: GuestPtr<str>,
        dfd: types::Fd,
        dp: GuestPtr<str>,
    ) -> Result<(), types::Error> {
        check_path!(self, "rename_src", m, sfd, sp);
        check_path!(self, "rename_dst", m, dfd, dp);
        self.inner.path_rename(m, sfd, sp, dfd, dp).await
    }
    async fn path_symlink(
        &mut self,
        m: &mut GuestMemory<'_>,
        sp: GuestPtr<str>,
        fd: types::Fd,
        dp: GuestPtr<str>,
    ) -> Result<(), types::Error> {
        // The link *target* text is not a path we open; only the new link location is checked.
        check_path!(self, "symlink", m, fd, dp);
        self.inner.path_symlink(m, sp, fd, dp).await
    }
    async fn path_unlink_file(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        p: GuestPtr<str>,
    ) -> Result<(), types::Error> {
        check_path!(self, "unlink", m, fd, p);
        self.inner.path_unlink_file(m, fd, p).await
    }
    async fn poll_oneoff(
        &mut self,
        m: &mut GuestMemory<'_>,
        s: GuestPtr<types::Subscription>,
        e: GuestPtr<types::Event>,
        n: types::Size,
    ) -> Result<types::Size, types::Error> {
        self.inner.poll_oneoff(m, s, e, n).await
    }
    fn proc_exit(&mut self, m: &mut GuestMemory<'_>, status: types::Exitcode) -> wasmtime::Error {
        self.inner.proc_exit(m, status)
    }
    fn proc_raise(
        &mut self,
        m: &mut GuestMemory<'_>,
        s: types::Signal,
    ) -> Result<(), types::Error> {
        self.inner.proc_raise(m, s)
    }
    fn sched_yield(&mut self, m: &mut GuestMemory<'_>) -> Result<(), types::Error> {
        self.inner.sched_yield(m)
    }
    fn random_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        b: GuestPtr<u8>,
        l: types::Size,
    ) -> Result<(), types::Error> {
        self.inner.random_get(m, b, l)
    }
    fn sock_accept(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        f: types::Fdflags,
    ) -> Result<types::Fd, types::Error> {
        self.inner.sock_accept(m, fd, f)
    }
    fn sock_recv(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        d: types::IovecArray,
        f: types::Riflags,
    ) -> Result<(types::Size, types::Roflags), types::Error> {
        self.inner.sock_recv(m, fd, d, f)
    }
    fn sock_send(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        d: types::CiovecArray,
        f: types::Siflags,
    ) -> Result<types::Size, types::Error> {
        self.inner.sock_send(m, fd, d, f)
    }
    fn sock_shutdown(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        h: types::Sdflags,
    ) -> Result<(), types::Error> {
        self.inner.sock_shutdown(m, fd, h)
    }
}

// ------------------------------------------------------------------------------------------
// Harness
// ------------------------------------------------------------------------------------------

struct Dirs {
    stdlib: PathBuf,
    data: PathBuf,
    out: PathBuf,
}

fn prepare() -> Result<(Vec<u8>, Dirs)> {
    let root = std::env::temp_dir().join("sandboxd-spike-adr001");
    let py = root.join("python");
    let mut wasm = Vec::new();
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(sandboxd_assets::PYTHON.bytes))?;
    if !py.join("lib/python3.15/os.py").exists() {
        zip.extract(&py)?;
    }
    std::io::Read::read_to_end(&mut zip.by_name("python.wasm")?, &mut wasm)?;

    let data = root.join("data");
    let out = root.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(data.join("secret"))?;
    std::fs::create_dir_all(data.join("sub"))?;
    std::fs::create_dir_all(&out)?;
    std::fs::write(data.join("input.csv"), "a,b\n1,2\n3,4\n")?;
    std::fs::write(data.join("sub/nested.txt"), "nested")?;
    std::fs::write(data.join("secret/key.txt"), "TOP-SECRET")?;
    std::fs::write(root.join("outside.txt"), "HOST FILE OUTSIDE MOUNTS")?;
    Ok((
        wasm,
        Dirs {
            stdlib: py.join("lib/python3.15"),
            data,
            out,
        },
    ))
}

const GUEST: &str = r#"
import os, pathlib, csv, json
r = {}
def t(name, fn):
    try:
        r[name] = ("ok", fn())
    except Exception as e:
        r[name] = ("err", type(e).__name__ + ": " + str(e)[:60])
t("read_csv", lambda: list(csv.reader(open("/data/input.csv"))))
t("listdir", lambda: sorted(os.listdir("/data")))
t("pathlib_glob", lambda: sorted(str(p) for p in pathlib.Path("/data").rglob("*.txt") if "secret" not in str(p)))
t("nested", lambda: open("/data/sub/nested.txt").read())
t("secret_denied", lambda: open("/data/secret/key.txt").read())
t("secret_via_dotdot", lambda: open("/data/sub/../secret/key.txt").read())
t("escape_dotdot", lambda: open("/data/../outside.txt").read())
t("escape_deep", lambda: open("/data/sub/../../../../outside.txt").read())
t("etc_passwd", lambda: open("/etc/passwd").read())
t("write_ro", lambda: open("/data/new.txt", "w").write("x"))
t("write_out", lambda: open("/out/result.json", "w").write(json.dumps({"ok": True})))
t("mkdir_out", lambda: os.makedirs("/out/a/b", exist_ok=True))
t("rename_out", lambda: os.rename("/out/result.json", "/out/a/result.json"))
t("stdlib_listing", lambda: "os.py" in os.listdir("/usr/local/lib/python3.15"))
print(json.dumps(r, indent=1))
"#;

const BENCH: &str = "import json, csv, decimal, email.message, pathlib, collections, datetime, re, statistics, textwrap\nprint('bench-ok')";

async fn run(
    engine: &Engine,
    module: &Module,
    dirs: &Dirs,
    code: &str,
    interpose: bool,
) -> Result<(String, String, Vec<String>, Duration)> {
    let stdout = MemoryOutputPipe::new(1 << 20);
    let stderr = MemoryOutputPipe::new(1 << 20);
    let mut b = WasiCtxBuilder::new();
    b.args(&["python", "-S", "-c", code])
        .env("PYTHONHOME", "/usr/local")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .stdout(stdout.clone())
        .stderr(stderr.clone())
        .preopened_dir(&dirs.stdlib, "/usr/local/lib/python3.15", FsPerms::ReadOnly)?
        .preopened_dir(&dirs.data, "/data", FsPerms::ReadOnly)?
        .preopened_dir(&dirs.out, "/out", FsPerms::ReadWrite)?;
    let inner = b.build_p1();
    // wasmtime-wasi numbers preopens from fd 3 in insertion order.
    let fds = HashMap::from([
        (
            3,
            FdInfo {
                mount: "/usr/local/lib/python3.15".into(),
                path: "/usr/local/lib/python3.15".into(),
            },
        ),
        (
            4,
            FdInfo {
                mount: "/data".into(),
                path: "/data".into(),
            },
        ),
        (
            5,
            FdInfo {
                mount: "/out".into(),
                path: "/out".into(),
            },
        ),
    ]);
    let state = Interposer {
        inner,
        fds,
        deny_prefixes: vec!["/data/secret".into()],
        events: Vec::new(),
        enabled: interpose,
    };

    let mut linker: Linker<Interposer> = Linker::new(engine);
    p1::add_to_linker(&mut linker, |s: &mut Interposer| s)?;
    let mut store = Store::new(engine, state);
    let t0 = Instant::now();
    let instance = linker.instantiate_async(&mut store, module).await?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    let res = start.call_async(&mut store, ()).await;
    let elapsed = t0.elapsed();
    if let Err(e) = res {
        // proc_exit(0) surfaces as an I32Exit error; anything else is a real failure.
        if let Some(code) = e.downcast_ref::<wasmtime_wasi::I32Exit>() {
            if code.0 != 0 {
                eprintln!("guest exited {}", code.0);
            }
        } else {
            return Err(e);
        }
    }
    let out = String::from_utf8_lossy(&stdout.contents()).into_owned();
    let err = String::from_utf8_lossy(&stderr.contents()).into_owned();
    Ok((
        out,
        err,
        std::mem::take(&mut store.data_mut().events),
        elapsed,
    ))
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

#[tokio::main]
async fn main() -> Result<()> {
    let (wasm, dirs) = prepare()?;
    let mut cfg = Config::new();
    let engine = Engine::new(&cfg)?;
    let t = Instant::now();
    let module = Module::new(&engine, &wasm)?;
    println!("compile python.wasm: {:?}", t.elapsed());

    println!("\n=== functional run (interposer ON) ===");
    let (out, err, events, dur) = run(&engine, &module, &dirs, GUEST, true).await?;
    println!("{out}");
    if !err.trim().is_empty() {
        println!("stderr:\n{err}");
    }
    println!("run time: {dur:?}");
    println!("\n--- interposer events (non-stdlib) ---");
    for e in events
        .iter()
        .filter(|e| !e.contains("/usr/local/lib/python3.15"))
    {
        println!("  {e}");
    }
    println!(
        "  ({} events total, {} on stdlib paths)",
        events.len(),
        events
            .iter()
            .filter(|e| e.contains("/usr/local/lib/python3.15"))
            .count()
    );
    let host_out = dirs.out.join("a/result.json");
    println!(
        "host sees /out/a/result.json: {:?}",
        std::fs::read_to_string(&host_out).ok()
    );

    println!("\n=== overhead benchmark (stdlib imports) ===");
    let n = 7;
    let mut on = Vec::new();
    let mut off = Vec::new();
    for _ in 0..n {
        off.push(run(&engine, &module, &dirs, BENCH, false).await?.3);
        on.push(run(&engine, &module, &dirs, BENCH, true).await?.3);
    }
    let (m_off, m_on) = (median(off), median(on));
    let pct = (m_on.as_secs_f64() / m_off.as_secs_f64() - 1.0) * 100.0;
    println!("median interposer OFF: {m_off:?}");
    println!("median interposer ON : {m_on:?}");
    println!("overhead: {pct:+.2}%  (exit criterion < 5%)");
    Ok(())
}
