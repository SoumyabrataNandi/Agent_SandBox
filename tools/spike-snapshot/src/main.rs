//! C3-U1 snapshot spike (cycle 3, FR-S1.0). Runs in CI only, after `interpreters/build.sh`.
//!
//! For each language it:
//! 1. pre-initialises the custom reactor module with `wasmtime-wizer` (empty env; stdlib and
//!    helpers preopened read-only at their guest paths, as sandboxd would);
//! 2. runs a set of compatibility programs on the **upstream** module (today's launch line) and
//!    on the **snapshot** (`sandboxd-run`), and compares stdout, stderr and exit code byte for byte;
//! 3. measures instantiate+run time and fuel for `print(1)` / `console.log(1)` on both.
//!
//! It writes a JSON report and always exits 0, so the CI job can publish the report. The verdict
//! is the report's `go` field (AC 2: Python compatible and ≥ 5× faster).
//!
//! Usage: spike-snapshot --out report.json --stdlib <lib/python3.15> --helpers <dir>
//!          --upstream-python <python.wasm> [--custom-python <sandboxd-python.wasm>]
//!          [--upstream-qjs <qjs-wasi.wasm>] [--custom-qjs <sandboxd-qjs.wasm>]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Instant,
};

use serde_json::{Value, json};
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::{FsPerms, I32Exit, WasiCtxBuilder, p1::WasiP1Ctx, p2::pipe::MemoryOutputPipe};

type Res<T> = Result<T, String>;

const STDLIB_GUEST: &str = "/usr/local/lib/python3.15";
const HELPERS_GUEST: &str = "/usr/local/lib/sandboxd";
const ITERATIONS: usize = 20;

struct Ctx {
    engine: Engine,
    stdlib: PathBuf,
    helpers: PathBuf,
    work: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
struct Outcome {
    stdout: String,
    stderr: String,
    exit: i32,
    fuel: u64,
}

fn engine() -> Res<Engine> {
    let mut c = Config::new();
    c.consume_fuel(true)
        .max_wasm_stack(1 << 20)
        .async_stack_size(4 << 20);
    Engine::new(&c).map_err(|e| e.to_string())
}

fn linker(engine: &Engine) -> Res<Linker<WasiP1Ctx>> {
    let mut l = Linker::new(engine);
    wasmtime_wasi::p1::add_to_linker_async(&mut l, |c| c).map_err(|e| e.to_string())?;
    Ok(l)
}

/// One run: fresh store, given argv/env/mounts, call `entry`.
async fn run(
    cx: &Ctx,
    module: &Module,
    entry: &str,
    argv: &[&str],
    env: &[(&str, &str)],
    mounts: &[(&Path, &str)],
) -> Res<Outcome> {
    let out = MemoryOutputPipe::new(1 << 20);
    let err = MemoryOutputPipe::new(1 << 20);
    let mut b = WasiCtxBuilder::new();
    b.args(argv)
        .envs(env)
        .stdout(out.clone())
        .stderr(err.clone());
    for (host, guest) in mounts {
        b.preopened_dir(host, guest, FsPerms::ReadOnly)
            .map_err(|e| format!("preopen {guest}: {e}"))?;
    }
    let mut store = Store::new(&cx.engine, b.build_p1());
    store.set_fuel(u64::MAX / 2).map_err(|e| e.to_string())?;
    let inst = linker(&cx.engine)?
        .instantiate_async(&mut store, module)
        .await
        .map_err(|e| format!("instantiate: {e}"))?;
    let f = inst
        .get_typed_func::<(), ()>(&mut store, entry)
        .map_err(|e| format!("export {entry}: {e}"))?;
    let exit = match f.call_async(&mut store, ()).await {
        Ok(()) => 0,
        Err(e) => match e.downcast_ref::<I32Exit>() {
            Some(c) => c.0,
            None => return Err(format!("trap: {e:?}")),
        },
    };
    let fuel = (u64::MAX / 2).saturating_sub(store.get_fuel().unwrap_or(0));
    drop(store);
    Ok(Outcome {
        stdout: String::from_utf8_lossy(&out.contents()).into_owned(),
        stderr: String::from_utf8_lossy(&err.contents()).into_owned(),
        exit,
        fuel,
    })
}

/// Pre-initialise `wasm` with Wizer, using the same read-only mounts sandboxd would provide.
async fn snapshot(cx: &Ctx, wasm: &[u8], argv0: &str) -> Res<Vec<u8>> {
    let mut b = WasiCtxBuilder::new();
    b.args(&[argv0]);
    b.preopened_dir(&cx.stdlib, STDLIB_GUEST, FsPerms::ReadOnly)
        .map_err(|e| e.to_string())?;
    b.preopened_dir(&cx.helpers, HELPERS_GUEST, FsPerms::ReadOnly)
        .map_err(|e| e.to_string())?;
    let mut store = Store::new(&cx.engine, b.build_p1());
    store.set_fuel(u64::MAX / 2).map_err(|e| e.to_string())?;
    let l = linker(&cx.engine)?;
    wasmtime_wizer::Wizer::new()
        .init_func("wizer-initialize")
        .run(&mut store, wasm, async |store, module| {
            l.instantiate_async(store, module).await
        })
        .await
        .map_err(|e| format!("wizer: {e:?}"))
}

fn code_dir(cx: &Ctx, name: &str, file: &str, code: &str) -> Res<PathBuf> {
    let d = cx.work.join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    std::fs::write(d.join(file), code).map_err(|e| e.to_string())?;
    Ok(d)
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.total_cmp(b));
    v[v.len() / 2]
}

const PY_PROGRAMS: &[(&str, &str)] = &[
    ("print", "print(1)\n"),
    (
        "traceback",
        "def f():\n    return 1 / 0\n\ndef g():\n    f()\n\ng()\n",
    ),
    ("syntax-error", "x = (\n"),
    ("sys-exit", "import sys\nprint('bye')\nsys.exit(3)\n"),
    (
        "argv-env",
        "import sys, os\nprint(sys.argv)\nprint(os.environ.get('FOO'), os.environ.get('TZ'), sorted(os.environ))\nprint(os.environb.get(b'FOO'))\n",
    ),
    (
        "main-module",
        "import sys\nprint(__name__, __file__, '/code' in sys.path, sys.flags.isolated, sys.flags.no_site, sys.dont_write_bytecode)\n",
    ),
    (
        "workload",
        "import json, csv, io, statistics, datetime, re\nrows = list(csv.reader(io.StringIO('a,b\\n1,2\\n3,4\\n')))\nprint(json.dumps({'rows': rows, 'mean': statistics.mean([1, 2, 3])}), re.sub(r'\\d', '#', 'a1b2'), datetime.date(2026, 1, 2).isoformat())\n",
    ),
    (
        "atexit-and-stderr",
        "import atexit, sys\natexit.register(lambda: print('atexit ran'))\nprint('to stderr', file=sys.stderr)\n",
    ),
    (
        "chained",
        "try:\n    {}['k']\nexcept KeyError as e:\n    raise ValueError('wrapped') from e\n",
    ),
    (
        "files",
        "import os\nprint(sorted(os.listdir('/code')))\nprint(open('/code/main.py').read().splitlines()[0])\n",
    ),
];

const JS_PROGRAMS: &[(&str, &str)] = &[
    ("print", "console.log(1);\n"),
    ("args", "console.log(JSON.stringify(scriptArgs));\n"),
    ("throw", "function g() { throw new Error('boom'); }\ng();\n"),
    (
        "globals",
        "console.log(typeof fetch, typeof Headers, typeof std, typeof os);\n",
    ),
    (
        "async",
        "await Promise.resolve();\nconsole.log('after await');\n",
    ),
];

async fn python(cx: &Ctx, upstream: &Path, custom: Option<&Path>) -> Value {
    let up_bytes = match std::fs::read(upstream) {
        Ok(b) => b,
        Err(e) => return json!({"error": format!("read upstream: {e}")}),
    };
    let up = match Module::new(&cx.engine, &up_bytes) {
        Ok(m) => m,
        Err(e) => return json!({"error": format!("compile upstream: {e}")}),
    };
    let Some(custom) = custom else {
        return json!({"error": "custom python module missing (build failed?)"});
    };
    let custom_bytes = match std::fs::read(custom) {
        Ok(b) => b,
        Err(e) => return json!({"error": format!("read custom: {e}")}),
    };
    let t = Instant::now();
    let snap = match snapshot(cx, &custom_bytes, "python").await {
        Ok(s) => s,
        Err(e) => return json!({"error": e}),
    };
    let snapshot_ms = t.elapsed().as_secs_f64() * 1e3;
    let snap_mod = match Module::new(&cx.engine, &snap) {
        Ok(m) => m,
        Err(e) => return json!({"error": format!("compile snapshot: {e}")}),
    };
    let env = [("TZ", "UTC"), ("FOO", "bar")];
    let mut compat = Vec::new();
    let mut all_equal = true;
    for (name, code) in PY_PROGRAMS {
        let dir = match code_dir(cx, &format!("py-{name}"), "main.py", code) {
            Ok(d) => d,
            Err(e) => return json!({"error": e}),
        };
        let up_mounts = [
            (cx.stdlib.as_path(), STDLIB_GUEST),
            (dir.as_path(), "/code"),
        ];
        let sn_mounts = [
            (cx.stdlib.as_path(), STDLIB_GUEST),
            (cx.helpers.as_path(), HELPERS_GUEST),
            (dir.as_path(), "/code"),
        ];
        let a = run(
            cx,
            &up,
            "_start",
            &[
                "python",
                "-I",
                "-B",
                "-S",
                "-X",
                "frozen_modules=on",
                "/code/main.py",
                "a1",
                "b2",
            ],
            &env,
            &up_mounts,
        )
        .await;
        let b = run(
            cx,
            &snap_mod,
            "sandboxd-run",
            &["python", "/code/main.py", "a1", "b2"],
            &env,
            &sn_mounts,
        )
        .await;
        let equal = match (&a, &b) {
            (Ok(x), Ok(y)) => x.stdout == y.stdout && x.stderr == y.stderr && x.exit == y.exit,
            _ => false,
        };
        all_equal &= equal;
        compat.push(json!({
            "name": name, "equal": equal,
            "upstream": outcome_json(&a), "snapshot": outcome_json(&b),
        }));
    }
    // random must differ between two snapshot runs (re-seeded per run).
    let rdir = code_dir(
        cx,
        "py-random",
        "main.py",
        "import random\nprint(random.random())\n",
    )
    .unwrap_or_default();
    let mounts = [
        (cx.stdlib.as_path(), STDLIB_GUEST),
        (cx.helpers.as_path(), HELPERS_GUEST),
        (rdir.as_path(), "/code"),
    ];
    let r1 = run(
        cx,
        &snap_mod,
        "sandboxd-run",
        &["python", "/code/main.py"],
        &[],
        &mounts,
    )
    .await;
    let r2 = run(
        cx,
        &snap_mod,
        "sandboxd-run",
        &["python", "/code/main.py"],
        &[],
        &mounts,
    )
    .await;
    let random_differs =
        matches!((&r1, &r2), (Ok(a), Ok(b)) if a.stdout != b.stdout && !a.stdout.is_empty());

    let (up_ms, up_fuel) = timing(cx, &up, "_start", true).await;
    let (sn_ms, sn_fuel) = timing(cx, &snap_mod, "sandboxd-run", false).await;
    let speedup = if sn_ms > 0.0 { up_ms / sn_ms } else { 0.0 };
    json!({
        "compat_all_equal": all_equal,
        "random_differs": random_differs,
        "upstream_print_ms_median": up_ms, "snapshot_print_ms_median": sn_ms,
        "speedup": speedup,
        "upstream_print_fuel": up_fuel, "snapshot_print_fuel": sn_fuel,
        "custom_module_bytes": custom_bytes.len(), "snapshot_module_bytes": snap.len(),
        "snapshot_build_ms": snapshot_ms,
        "compat": compat,
        "go": all_equal && random_differs && speedup >= 5.0,
    })
}

async fn timing(cx: &Ctx, m: &Module, entry: &str, upstream: bool) -> (f64, u64) {
    let Ok(dir) = code_dir(cx, "py-timing", "main.py", "print(1)\n") else {
        return (0.0, 0);
    };
    let mounts_up = [
        (cx.stdlib.as_path(), STDLIB_GUEST),
        (dir.as_path(), "/code"),
    ];
    let mounts_sn = [
        (cx.stdlib.as_path(), STDLIB_GUEST),
        (cx.helpers.as_path(), HELPERS_GUEST),
        (dir.as_path(), "/code"),
    ];
    let argv_up = [
        "python",
        "-I",
        "-B",
        "-S",
        "-X",
        "frozen_modules=on",
        "/code/main.py",
    ];
    let argv_sn = ["python", "/code/main.py"];
    let mut v = Vec::new();
    let mut fuel = 0;
    for _ in 0..ITERATIONS {
        let t = Instant::now();
        let r = if upstream {
            run(cx, m, entry, &argv_up, &[], &mounts_up).await
        } else {
            run(cx, m, entry, &argv_sn, &[], &mounts_sn).await
        };
        v.push(t.elapsed().as_secs_f64() * 1e3);
        if let Ok(o) = r {
            fuel = o.fuel;
        }
    }
    (median(v), fuel)
}

async fn javascript(cx: &Ctx, upstream: Option<&Path>, custom: Option<&Path>) -> Value {
    let (Some(upstream), Some(custom)) = (upstream, custom) else {
        return json!({"error": "upstream or custom qjs module missing (build failed?)"});
    };
    let (Ok(up_bytes), Ok(custom_bytes)) = (std::fs::read(upstream), std::fs::read(custom)) else {
        return json!({"error": "cannot read qjs modules"});
    };
    let Ok(up) = Module::new(&cx.engine, &up_bytes) else {
        return json!({"error": "compile upstream qjs"});
    };
    let snap = match snapshot(cx, &custom_bytes, "qjs").await {
        Ok(s) => s,
        Err(e) => return json!({"error": e}),
    };
    let Ok(snap_mod) = Module::new(&cx.engine, &snap) else {
        return json!({"error": "compile qjs snapshot"});
    };
    let mut compat = Vec::new();
    let mut all_equal = true;
    for (name, code) in JS_PROGRAMS {
        let Ok(dir) = code_dir(cx, &format!("js-{name}"), "main.mjs", code) else {
            return json!({"error": "code dir"});
        };
        let up_mounts = [
            (cx.helpers.as_path(), HELPERS_GUEST),
            (dir.as_path(), "/code"),
        ];
        let a = run(
            cx,
            &up,
            "_start",
            &[
                "qjs",
                "--std",
                "-m",
                "-I",
                "/usr/local/lib/sandboxd/boot.js",
                "/code/main.mjs",
                "x",
            ],
            &[],
            &up_mounts,
        )
        .await;
        let b = run(
            cx,
            &snap_mod,
            "sandboxd-run",
            &["qjs", "/code/main.mjs", "x"],
            &[],
            &up_mounts,
        )
        .await;
        let equal = match (&a, &b) {
            (Ok(x), Ok(y)) => x.stdout == y.stdout && x.stderr == y.stderr && x.exit == y.exit,
            _ => false,
        };
        all_equal &= equal;
        compat.push(json!({"name": name, "equal": equal, "upstream": outcome_json(&a), "snapshot": outcome_json(&b)}));
    }
    let Ok(dir) = code_dir(cx, "js-timing", "main.mjs", "console.log(1);\n") else {
        return json!({"error": "code dir"});
    };
    let mounts = [
        (cx.helpers.as_path(), HELPERS_GUEST),
        (dir.as_path(), "/code"),
    ];
    let mut tu = Vec::new();
    let mut ts = Vec::new();
    let (mut fu, mut fs) = (0, 0);
    for _ in 0..ITERATIONS {
        let t = Instant::now();
        if let Ok(o) = run(
            cx,
            &up,
            "_start",
            &[
                "qjs",
                "--std",
                "-m",
                "-I",
                "/usr/local/lib/sandboxd/boot.js",
                "/code/main.mjs",
            ],
            &[],
            &mounts,
        )
        .await
        {
            fu = o.fuel;
        }
        tu.push(t.elapsed().as_secs_f64() * 1e3);
        let t = Instant::now();
        if let Ok(o) = run(
            cx,
            &snap_mod,
            "sandboxd-run",
            &["qjs", "/code/main.mjs"],
            &[],
            &mounts,
        )
        .await
        {
            fs = o.fuel;
        }
        ts.push(t.elapsed().as_secs_f64() * 1e3);
    }
    let (um, sm) = (median(tu), median(ts));
    json!({
        "compat_all_equal": all_equal,
        "upstream_print_ms_median": um, "snapshot_print_ms_median": sm,
        "speedup": if sm > 0.0 { um / sm } else { 0.0 },
        "upstream_print_fuel": fu, "snapshot_print_fuel": fs,
        "snapshot_module_bytes": snap.len(),
        "compat": compat,
    })
}

fn outcome_json(o: &Res<Outcome>) -> Value {
    match o {
        Ok(o) => json!({"stdout": o.stdout, "stderr": o.stderr, "exit": o.exit, "fuel": o.fuel}),
        Err(e) => json!({"error": e}),
    }
}

fn main() {
    let mut args: BTreeMap<String, String> = BTreeMap::new();
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        if let Some(v) = it.next() {
            args.insert(k.trim_start_matches("--").to_string(), v);
        }
    }
    let path = |k: &str| args.get(k).map(PathBuf::from).filter(|p| p.exists());
    let out = args
        .get("out")
        .cloned()
        .unwrap_or_else(|| "spike-report.json".into());
    let rt = tokio::runtime::Runtime::new().expect("tokio");
    let report = rt.block_on(async {
        let (Some(stdlib), Some(helpers), Some(up_py)) =
            (path("stdlib"), path("helpers"), path("upstream-python"))
        else {
            return json!({"error": "need --stdlib, --helpers and --upstream-python"});
        };
        let cx = match engine() {
            Ok(engine) => Ctx {
                engine,
                stdlib,
                helpers,
                work: std::env::temp_dir().join("spike-snapshot"),
            },
            Err(e) => return json!({"error": e}),
        };
        let py = python(&cx, &up_py, path("custom-python").as_deref()).await;
        let js = javascript(
            &cx,
            path("upstream-qjs").as_deref(),
            path("custom-qjs").as_deref(),
        )
        .await;
        let go = py.get("go").and_then(Value::as_bool).unwrap_or(false);
        json!({"python": py, "javascript": js, "go": go})
    });
    let text = serde_json::to_string_pretty(&report).unwrap_or_default();
    if let Err(e) = std::fs::write(&out, &text) {
        eprintln!("write {out}: {e}");
    }
    println!("{text}");
}
