//! Compiled-module cache (U4 design §2, Q1) and stdlib bytecode provisioning (Q2).

use std::{
    hash::{Hash, Hasher},
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use wasmtime::{Engine, Module};

use crate::error::RuntimeError;

/// Loads `<cache>/modules/<key>.cwasm` after verifying it, or compiles and stores it.
pub(crate) struct ModuleCache {
    dir: PathBuf,
    compat: u64,
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default()
}

impl ModuleCache {
    pub(crate) fn new(cache_dir: &Path, engine: &Engine) -> Result<Self, RuntimeError> {
        let dir = cache_dir.join("modules");
        create_private_dir(&dir)?;
        let mut h = std::collections::hash_map::DefaultHasher::new();
        engine.precompile_compatibility_hash().hash(&mut h);
        env!("CARGO_PKG_VERSION").hash(&mut h);
        Ok(Self {
            dir,
            compat: h.finish(),
        })
    }

    /// `asset_sha` identifies the source bytes; `wasm` is only invoked on a miss.
    pub(crate) fn load_or_compile(
        &self,
        engine: &Engine,
        name: &str,
        asset_sha: &str,
        wasm: impl FnOnce() -> Result<Vec<u8>, RuntimeError>,
    ) -> Result<(Module, bool), RuntimeError> {
        let key = format!(
            "{name}-{}-{:016x}",
            &asset_sha[..16.min(asset_sha.len())],
            self.compat
        );
        let file = self.dir.join(format!("{key}.cwasm"));
        let sidecar = self.dir.join(format!("{key}.sha256"));

        if let (Ok(expected), true) = (std::fs::read_to_string(&sidecar), file.is_file()) {
            match sha256_file(&file) {
                Ok(actual) if actual == expected.trim() => {
                    // SAFETY: `Module::deserialize_file` requires that the file is the output of
                    // `Module::serialize` from an Engine with compatible settings. We only load a
                    // file whose SHA-256 matches the sidecar this code wrote right after serializing
                    // it (below), and the key includes the engine's compatibility hash and this crate's
                    // version, so a stale or foreign artifact gets a different file name. The cache
                    // directory is created user-only. A mismatch never reaches this call: the entry
                    // is discarded and recompiled instead. wasmtime additionally validates the
                    // header/version and refuses incompatible artifacts.
                    #[allow(unsafe_code)]
                    let loaded = unsafe { Module::deserialize_file(engine, &file) };
                    match loaded {
                        Ok(m) => return Ok((m, true)),
                        Err(_) => self.discard(&file, &sidecar),
                    }
                }
                _ => self.discard(&file, &sidecar),
            }
        }

        let bytes = wasm()?;
        let module = Module::new(engine, &bytes)
            .map_err(|e| RuntimeError::Compile(format!("{name}: {e}")))?;
        let serialized = module
            .serialize()
            .map_err(|e| RuntimeError::Compile(format!("serialize {name}: {e}")))?;
        let digest = hex::encode(Sha256::digest(&serialized));
        let n = nonce();
        let tmp = self.dir.join(format!(".{key}.{n}.tmp"));
        let tmp_side = self.dir.join(format!(".{key}.{n}.sha.tmp"));
        let write = || -> std::io::Result<()> {
            std::fs::write(&tmp, &serialized)?;
            std::fs::write(&tmp_side, &digest)?;
            std::fs::rename(&tmp, &file)?;
            std::fs::rename(&tmp_side, &sidecar) // sidecar last: its presence means "complete"
        };
        if let Err(e) = write() {
            // Caching is an optimization; a failure must not fail the run.
            let _ = std::fs::remove_file(&tmp);
            let _ = std::fs::remove_file(&tmp_side);
            eprintln!(
                "sandboxd: could not write module cache {}: {e}",
                file.display()
            );
        }
        Ok((module, false))
    }

    fn discard(&self, file: &Path, sidecar: &Path) {
        let _ = std::fs::remove_file(sidecar);
        let _ = std::fs::remove_file(file);
    }
}

pub(crate) fn create_private_dir(p: &Path) -> Result<(), RuntimeError> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(p)
        .map_err(|e| RuntimeError::Io(format!("create {}: {e}", p.display())))
}

/// Extract `python.wasm` from the embedded CPython zip.
pub(crate) fn python_wasm() -> Result<Vec<u8>, RuntimeError> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(sandboxd_assets::PYTHON.bytes))
        .map_err(|e| RuntimeError::Compile(format!("embedded python zip: {e}")))?;
    let mut f = zip
        .by_name("python.wasm")
        .map_err(|e| RuntimeError::Compile(format!("python.wasm in zip: {e}")))?;
    let mut buf = Vec::with_capacity(f.size() as usize);
    f.read_to_end(&mut buf)
        .map_err(|e| RuntimeError::Compile(format!("read python.wasm: {e}")))?;
    Ok(buf)
}

/// Marker written next to the stdlib after bytecode compilation succeeded.
pub(crate) const PYC_MARKER: &str = ".pyc-complete";

/// Run `compileall` inside the sandbox once, writing `.pyc` into the stdlib cache (Q2).
pub(crate) async fn ensure_bytecode(
    engine: &Engine,
    module: &Module,
    stdlib: &Path,
) -> Result<bool, RuntimeError> {
    let root = stdlib.parent().and_then(Path::parent).unwrap_or(stdlib); // <sha>/lib/python3.x → <sha>
    let marker = root.join(PYC_MARKER);
    if marker.is_file() {
        return Ok(false);
    }
    compileall(
        engine,
        module,
        &[(stdlib, sandboxd_policy::STDLIB_GUEST_PATH, true)],
        sandboxd_policy::STDLIB_GUEST_PATH,
    )
    .await?;
    std::fs::write(&marker, "ok")
        .map_err(|e| RuntimeError::Io(format!("write {}: {e}", marker.display())))?;
    Ok(true)
}

/// Compile the Python guest helpers to `__pycache__` (unchecked-hash) with this interpreter.
/// The marker holds the interpreter's asset hash, so a new CPython recompiles them. Failure is not
/// fatal for the caller: the helpers then load from source (slower, same behaviour).
pub(crate) async fn ensure_helper_bytecode(
    engine: &Engine,
    module: &Module,
    stdlib: &Path,
    helpers: &Path,
) -> Result<bool, RuntimeError> {
    let marker = helpers.join(".pyc-complete");
    let want = sandboxd_assets::PYTHON.sha256;
    if std::fs::read_to_string(&marker).is_ok_and(|m| m == want) {
        return Ok(false);
    }
    compileall(
        engine,
        module,
        &[
            (stdlib, sandboxd_policy::STDLIB_GUEST_PATH, false),
            (helpers, sandboxd_policy::HELPER_GUEST_PATH, true),
        ],
        sandboxd_policy::HELPER_GUEST_PATH,
    )
    .await?;
    std::fs::write(&marker, want)
        .map_err(|e| RuntimeError::Io(format!("write {}: {e}", marker.display())))?;
    Ok(true)
}

/// Compile the merged helpers + operator packages directory to `__pycache__` (cycle 5). Same
/// rules as the helpers: the marker holds the interpreter hash, and failure is not fatal.
pub(crate) async fn ensure_package_bytecode(
    engine: &Engine,
    module: &Module,
    stdlib: &Path,
    packages: &Path,
) -> Result<bool, RuntimeError> {
    let marker = packages.join(".pyc-complete");
    let want = sandboxd_assets::PYTHON.sha256;
    if std::fs::read_to_string(&marker).is_ok_and(|m| m == want) {
        return Ok(false);
    }
    compileall(
        engine,
        module,
        &[
            (stdlib, sandboxd_policy::STDLIB_GUEST_PATH, false),
            (packages, sandboxd_policy::HELPER_GUEST_PATH, true),
        ],
        sandboxd_policy::HELPER_GUEST_PATH,
    )
    .await?;
    std::fs::write(&marker, want)
        .map_err(|e| RuntimeError::Io(format!("write {}: {e}", marker.display())))?;
    Ok(true)
}

/// Run `python -m compileall -f -q --invalidation-mode unchecked-hash <target>` in a sandbox with
/// the given (host dir, guest path, writable) preopens.
async fn compileall(
    engine: &Engine,
    module: &Module,
    mounts: &[(&Path, &str, bool)],
    target: &str,
) -> Result<(), RuntimeError> {
    use wasmtime_wasi::{FsPerms, WasiCtxBuilder, p2::pipe::MemoryOutputPipe};
    let err = MemoryOutputPipe::new(1 << 20);
    let mut b = WasiCtxBuilder::new();
    b.args(&[
        "python",
        "-I",
        "-S",
        "-m",
        "compileall",
        "-f",
        "-q",
        "--invalidation-mode",
        "unchecked-hash",
        target,
    ])
    .stderr(err.clone());
    for (host, guest, writable) in mounts {
        let perms = if *writable {
            FsPerms::ReadWrite
        } else {
            FsPerms::ReadOnly
        };
        b.preopened_dir(host, guest, perms)
            .map_err(|e| RuntimeError::Io(format!("preopen {guest}: {e}")))?;
    }
    let ctx = b.build_p1();
    let mut linker: wasmtime::Linker<wasmtime_wasi::p1::WasiP1Ctx> = wasmtime::Linker::new(engine);
    wasmtime_wasi::p1::add_to_linker_async(&mut linker, |c| c)
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;
    let mut store = wasmtime::Store::new(engine, ctx);
    store
        .set_fuel(u64::MAX)
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;
    store.epoch_deadline_callback(|_| Ok(wasmtime::UpdateDeadline::Yield(1)));
    let inst = linker
        .instantiate_async(&mut store, module)
        .await
        .map_err(|e| RuntimeError::Compile(format!("instantiate for compileall: {e}")))?;
    let start = inst
        .get_typed_func::<(), ()>(&mut store, "_start")
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;
    if let Err(e) = start.call_async(&mut store, ()).await {
        let code = e.downcast_ref::<wasmtime_wasi::I32Exit>().map(|c| c.0);
        if code != Some(0) {
            // compileall exits 1 if *some* file failed (e.g. test fixtures with bad syntax): still useful.
            let log = String::from_utf8_lossy(&err.contents())
                .chars()
                .take(400)
                .collect::<String>();
            if code != Some(1) {
                return Err(RuntimeError::Compile(format!(
                    "compileall failed ({code:?}): {log}"
                )));
            }
        }
    }
    Ok(())
}
