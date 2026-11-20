//! Snapshot creation (cycle 3, C3-U3, ADR-C3-2).
//!
//! The custom interpreters (`sandboxd_assets::PYTHON_SNAPSHOT` / `JAVASCRIPT_SNAPSHOT`) are WASI
//! reactors with a `wizer-initialize` export. At start-up the runtime pre-initialises them with
//! `wasmtime-wizer`; the result is compiled and cached like the plain interpreters (sidecar hash,
//! rebuild on tamper). Runs then instantiate the snapshot and call `sandboxd-run`.
//!
//! Isolation of the snapshot itself (T22): initialisation sees **no environment variables**, a
//! fixed argv, and only the stdlib and helper directories, **read-only**, at their guest paths. The
//! custom interpreters reset wasi-libc's preopen table and environment at the end of init, so runs
//! see their own mounts and environment.

use std::path::Path;

use sha2::{Digest, Sha256};
use wasmtime::{Engine, Linker, Module, Store, UpdateDeadline};
use wasmtime_wasi::{FsPerms, WasiCtxBuilder, p1::WasiP1Ctx};

use crate::{error::RuntimeError, helpers::helpers_sha256};

/// Bumped when the snapshot recipe (init flags, preload list, entry points) changes in a way the
/// asset and helper hashes don't capture.
const RECIPE: &str = "c3u3-v1";

/// Cache key input for a snapshot: interpreter asset + helpers + recipe.
pub(crate) fn snapshot_sha(asset_sha: &str) -> String {
    let mut h = Sha256::new();
    h.update(asset_sha.as_bytes());
    h.update([0]);
    h.update(helpers_sha256().as_bytes());
    h.update([0]);
    h.update(RECIPE.as_bytes());
    hex::encode(h.finalize())
}

/// Pre-initialise `wasm` (a reactor exporting `wizer-initialize`) and return the snapshot module
/// bytes. Blocks the calling thread (runs on its own OS thread with a private tokio runtime), so
/// it can be called from `ModuleCache::load_or_compile`'s synchronous closure.
pub(crate) fn build(
    engine: &Engine,
    wasm: &'static [u8],
    argv0: &'static str,
    stdlib: Option<&Path>,
    helpers: &Path,
) -> Result<Vec<u8>, RuntimeError> {
    let engine = engine.clone();
    let stdlib = stdlib.map(Path::to_path_buf);
    let helpers = helpers.to_path_buf();
    std::thread::Builder::new()
        .name("sandboxd-snapshot".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| RuntimeError::Io(format!("snapshot runtime: {e}")))?;
            rt.block_on(wizer(&engine, wasm, argv0, stdlib.as_deref(), &helpers))
        })
        .map_err(|e| RuntimeError::Io(format!("spawn snapshot thread: {e}")))?
        .join()
        .map_err(|_| RuntimeError::Compile("snapshot thread panicked".into()))?
}

async fn wizer(
    engine: &Engine,
    wasm: &[u8],
    argv0: &str,
    stdlib: Option<&Path>,
    helpers: &Path,
) -> Result<Vec<u8>, RuntimeError> {
    use wasmtime_wasi::p2::pipe::MemoryOutputPipe;
    let out = MemoryOutputPipe::new(1 << 16);
    let err = MemoryOutputPipe::new(1 << 16);
    let mut b = WasiCtxBuilder::new();
    // No env (T22), fixed argv, stdout/stderr captured for diagnostics only.
    b.args(&[argv0]).stdout(out.clone()).stderr(err.clone());
    if let Some(lib) = stdlib {
        b.preopened_dir(lib, sandboxd_policy::STDLIB_GUEST_PATH, FsPerms::ReadOnly)
            .map_err(|e| RuntimeError::Io(format!("snapshot preopen stdlib: {e}")))?;
    }
    b.preopened_dir(
        helpers,
        sandboxd_policy::HELPER_GUEST_PATH,
        FsPerms::ReadOnly,
    )
    .map_err(|e| RuntimeError::Io(format!("snapshot preopen helpers: {e}")))?;
    let mut store: Store<WasiP1Ctx> = Store::new(engine, b.build_p1());
    store
        .set_fuel(u64::MAX)
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;
    store.epoch_deadline_callback(|_| Ok(UpdateDeadline::Yield(1)));
    let mut linker: Linker<WasiP1Ctx> = Linker::new(engine);
    wasmtime_wasi::p1::add_to_linker_async(&mut linker, |c| c)
        .map_err(|e| RuntimeError::Compile(e.to_string()))?;
    wasmtime_wizer::Wizer::new()
        .init_func("wizer-initialize")
        .run(&mut store, wasm, async |store, module: &Module| {
            linker.instantiate_async(store, module).await
        })
        .await
        .map_err(|e| {
            let tail = |p: &MemoryOutputPipe| {
                let s = String::from_utf8_lossy(&p.contents()).into_owned();
                s.lines()
                    .rev()
                    .take(20)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            RuntimeError::Compile(format!(
                "snapshot ({argv0}): {e}\n--- init stderr ---\n{}\n--- init stdout ---\n{}",
                tail(&err),
                tail(&out)
            ))
        })
}

/// Initial linear-memory size of a module (its memory floor), in bytes.
pub(crate) fn memory_floor(m: &Module) -> u64 {
    m.exports()
        .filter_map(|e| e.ty().memory().map(|t| t.minimum()))
        .max()
        .unwrap_or(0)
        .saturating_mul(65536)
}
