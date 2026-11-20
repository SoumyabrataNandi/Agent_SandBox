# C3-U3 Snapshot Integration — Code Summary & Test Results

Design answers Q1–Q5: all A. Releases are published by CI only when the spike passes. The interpreters are embedded and required. `run.start` gains an `interpreter` field. Snapshots are used on every OS. The diagnostic export is compiled out.

## Pipeline
| Piece | Result |
|---|---|
| Pins | wasi-sdk 33 and wasmtime 50.0.2 **match** GitHub's published asset digests. CPython 3.15.2 **matches** python.org's published sha256. QuickJS is a GitHub tag archive (no upstream digest): pinned, and a regenerated archive fails the build. All builds run in `release` mode (unpinned input → error). |
| `interpreters.yml` | Spike job exports `go` + a source hash. The new `release` job (push + `go` only) publishes `interp-<hash>` as a prerelease with `SHA256SUMS` and **build-provenance attestations**. |
| Releases | `interp-f940919f383c1ce8` (first), **`interp-ef9ab1d314d38dc0`** (current; fixes below). Pinned in `assets/manifest.toml` as `[python_snapshot]` / `[javascript_snapshot]`, and verified by `fetch-assets.py` and `sandboxd-assets/build.rs`. |

## Runtime
| File | Change |
|---|---|
| `src/snapshot.rs` (new) | `build()`: `wasmtime-wizer` on the **run engine**, on its own thread. Empty env, fixed argv, stdlib + helpers **read-only** only (T22). Init stdout/stderr are kept for error messages. `snapshot_sha()` (asset + helpers + recipe), `memory_floor()`. |
| `src/sandbox.rs` | `SnapshotMode` (auto/on/off). Snapshots built after the stdlib bytecode, cached through `ModuleCache` (engine-hash key, SHA-256 sidecar, rebuild on tamper), probed with pooling. Per-run path: snapshot if available and `limits.memory ≥ floor`; argv `python /code/main.py` / `qjs /code/main.mjs`; entry `sandboxd-run`. `WarmupReport`: per-language snapshot flags and floors, plus the fallback reason. `memory_guaranteed_dense_image_size(128 MiB)` (from the spike). |
| `sandboxd-audit` | `run.start.interpreter = "snapshot" \| "upstream"` (additive, optional) |
| `sandboxd-assets` | `PYTHON_SNAPSHOT`, `JAVASCRIPT_SNAPSHOT` embedded (about +9.6 MB binary) |
| Server / binary | `[runtime] snapshots`; start-up log of floors and fallback |

## Defects found by running the existing suites on the snapshot path
1. **Python HTTPS (all urllib calls failed):** the preload imported `urllib.request` before `http.client` was patched. `urllib.request` defines `HTTPSHandler` at import time only if `http.client.HTTPSConnection` exists, so `build_opener()` raised `NameError`. **Fix:** patch `socket` and `http.client` first, then import `urllib.request` (the order the C2-U3 lazy hook guaranteed).
2. **JavaScript `std.getenviron()` crashed (E-ENV escape case):** init resets wasi-libc's environment (T22), but the QuickJS run entry never re-read it (Python's did). **Fix:** `__wasilibc_ensure_environ()` at the start of `sandboxd-run`.

Both are covered now: an environment-reading program was added to the spike and to the runtime parity test. The fixes shipped as `interp-ef9ab1d314d38dc0` (spike: Python 14.5×, JS 2.5×, all compatible).

## Measured on this Windows laptop
- **Memory floors:** Python **40 MiB**, JavaScript **1.3 MiB**. These equal what the upstream interpreters need themselves (same initial memory), so no previously runnable policy is affected. Below the floor the upstream path is chosen, as tested.
- **Windows has no copy-on-write image** (the spike's open question): wasmtime initialises the snapshot's data on every instantiation through fuel-charged code. Python `print(1)` costs **26.9 M** instructions (snapshot) vs **58.1 M** (upstream). On Linux CI the spike measured 1.7 M. JavaScript: 0.41 M vs 3.77 M. Snapshots stay on there (Q3 = A). Wall-clock numbers: see the release perf smoke below.

## Release perf smoke (this Windows laptop; snapshots + pooling on)
| Workload | Before C3-U3 (cycle-2 smoke, same laptop) | Now | Fuel now (before) |
|---|---|---|---|
| Python `print(1)` | 102–153 ms | **31 ms** | 26.9 M (58.0 M) |
| Python `import json,csv,re,datetime` | 167–299 ms | **27 ms** | 27.1 M (138.6 M) |
| JavaScript `console.log` | 8–16 ms | 12 ms | 0.41 M (3.8 M) |

Even without copy-on-write, Python is about 4–10× faster on Windows; import-heavy code gains most because the modules are preloaded. The NFR-P1 target (≤ 15 ms Python, Linux CI) is measured by the C3-U5 benchmark job. The first warm-up on this laptop (release, empty cache) took 44 s: interpreter compilation, stdlib bytecode and both snapshots.

## Tests
- **`tests/snapshot.rs` (new, 5):**
  - parity: **13 Python + 6 JavaScript programs**, byte-identical stdout/stderr, same exit code, outcome, error code and artifacts on both paths. Includes tracebacks, SyntaxError, `sys.exit(3)`, `sys.exit("msg")`, argv/env, `__main__`, workload, atexit, chained exceptions, native-extension detection, files/`/out`, JS stack traces, globals, top-level await, `std.getenviron()`;
  - **no state carried between runs** (globals, `sys.modules`, `os.environ`, `sys.path`, `random` state, JS globals);
  - memory-floor path selection;
  - fewer instructions on the snapshot path (≥ 5× on Linux; fewer elsewhere);
  - mode parsing.
- **Existing suites, all passing on the snapshot path (the new default):** runtime 20, network 14 (the bootstrap heuristic test now checks both paths), pooling 6, server 9 + config unit tests, CLI 5, VFS, broker 11, audit, policy, and the **escape suite 17 + E-NET 11**.
- Clippy `-D warnings` and fmt clean.

## Notes
- The first start after an upgrade builds the snapshots (about 3 s release, longer in debug builds), cached afterwards. `sandboxd cache warm` does it ahead of time.
- The C2-U3 bootstrap stays for the upstream path (`snapshots = off`, or below the floor).
