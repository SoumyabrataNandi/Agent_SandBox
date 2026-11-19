# C3-U1 Snapshot Spike — Summary and Go/No-Go

**Requirement:** FR-S1.0 / AC 2: the custom CPython + QuickJS builds, pre-initialised with Wizer, pass the compatibility tests and make Python `print(1)` ≥ 5× faster.
**Evidence:** `ci-results` branch, `spike/4dfeabb….json` (GitHub Actions run of `interpreters.yml`, ubuntu-latest, 4 vCPU, 16 GB).

## Result: GO (recommended)
| Measure (median of 20, pooled engine, stdlib bytecode precompiled for the baseline) | Upstream (today) | Snapshot | Factor |
|---|---|---|---|
| Python `print(1)`: wall time | 29.2 ms | **1.83 ms** | **16×** |
| Python `print(1)`: instructions (fuel) | 54.8 M | **1.73 M** | 32× |
| Instantiating the snapshot | — | **0** instructions | — |
| JavaScript `console.log(1)`: wall time | 1.06 ms | 0.41 ms | 2.6× |
| JavaScript: instructions | 3.63 M | 65 K | 55× |
| Snapshot build time / size | — | 3.3 s / 14.7 MB (Python); 1.7 MB (JS) | — |

**Compatibility: byte-identical stdout, stderr and exit code on all programs.**
- **Python, 10/10:** `print`, multi-frame traceback, SyntaxError, `sys.exit(3)`, argv/environment (incl. `os.environb`), `__name__`/`__file__`/flags/`sys.path`, a JSON/CSV/statistics/datetime/re workload, atexit + stderr, chained exceptions, `/code` listing.
- **JavaScript, 5/5:** `console.log`, `scriptArgs`, uncaught error stack, globals (`fetch`/`Headers` present, `std`/`os` absent), top-level await.
- **Per-run randomness:** `random.random()` differs between two runs of the same snapshot.

## What the spike changed or found (input for C3-U3)
1. **Build.** CPython 3.15.2 is built with its own `Tools/wasm/wasi` script and pinned wasi-sdk 33, then relinked as a reactor with `sandboxd_python.c`. It must use `PY_CORE_LDFLAGS` (16 MiB stack, 40 MiB initial memory); with the plain `PY_LDFLAGS` the stack was the 64 KiB default. The link uses `--strip-debug` (32 MB → 8 MB). QuickJS-ng 0.18 builds via CMake.
2. **Wizer** (`wasmtime-wizer` 50.0.2) calls the reactor's `_initialize`, then `wizer-initialize`, and strips `_initialize`, so restored instances can't re-run constructors.
3. **`sandboxd-run` must not call `Py_FinalizeEx()`.** Tearing down the preloaded state cost tens of millions of instructions. It runs the file with `PyRun_FileExFlags` and then performs the Python-visible exit effects: flush after the file, `SystemExit` exit-code rules, `PyErr_Print` for tracebacks, `atexit` callbacks, final flush, then `_Exit`.
4. **The decisive fix was wasmtime configuration, not interpreter code.** A snapshot heap is large and sparse. Above `memory_guaranteed_dense_image_size` (default 16 MiB), wasmtime skips the copy-on-write image and copies every data segment through a fuel-charged startup function on **every instantiation** (9.75 M instructions here). Setting it to **128 MiB** makes instantiation free. This is now set in sandboxd's runtime engine too.
5. **Fair baseline.** The upstream numbers use precompiled stdlib bytecode, as sandboxd does in production.
6. **Dead ends, measured and recorded:** `gc.freeze()` (no effect, kept because it is harmless and keeps GC from scanning preloaded objects) and `_Exit` instead of `exit` (no measurable effect, kept). The real cost was found by the per-phase profile (`sandboxd-step` diagnostic export) plus instantiation fuel.
7. **Pins.** wasi-sdk, wasmtime CLI and CPython digests come from the first CI download (trust on first use). C3-U3 cross-checks them against the upstream-published digests and pins QuickJS.

## Caveats for C3-U3
- These numbers come from the spike harness, not sandboxd's run path (interposer, devices, audit). C3-U3 measures the real path against NFR-P1 (≤ 15 ms Python end to end).
- The network-shim behaviour difference is by design: the snapshot always has the shims preloaded.
- **Open question (not verified):** the spike ran on Linux only. Whether macOS and Windows get a copy-on-write image, or fall back to copying the data segments on each instantiation (the 9.75 M-instruction path above), must be measured. C3-U3 measures it locally on Windows, and C3-U5 on the CI runners. If they fall back, snapshot runs there pay roughly the old instantiation cost, but are still faster than today's full start-up.
