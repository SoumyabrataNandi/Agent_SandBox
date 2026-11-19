# C3-U3 Snapshot Integration — Functional Design

**Requirements:** FR-S1.1–S1.6 (S1.5 amended), NFR-P1/P3/P4/P5, AC 3/4 · **ADRs:** ADR-C3-1/2 · **Spike:** C3-U1 GO (Python 16×, JS 2.6×; 10/10 + 5/5 byte-identical)

## 1. Asset pipeline (custom interpreters)
1. **Build and release:** `interpreters.yml` gets a `release` job that runs on `main` when `interpreters/**` changes, **only if the spike job's `go` is true**. It publishes a GitHub Release `interp-<source-hash>` with `sandboxd-python.wasm`, `sandboxd-qjs.wasm`, `SHA256SUMS` and build-provenance attestations. The source hash covers `sources.toml`, the C files and `build.sh`. The repository is public, so downloads need no login.
2. **Release builds** run with `SANDBOXD_INTERP_MODE=release`, so every input must be pinned. QuickJS's pin is added. The three trust-on-first-use pins are cross-checked against the upstream-published digests (python.org, the GitHub release digests for wasi-sdk/wasmtime); any mismatch stops the unit.
3. **`assets/manifest.toml`** gains `[python_snapshot]` and `[javascript_snapshot]` (url, file, sha256, license PSF-2.0 / MIT). `scripts/fetch-assets.py` and `sandboxd-assets/build.rs` verify them like the upstream assets. **`sandboxd-python.wasm`'s `sandboxd-step` diagnostic export is compiled out** (`-DSANDBOXD_SPIKE` only in the spike job; Q4).
4. `sandboxd-assets` exposes `PYTHON_SNAPSHOT` and `JAVASCRIPT_SNAPSHOT` (Q1: embedded and required).

## 2. Snapshot creation (runtime start-up)
In `Sandbox::build`, after the stdlib, helpers and bytecode steps (so Wizer's init imports precompiled bytecode):
1. `key = sha256(asset sha256, helpers sha256, preload marker, wasmtime version, engine compatibility hash)`.
2. **Cache hit:** `ModuleCache` loads `snapshot-<lang>-<key>.cwasm` with its sidecar check, and a tamper → rebuild path, exactly like the interpreter modules.
3. **Miss:** `wasmtime_wizer::Wizer::new().init_func("wizer-initialize").run(store, bytes, instantiate)`. The store uses the **run engine** and a plain `WasiP1Ctx`: argv `["python"]`, **empty env**, and the stdlib and helpers preopened **read-only** at their guest paths, nothing else (T22). The output is compiled, serialised and cached. About 3 s, once per host and version. `sandboxd cache warm` does it ahead of time; `cache clear` removes `snapshots`.
4. **Failure** (Wizer error, incompatible asset, trap in init) with `snapshots = auto` → log a warning and use the upstream path. With `snapshots = on`, it's a start-up error.
5. Both interpreters are probed (instantiate only) like the C3-U2 pooling probe.

## 3. Run path
| | Upstream (today) | Snapshot |
|---|---|---|
| Python argv | `python -I -B -S -X frozen_modules=on [-c launcher] /code/main.py …` | `python /code/main.py …` |
| Python entry | `_start` | `sandboxd-run` |
| JS argv / entry | `qjs --std -m -I boot.js /code/main.mjs …` / `_start` | `qjs /code/main.mjs …` / `sandboxd-run` |
| Network shims | Bootstrap (C2-U3), only when networking is possible | **Preloaded and patched in the snapshot**; the bootstrap heuristic doesn't apply |
| Mounts, devices, interposer, limits, audit | unchanged | unchanged |

- **Path selection per run:** snapshot if available **and** the policy's memory limit ≥ the snapshot's initial memory (its memory floor, read from the module's memory type, about 40–50 MiB). Otherwise upstream (design Q7, logged once per policy). `policy check` notes policies below the floor.
- **Observable difference (documented, S1.4):** the preload list is in `sys.modules`.
- **Audit (Q2):** `run.start` gains `interpreter: "snapshot" | "upstream"` (additive).
- **Fuel limits:** unchanged semantics. Snapshot runs simply use far less fuel.

## 4. Configuration
`[runtime] snapshots = "auto" | "on" | "off"` (default `auto`). `RuntimeConfig.snapshots: SnapshotMode`. `WarmupReport` gains `snapshots: {python, javascript}: bool` and `snapshot_fallback: Option<String>`.

## 5. Tests
- **Compatibility on the real path:** run the whole runtime, network and escape suites with snapshots on (the default). Add a parameterised run of the cycle-1/2 compatibility programs on **both** paths, with byte-identical comparison.
- **Fallback:** a policy below the memory floor → upstream path (`interpreter: "upstream"` in audit); `snapshots = off`; a corrupted asset or snapshot cache entry → rebuild (tamper test).
- **Isolation (NFR-P2, partly here, rest in U6):** state set by run N (globals, `sys.modules` additions, env, `random` state) is invisible in run N+1.
- **Performance:** a release perf-smoke comparison, upstream vs snapshot, in fuel and wall time. The fuel of a restored run on **Windows** answers the spike's open question about copy-on-write on Windows.

## 6. Risks
- **Asset availability:** the main CI can't build until the release exists and the manifest pins it. Order: spike job green → release published → pin commit.
- **Memory floor:** policies with `memory` < ~48 MiB lose the snapshot speed-up (they still work).
- **Snapshot staleness:** helpers changes alter the key, so the snapshot is rebuilt automatically.
