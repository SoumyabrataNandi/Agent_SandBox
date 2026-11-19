# Cycle 3 Application Design — Pooling, Snapshots, Sessions, Benchmarks

**Inputs:** approved requirements and execution plan (2026-11-19). Facts verified for this design:
- `wasmtime-wizer` **50.0.2** exists (matches our wasmtime; MSRV 1.97 ≤ our 1.100).
- wasi-libc provides `__wasilibc_reset_preopens()` and `__wasilibc_deinitialize_environ()`, so a pre-initialised module can re-read each run's preopens and environment.
- CPython's WASI build (`Tools/wasm/wasi`, pinned wasi-sdk) links all extension modules statically, so `libpython3.15.a` plus our own `main.c` can be linked into a custom module.

## 1. Component changes
```
NEW  interpreters/                 C sources + build scripts for the custom interpreters (CI only)
       python/sandboxd_python.c    reactor module: wizer-initialize, sandboxd-run, sandboxd-session
       quickjs/sandboxd_qjs.c      reactor module: wizer-initialize, sandboxd-run, sandboxd-session
       build.sh, sources.toml      pinned source + wasi-sdk URLs and SHA-256s
NEW  .github/workflows/interpreters.yml   build → measure (spike) → release `interp-<hash>` → results to `ci-results`
NEW  .github/workflows/bench.yml          workflow_dispatch: benchmarks → `ci-results` + summary + artifact
NEW  scripts/bench/                       harness (stdlib Python + Docker CLI) and renderer for docs/BENCHMARKS.md
ext  sandboxd-assets    custom interpreter entries (optional; fall back to upstream)
ext  sandboxd-runtime   EngineProfile (pooling), Snapshotter (wasmtime-wizer), entry-point abstraction,
                        SessionInstance (persistent Store actor), per-call accounting in the epoch callback
ext  sandboxd-vfs       session `/work` mount; per-call `/out` collect+clear; `/dev/sandbox/session` device
ext  sandboxd-policy    [session] new keys (max_lifetime, max_calls), idle_ttl default 10 min; enabled accepted
ext  sandboxd-server    [runtime] config (pooling, snapshots); SessionStore + reaper; /v1/sessions*; MCP tools;
                        pool/session metrics
ext  sandboxd-audit     session.start / session.end; `session_id` on run events
ext  guest helpers      sandboxd_session.py (session loop, upstream path); boot.js session loop
```

## 2. ADRs

### ADR-C3-1 Custom interpreters: reactor modules with explicit entry points
- Both interpreters are built as **WASI reactors** (`-mexec-model=reactor`, so there is no `_start`), exporting:
  - **`wizer-initialize`**: one-time start-up. Python: `PyConfig` with the same settings as today (isolated, `-S`, `-B`, frozen modules, safe path), imports the **preload list** and the sandboxd helpers, and applies the network patches. QuickJS: runtime + context + `qjs:std`/`qjs:os`, plus the evaluated `boot.js` stub. It ends with `__wasilibc_reset_preopens()` and `__wasilibc_deinitialize_environ()`, so nothing init-time-specific is captured.
  - **`sandboxd-run`**: one program. Re-reads argv/env from WASI, sets `sys.argv` and rebuilds `os.environ` (Python), re-seeds `random` if it was preloaded, then runs `/code/main.py` **natively** with `PyRun_SimpleFileExFlags`. That gives CPython's own traceback printing and `SystemExit` handling, and no Python-level `compile()`, so the AST-init cost from C2-U3 disappears. JS: sets `scriptArgs` and evaluates `/code/main.mjs` as a module, then runs the job loop.
  - **`sandboxd-session`**: the session loop (ADR-C3-4).
- The runtime gains an **entry-point abstraction**: upstream modules use `_start` + argv (today's path); custom modules call `_initialize` once, then the named export. Everything else is shared: interposer, devices, limits, audit.
- **Build (CI only, ADR-C3-5):**
  - CPython: the pinned `Python-3.15.x.tgz` + `Tools/wasm/wasi build` with pinned wasi-sdk 33 produce `libpython3.15.a`, plus static module objects, linked with `sandboxd_python.c`.
  - QuickJS-ng: pinned 0.18 source + CMake with wasi-sdk, linked with `sandboxd_qjs.c`.
  - Outputs are released as `interp-<source-hash>` with `SHA256SUMS` and provenance attestations, and pinned in `assets/manifest.toml`. Upstream binaries stay as the fallback.

### ADR-C3-2 Snapshots taken at sandboxd start-up
- `Snapshotter` runs `wasmtime_wizer::Wizer` on the custom module with WASI enabled for init:
  - **empty env**;
  - fixed argv;
  - the stdlib and helper dirs preopened **read-only at their guest paths**, and nothing else.

  The result is compiled for the run engine, cached as `snapshots/<key>.cwasm` with the SHA-256 sidecar, and recompiled on mismatch (as in cycle 1). `key` = hash(custom module, helpers, preload list, init flags, wasmtime version).
- **Preload list** (Python, Q3): see the questions. Modules imported at init are in `sys.modules` (the documented difference, Q10 of the requirements).
- **Memory floor:** the snapshot's initial memory (expected 20–40 MiB) must fit the run's memory limit. Runs whose limit is lower use the upstream path automatically (Q7).
- **Hash secret** (Q1): CPython fixes its string-hash secret at init, so per-run re-seeding (requirement S1.5) is impossible with a snapshot. See Q1 for the replacement.

### ADR-C3-3 Pooling allocator sizing
- `[runtime] pooling = auto` → `InstanceAllocationStrategy::Pooling` with:
  - `total_core_instances` = `total_memories` = `max_concurrent + session.max_sessions + 2`;
  - `max_memory_size` = the largest `limits.memory` among loaded policies (rounded to 64 KiB);
  - `table_elements` sized to the interpreters;
  - `memory_init_cow(true)`;
  - async stacks pooled (4 MiB each).
- **Sizing guarantees no exhaustion:** admission control caps concurrent runs, and `max_sessions` caps sessions. If wasmtime still refuses (address space), sandboxd logs it and starts with the on-demand allocator. A run never fails because of the pool.
- Linear memory is reset by wasmtime between uses. An escape case writes a canary in run N and scans memory in run N+1 (NFR-P2).
- Gauges: `pool_slots_total` and `pool_slots_in_use`.

### ADR-C3-4 Sessions: a persistent Store owned by an actor; guest loop over a device
- `SessionStore` (server) maps an id (UUIDv4, 122 random bits) to a `SessionHandle {principal, policy, language, created, last_used, calls}`. Each session's **actor task** owns its `Store`, `RunFs` (with `/work`) and `RunNet`. Calls arrive on a channel, one at a time. A reaper task enforces `idle_ttl`, `max_lifetime` and `max_calls`.
- **Guest loop:** the session entry (custom `sandboxd-session` export, or the upstream `_start` with a `sandboxd_session.py` / `boot.js` loop) reads `/dev/sandbox/session`. Each read blocks host-side until the next call arrives and returns `{cell, path}`.
  - The host has written the cell's code to the code dir as **`/code/cell_<N>.py|.mjs`** (Q4).
  - The guest executes it in the persistent namespace and writes `{status, exit_code}` back.
- **Per-call accounting without leaving the guest:** the epoch callback reads the **per-call deadline and fuel budget** from the store data, set by the host at each call. A per-call CPU or wall-clock overrun traps and **ends the session** (SE1.4). Output goes through switchable `CappedStream`s that are rotated per call. `/out` is collected and cleared after each call. `/work` persists (artifact quota).
- **Exceptions in a cell:** printed with the normal traceback to that call's stderr; the session continues. `sys.exit(n)` in a cell: see Q5.
- **JS cells:** evaluated as global scripts with top-level await (`std.evalScript(code, {async: true})`), so declarations persist across cells (Q8).
- **Audit:** `session.start` / `session.end{reason}`. Each call is `run.start` / `run.end` with `session_id`.

### ADR-C3-5 CI feedback channel (no `gh` here)
`interpreters.yml` and `bench.yml` push their result JSON (and the spike's measurements) to an orphan branch **`ci-results`** (`spike/<sha>.json`, `bench/<sha>.json`), using the workflow's `GITHUB_TOKEN` (`contents: write`, scoped to that job). I read them with `git fetch origin ci-results`. `scripts/bench/render.py` turns a results file into the tables in `docs/BENCHMARKS.md`, so the numbers are never typed by hand.

### ADR-C3-6 Benchmark harness
`scripts/bench/run.py` (stdlib only):
- warms each system, then measures N iterations per scenario, with `time.perf_counter_ns` around each client call;
- reports p50/p95/p99, throughput at concurrency 1/4/16, and RSS (from `/proc` for sandboxd; `docker stats` for containers).

**Scenarios:** hello (Py/JS), CSV workload, session call. **Comparators:** sandboxd CLI (cold), sandboxd HTTP (warm, snapshots on/off), `docker run --rm`, `docker exec`, and gVisor `runsc` if it installs on the runner. Versions and hardware (`lscpu`, kernel, Docker version) are recorded in the results.

## 3. Threat model additions (finalised in C3-U6)
| ID | Threat | Mitigation |
|---|---|---|
| T19 | Data remnants across pooled runs | wasmtime resets linear memory between uses; escape case scans for a previous run's canary |
| T20 | Session hijacking or probing | Bound to the creating principal; 122-bit random ids; `NOT_FOUND` for other principals; audited |
| T21 | Tampered snapshot or custom interpreter | Pinned sources + wasi-sdk; release SHA-256 pins; provenance; snapshot sidecar hash + rebuild |
| T22 | Secrets or host data baked into a snapshot | Init with empty env, fixed argv, read-only stdlib/helpers only; preopens and environ reset before the snapshot |
| T23 | Resource exhaustion via held sessions | `max_sessions`, `idle_ttl`, `max_lifetime`, `max_calls`; per-session memory cap; pool sized for sessions |

## 4. Unit-level impact on the plan
The preliminary units hold. C3-U1 (spike) builds `interpreters/` and `interpreters.yml`, and proves `wizer-initialize` + `sandboxd-run` on both interpreters with the compatibility tests. C3-U4 (sessions) works on the upstream path, using the Python/JS session-loop helpers, so it doesn't depend on the spike.
