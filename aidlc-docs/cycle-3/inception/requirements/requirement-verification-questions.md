# Cycle 3 — Requirements Verification Questions (Phase 5: performance)

## Starting point
Cycles 1–2 shipped the sandbox, the API/MCP, the network broker and OTLP. Phase 5 in the original brief: *"snapshots, pooling, persistent sessions, and published benchmarks against Docker. Hard numbers are what get open-source projects noticed."*

| Item | Today | Seam left for it |
|---|---|---|
| **Start-up** | Every run instantiates a fresh interpreter from a cached, precompiled module (`InstancePre`), then CPython runs its whole start-up. Python `print(1)`: **~100–150 ms** end to end (58 M instructions, almost all interpreter initialisation). JavaScript: **~8 ms**. | `InstancePool` concept (FR-8.1) |
| **Pooling** | Default on-demand allocator: each run maps fresh memory | wasmtime's pooling allocator + copy-on-write memory init |
| **Sessions** | `session` policy section validated, then **refused**. `RunRequest.session` → `NOT_IMPLEMENTED`. | FR-8.2, `SessionId`, `SessionStore` seam |
| **Benchmarks** | Perf smoke in CI (2× NFR-3 bounds). No Docker comparison. | — |

**Feasibility research done for this questionnaire:**
- **Snapshots (Wizer)** run the interpreter's start-up once and save the initialised memory as a new module. Projects doing this for CPython report **~1–5 ms per execution vs ~450 ms cold**. Wizer now lives in wasmtime (the `wasmtime-wizer` crate / `wasmtime wizer` command).
- **Catch:** Wizer needs the module to *export an initialisation function*. The upstream `python.wasm` and `qjs-wasi.wasm` don't, so snapshots mean **building our own CPython 3.15 and QuickJS-ng for WASI** from pinned sources with wasi-sdk. That's the biggest risk in this cycle.
- **Pooling allocator:** supported on Linux, macOS and Windows; copy-on-write memory init is mainly a Linux optimisation, and Windows is "not tuned".

Answer after each `[Answer]:` tag, or reply **"accept recommended defaults"**.

---

### Question 1 — Cycle 3 scope
A) **All of Phase 5: pooling, snapshots, sessions, benchmarks.** Snapshots get a **spike first**: build the custom interpreters and measure. If the spike fails, the cycle continues without them and they're documented as deferred. **(Recommended: snapshots are the headline number; the spike contains the risk)**
B) Pooling + sessions + benchmarks. Snapshots deferred (no custom interpreter builds).
C) Pooling + snapshots + benchmarks. Sessions deferred.
D) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 2 — How snapshots are produced
A) **Custom interpreter builds in CI.** CPython 3.15 and QuickJS-ng are compiled for WASI with pinned wasi-sdk, from pinned, hash-verified source tarballs, adding an exported init function. Wizer snapshots are taken **at sandboxd start-up**, like today's stdlib bytecode step: the snapshot contains our helpers and preloaded common stdlib modules, and is cached by content hash. **(Recommended: builds from source give better provenance; no snapshot binaries to host)**
B) Same builds, but the snapshot is taken **in CI** and shipped as an asset (faster first start, but bigger assets and less flexibility)
C) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 3 — Where the custom interpreter binaries come from (if snapshots are in scope)
Your laptop can't easily build CPython for WASI: it needs wasi-sdk and a matching host Python, and C: is nearly full. The repo is private, so GitHub release assets need authentication to download.
A) **CI builds them** (ubuntu runner, cached by source hash). Each run of the build workflow publishes them as a release in this repo with SHA-256 pins in `assets/manifest.toml`. `scripts/fetch-assets.py` downloads them using the GitHub token (CI) or your Git Credential Manager login (laptop). **(Recommended)**
B) A separate **public** `sandboxd-assets` repo hosts the built interpreters (anonymous downloads)
C) Build locally in WSL Ubuntu on D: (needs wasi-sdk there; uses C: space for WSL)
D) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 4 — Pooling allocator
A) **On by default** (`[runtime] pooling = "auto"`): slots are sized from `max_concurrent` and the largest policy memory limit. Memory is reset between runs, so no state carries over. It can be turned off in config. **(Recommended)**
B) Off by default, opt-in only
C) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 5 — Session model
A) **Live interpreter per session.** The instance stays in memory between calls, so variables, imports and files under a session-private writable `/work` persist (like a notebook kernel). Each call gets its own stdout/stderr/artifacts. In memory only: sessions are lost on restart. **(Recommended: what agents iterating on data actually need)**
B) Replay: re-run the full history of calls each time (stateless server; slow, but survives restarts)
C) Defer sessions
D) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 6 — Session limits and ownership
A) **Per-call limits** from the policy (wall clock, fuel, output) **plus session caps:**
   - memory stays bounded by the policy's `memory`;
   - `session.idle_ttl` (default 10 min) and a new `session.max_lifetime` (default 1 h);
   - `session.max_calls` (default 1000);
   - server-wide `session.max_sessions`.

   A session belongs to the **principal that created it**; other tokens get `NOT_FOUND`. Network quotas apply per session, not per call. **(Recommended)**
B) Per-call limits only; sessions live until idle
C) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 7 — Session API surface
A) **HTTP:** `POST /v1/sessions` (language + policy) → id; `POST /v1/sessions/{id}/runs`; `GET /v1/sessions/{id}`; `DELETE /v1/sessions/{id}`.
   **MCP:** `session_create`, `run_code` with an optional `session_id`, `session_close`.
   **CLI:** none (one-shot by nature).
   All session operations are audited. **(Recommended)**
B) MCP only
C) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 8 — Benchmarks against Docker
A) A **reproducible benchmark harness** (`scripts/bench/`, Python stdlib + Docker CLI), run by a manual `workflow_dispatch` CI job on an ubuntu runner (Docker is available there; not on your laptop). Results go to the job summary and an artifact, and are published in **`docs/BENCHMARKS.md`** with methodology and hardware. **(Recommended)**
   It compares sandboxd against `docker run --rm python:3.15-slim` (cold), `docker exec` into a running container (warm), and gVisor if available. Each is measured for:
   - hello-world latency (p50/p95);
   - a small realistic workload (JSON/CSV processing);
   - throughput at N concurrent;
   - memory per sandbox;
   - session call latency.
B) Local benchmarks only (no Docker comparison)
C) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 9 — Performance targets (release builds, warm caches, Linux CI runner)
A) **Targets:**
   - Python `print(1)` ≤ **15 ms** end to end through the service (snapshot + pool);
   - JavaScript ≤ **3 ms**;
   - session call overhead ≤ **2 ms**;
   - ≥ **100** Python runs/s on 4 vCPU;
   - idle session ≤ **40 MiB** RSS;
   - no regression for runs that don't use snapshots.

   The spike may revise these with measurements before construction. **(Recommended)**
B) No fixed targets; publish whatever we measure
C) Other targets (please describe after [Answer]: tag below)

[Answer]: A

### Question 10 — Behaviour guarantees for snapshot runs
A) **Indistinguishable from today's runs:**
   - the same `sys.argv`, environment (policy env applied after restore), flags, tracebacks, exit codes, network shims and audit events;
   - no host-specific data inside snapshots;
   - snapshots are reproducible and hash-checked like the module cache.

   The escape suite runs against the snapshot path, and the cycle-1/2 compatibility tests must pass unchanged. **The one documented difference:** stdlib modules preloaded into the snapshot (Q2) are already in `sys.modules`, so importing them is just a lookup. **(Recommended)**
B) Strict: no preloading, so `sys.modules` is identical too (smaller speed-up for programs that import common modules)
C) Other (please describe after [Answer]: tag below)

[Answer]: A
