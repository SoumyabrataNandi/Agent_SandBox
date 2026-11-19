# Cycle 3 Requirements — Performance (Phase 5)

**Status:** Draft for approval · **Date:** 2026-11-19 · **Answers:** Q1–Q10 all recommended (A).
Cycle-1/2 requirements stay in force. This cycle **replaces FR-8** (performance and sessions: "designed, not built").

## 1. Intent
Make sandboxd fast enough that agents never think about start-up cost, prove it with **published, reproducible numbers against Docker**, and let agents keep state across calls with **sessions**. None of this may weaken isolation, change program-visible behaviour, or bypass the audit log.

**Out of scope (this cycle):** sessions that survive a restart or migrate between hosts; sharing sessions between principals; a session CLI; pip/package installation; NumPy; GPU; multi-tenant quotas; gVisor/Firecracker *integration* (they're benchmark comparators only, if available).

## 2. Functional requirements

### FR-P1 Pooling allocator (Q4)
- **P1.1** `[runtime] pooling = "auto" | "on" | "off"` (default `auto` = on). With pooling, wasmtime's pooling allocator is used: slots are pre-reserved, sized from `max_concurrent` and the largest memory limit among loaded policies, and copy-on-write memory init is used where the OS supports it.
- **P1.2** Each run gets a slot whose memory is **reset**: no bytes from a previous run are observable. Tested by an escape case.
- **P1.3** If the pool can't serve a request (slots exhausted or sized too small), the run falls back to on-demand allocation **or** is queued by admission control. A run never fails because of pooling.
- **P1.4** Pool settings and occupancy are exposed in `/metrics` (and OTLP).

### FR-S1 Snapshots (Q1–Q3, Q10)
- **S1.0 Spike gate (first unit):** build CPython 3.15 and QuickJS-ng for WASI from pinned sources with an exported init function; pre-initialise with Wizer; measure. **Exit criteria:** the snapshot module runs the cycle-1/2 compatibility tests unchanged, and Python `print(1)` is ≥ 5× faster than today. If it fails, FR-S1 is deferred and documented, and the rest of the cycle continues.
- **S1.1 Interpreter builds:** a CI workflow builds both interpreters from **hash-pinned source tarballs** with pinned wasi-sdk on ubuntu, caches them by source hash, and publishes them as a release in this repo. `assets/manifest.toml` pins their SHA-256 values. `scripts/fetch-assets.py` downloads them using the GitHub token (CI) or the user's Git Credential Manager login (laptop). Upstream binaries stay as the fallback interpreter.
- **S1.2 Snapshot creation:** at sandboxd start-up, like the stdlib bytecode step, the runtime pre-initialises the custom interpreter with `wasmtime-wizer`. The snapshot includes interpreter initialisation, the sandboxd helpers, and a fixed list of **preloaded stdlib modules**. Snapshots are cached by a content hash (interpreter + helpers + preload list + flags) with the same tamper-checked sidecar as `.cwasm`, and are reproducible.
- **S1.3 Per-run restore:** each run instantiates the snapshot (pooled). The run then applies the per-run state the snapshot can't contain:
  - argv;
  - environment (the policy env; `os.environ` is rebuilt);
  - preopens and devices;
  - limits;
  - the network bootstrap decision.

  The program then executes.
- **S1.4 Behaviour (Q10):** indistinguishable from non-snapshot runs: `sys.argv`, env, flags, tracebacks (byte-identical), exit codes, network shims, audit events, native-extension detection. **The one documented difference:** preloaded stdlib modules are already in `sys.modules`.
- **S1.5** Snapshots contain **no host-specific data**: no host paths, env or time-dependent state. `random` is re-seeded per run. *(Amended by design Q1:)* CPython's string-hash secret is fixed at initialisation, so it is a **random secret generated when each host builds its snapshot**: it differs between installs and rebuilds, and is shared by the runs on one host.
- **S1.6** `[runtime] snapshots = "auto" | "off"`. With `auto`, sandboxd uses snapshots when the custom interpreters are available and falls back silently otherwise, which is logged. The run result reports `timings.setup_ms` as usual.

### FR-SE1 Sessions (Q5–Q7)
- **SE1.1 Model:** a session is a **live interpreter instance** kept between calls. Python globals, imports and JS module state persist. A session-private writable **`/work`** directory, counted against the artifact quota, persists. `/out` is collected **per call**. Sessions live in memory only and are lost on restart.
- **SE1.2 Guest protocol:** the interpreter runs a session loop (sandboxd helper) that receives each call's code through a virtual device and executes it in the persistent namespace. Each call's stdout/stderr is separate. *(Amended by design Q4:)* each cell is a real file **`/code/cell_<N>.py|.mjs`** written by the host, so tracebacks show source lines. `sys.exit(n)` ends the call with exit code n and the session continues (design Q5).
- **SE1.3 Policy (`[session]`):**
  - `enabled` (default `false`): a policy must opt in;
  - `idle_ttl`: default **10 min**, changed from cycle 1's 5 min, which was never in effect because sessions were refused;
  - **new** `max_lifetime` (default 1 h);
  - **new** `max_calls` (default 1000);
  - `max_sessions` (server-wide cap; default 100).
- **SE1.4 Limits:**
  - wall clock, fuel and output apply **per call**;
  - memory is the policy limit **for the whole session**;
  - network quotas apply **per session**;
  - a call that hits a CPU or wall-clock limit **ends the session**, because its state may be inconsistent; the result says so.
- **SE1.5 Ownership:** a session belongs to the **principal** that created it. Any other principal gets `NOT_FOUND` (not `FORBIDDEN`, so session ids can't be probed).
- **SE1.6 API:**
  - **HTTP:** `POST /v1/sessions` {language, policy} → {id, expires_at}; `POST /v1/sessions/{id}/runs` (the existing run body minus language and policy; streaming supported); `GET /v1/sessions/{id}`; `DELETE /v1/sessions/{id}`.
  - **MCP:** `session_create`, `run_code` + optional `session_id`, `session_close`.
- **SE1.7 Audit:** `session.start` and `session.end` (with reason: closed, idle, lifetime, max_calls, limit, shutdown). Each call is a normal run (`run.start` / `run.end`) carrying `session_id`.
- **SE1.8 Lifecycle:** idle, lifetime and max-calls expiry run in the background. Shutdown ends all sessions, which are audited.

### FR-B1 Benchmarks (Q8)
- **B1.1** `scripts/bench/` (Python stdlib + Docker CLI + the sandboxd binary) measures:
  - hello-world latency (p50/p95/p99, N=200);
  - a realistic workload (parse + aggregate a 1 MB CSV, JSON out);
  - throughput at concurrency 1/4/16;
  - memory per concurrent sandbox (RSS);
  - session call latency.
- **B1.2 Comparators:**
  - sandboxd CLI (cold process);
  - sandboxd server (HTTP, warm; with and without snapshots);
  - `docker run --rm python:3.15-slim` (cold);
  - `docker exec` into a running container (warm);
  - `node:22-slim` / `docker run` for JS;
  - gVisor `runsc`, if installable on the runner.
- **B1.3** A `workflow_dispatch` CI job (`bench.yml`, ubuntu-latest) runs the suite and writes results to the job summary and a JSON + Markdown artifact. **`docs/BENCHMARKS.md`** publishes methodology, hardware, versions, raw numbers and caveats. Numbers are only published from that job, never hand-edited.

## 3. Non-functional requirements
| ID | Requirement |
|---|---|
| NFR-P1 Targets (Q9) | Release build, warm caches, Linux CI runner (4 vCPU):<br>• Python `print(1)` ≤ **15 ms** end to end through the service (snapshot + pool)<br>• JavaScript ≤ **3 ms**<br>• session call overhead ≤ **2 ms** (excluding guest work)<br>• ≥ **100** Python runs/s on 4 vCPU<br>• idle session ≤ **40 MiB** RSS<br>• no regression on the non-snapshot path<br>The S1.0 spike may revise these with measurements. Any change is recorded before construction. |
| NFR-P2 Isolation | Pooling, snapshots and sessions add **no shared mutable state between runs or sessions**. New escape cases: memory remnants across pooled runs; session cross-principal access and id guessing; session state leakage between sessions; snapshot tampering (cache) → rebuild. |
| NFR-P3 Compatibility | Cycle-1/2 APIs, policies (except new optional `[runtime]`/`[session]` keys), audit schema (additive only), and program-visible behaviour (S1.4). The upstream-interpreter path stays supported. |
| NFR-P4 Supply chain | Custom interpreters are built from pinned, hash-verified sources with pinned wasi-sdk, with build provenance in CI. `wasmtime-wizer` passes cargo-deny/cargo-audit with no new ignores. |
| NFR-P5 Platforms | Linux, macOS, Windows. Pooling/CoW performance may differ by OS (documented). Benchmarks are published for Linux. |
| NFR-P6 Laptop constraints | No admin and C: nearly full: nothing new is built on the laptop. Custom interpreters are downloaded (CI-built), and caches stay on D:. |

## 4. Acceptance criteria
1. With pooling on, 1,000 sequential runs show no memory remnants from previous runs (escape case), and `/metrics` shows pool occupancy.
2. **Spike:** the custom CPython + QuickJS builds pre-initialised with Wizer pass the runtime compatibility tests (tracebacks byte-identical, argv/env/exit codes) and make Python `print(1)` ≥ 5× faster. If not, FR-S1 is formally deferred.
3. With snapshots, the full runtime, network and escape suites pass unchanged (except the documented `sys.modules` difference). Tampering with a snapshot cache entry is detected and it is rebuilt.
4. NFR-P1 targets are met in the CI benchmark job, or the spike's revised targets are.
5. A session keeps variables, imports and `/work` files across calls. Each call's output and artifacts are separate. Idle TTL, max lifetime and max calls end it with an audited reason.
6. A second principal can't see or use another principal's session (`NOT_FOUND`), and session ids are unguessable (≥ 122 random bits).
7. A CPU or wall-clock limit inside a session ends that session and reports it; other sessions are unaffected.
8. Sessions work over HTTP (incl. streaming) and MCP (`session_create` / `run_code` + `session_id` / `session_close`), and are refused when the policy has `session.enabled = false`.
9. `bench.yml` produces the results artifact, and `docs/BENCHMARKS.md` contains numbers, methodology and versions for every comparator that ran.
10. All CI jobs (4 OS runners, escape suite incl. new cases, otel, supply chain) pass.
