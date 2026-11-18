# U4 Runtime — Functional, NFR & Infrastructure Design

**Crate:** `sandboxd-runtime` (component C4). Depends on policy, audit, vfs, assets, wasmtime 50, wasmtime-wasi (p1) and tokio.
**Inputs:** U3 `RunFs`/`Interposer`, U1 `Policy`/`Limits`, U2 audit events, ADR-003 (async), ADR-004 (assets).

## 0. Measurements that shaped this design (release, Windows laptop, median of 7)
| Step | Time |
|---|---|
| Compile `python.wasm` (Cranelift) | 5.4 s · QuickJS 1.3 s |
| `Module::serialize` → 23 MB `.cwasm` / `deserialize` | 10 ms / **7 ms** |
| `InstancePre::instantiate_async` | 3–6 ms |
| CPython `-I -B -S -c "print(1)"` end to end | 116 ms; **86 ms** with `-X frozen_modules=on` |
| CPython `import json, csv, re, datetime` | **433 ms**, because every import compiles from source (no `.pyc`, `-B`, ro stdlib) |
| QuickJS `qjs -e "console.log(1+1)"` | **3 ms** |

So NFR-3 (CPython ≤ 300 ms, QuickJS ≤ 50 ms) is met for trivial code. Realistic imports need precompiled bytecode (Q2).

## 1. Public API
```rust
pub enum Language { Python, JavaScript }
pub struct RunRequest { pub language: Language, pub code: String, pub files: Vec<InputFile>,
                        pub args: Vec<String>, pub stdin: Option<Vec<u8>>, pub overrides: Overrides,
                        pub session: Option<SessionId> /* reserved → NotImplemented */ }
pub struct RunResult  { pub run_id: RunId, pub outcome: Outcome, pub exit_code: Option<i32>,
                        pub stdout: Vec<u8>, pub stderr: Vec<u8>, pub stdout_truncated: bool, pub stderr_truncated: bool,
                        pub artifacts: Vec<Artifact>, pub limits_hit: Vec<LimitKind>, pub error: Option<RunError>,
                        pub fuel_used: u64, pub peak_memory: u64, pub timings: Timings }
pub enum RunEvent     { Stdout(Bytes), Stderr(Bytes), LimitHit(LimitKind), Finished(Box<RunResult>) }
pub enum RunError     { UnsupportedNativeExtension { module: String }, InvalidRequest(String),
                        PolicyViolation(String), Trap(String), Internal(String), NotImplemented(&'static str) }
pub struct Timings    { pub queued_ms: u64 /* set by U5 */, pub setup_ms: u64, pub run_ms: u64, pub collect_ms: u64, pub total_ms: u64 }

pub struct Sandbox;   // cheap to clone (Arc inside)
impl Sandbox {
    pub async fn new(cfg: RuntimeConfig, audit: Arc<dyn AuditSink>) -> Result<Sandbox, RuntimeError>; // warms the cache
    pub async fn execute(&self, req: RunRequest, policy: Arc<Policy>, principal: &str,
                         events: Option<mpsc::Sender<RunEvent>>) -> RunResult;          // never panics, never Err
}
pub trait InstancePool  { async fn acquire(&self, lang: Language) -> Result<Prepared, RuntimeError>; } // naive impl
pub trait FallbackBackend { … }   // no impl (Q3 of requirements)
pub trait SessionStore    { … }   // reserved
pub trait NetworkBroker   { … }   // Phase 4 (http, tcp_connect → VirtualDevice)
```

## 2. Engine & module cache (ADR-003/004)
- **Engine:** `consume_fuel(true)`, `epoch_interruption(true)`, `max_wasm_stack(2 MiB)`, and Cranelift `opt_level=speed`. Built once per process and shared.
- **Epoch ticker:** one std thread calls `engine.increment_epoch()` every **10 ms**, stopped on drop.
- **ModuleCache (Q1):** keyed by `sha256(wasm) + Engine::precompile_compatibility_hash()`.
  - `<cache>/modules/<key>.cwasm` plus a `<key>.sha256` sidecar.
  - On load, hash the file and compare to the sidecar, then `unsafe { Module::deserialize_file }`. On a miss, compile, serialize, and write the file and sidecar atomically.
  - The `unsafe` lives in **one** reviewed function with a `// SAFETY:` comment. Only this crate opts out of `unsafe_code = deny`.
- **InstancePre** per language is built once at `Sandbox::new`, with the interposer linked via the generic `add_to_linker`.

## 3. Per-run execution
| Step | Detail |
|---|---|
| 1 | Validate the request: code ≤ 1 MiB, args ≤ 64 × 4 KiB, stdin ≤ `input_bytes`, `session` → `NotImplemented`. Apply `policy.tighten(overrides)`; widening → `PolicyViolation` + `policy.denied` audit. |
| 2 | Emit `run.start` (code sha256 and size; code only if `audit.log_code`). |
| 3 | `RunFs::create`, plus a hidden **read-only `/code` mount** holding `main.py` / `main.mjs` (Q4). |
| 4 | WASI ctx: args, env (policy literals only), stdin (memory pipe), and stdout/stderr through **`CappedStream`**, which streams chunks to `events` and stops at the cap (§4). Python args are `python -I -B -S -X frozen_modules=on /code/main.py <args>`. JS args are `qjs -m /code/main.mjs <args>` (Q5). |
| 5 | `Store<RunState { interposer, limiter }>`: `set_fuel(limits.fuel)`, epoch deadline callback (§4), `limiter(|s| &mut s.limiter)`. |
| 6 | `instance_pre.instantiate_async` → `_start.call_async`. |
| 7 | Classify the outcome (§5), `interposer.finish()`, `collect_artifacts()`, native-extension check (Q3). |
| 8 | Emit `run.end` (outcome, exit code, duration, fuel used, peak memory, limits hit, byte counts, artifact digests). Send `Finished`. Drop `RunFs`, which deletes the run dir. |

## 4. Limits
| Limit | Mechanism | On hit |
|---|---|---|
| CPU (`fuel`) | `store.set_fuel` | Trap `OutOfFuel` → `limits_hit=[cpu]` |
| Wall clock | Epoch callback: if `now ≥ deadline` → error `WallClockExceeded`, else `UpdateDeadline::Yield(1)`. Async yield every 10 ms keeps the executor fair. | `[wall_clock]`; precision about 10–20 ms |
| Memory | `ResourceLimiter::memory_growing`: deny past `limits.memory`, record the peak. Also caps tables (10k elements) and instances (1). | Guest sees a failed `memory.grow` (MemoryError/abort) → `[memory]` |
| stdout / stderr | `CappedStream`: accepts bytes up to the cap, then marks truncated, emits `LimitHit`, and makes the write fail with an I/O error (the guest usually exits). | `[stdout]` / `[stderr]`; output kept up to the cap |
| `/out` | U3 interposer live quota | `[artifacts]` |
| Inputs | U3 `RunFs::create` | `InvalidRequest` (before running) |

## 5. Outcome classification (first match wins)
1. Host error before the guest starts (cache, RunFs, policy) → `Outcome::Error` + `RunError`.
2. `I32Exit(0)` or a normal return → `Ok`. `I32Exit(n≠0)` → `Exit`, `exit_code=n`.
3. `Trap::OutOfFuel` → `Limit` + `cpu`. `WallClockExceeded` → `Limit` + `wall_clock`.
4. Other trap → if the limiter recorded a denied grow → `Limit` + `memory`, else `Trap` with a sanitized message (first line, no host paths).
5. `limits_hit` also merges stream caps, the interposer quota and the memory flag, even when the guest exited "normally" after hitting them.
6. **Native extensions (Q3):** if stderr matches `ModuleNotFoundError: No module named '<m>'` and `<m>`'s root is in the known list (numpy, pandas, scipy, sklearn, torch, tensorflow, lxml, PIL, cv2, matplotlib, pyarrow, polars, …) → `error = UnsupportedNativeExtension{module}`, keeping the outcome and output.

## 6. NFR (scaled)
- **Security:** `unsafe` only in `ModuleCache::load` (SAFETY: file hash verified against a sidecar written by this process; key includes the engine compatibility hash; cache dir is 0700/user-only). No env inheritance. `execute` catches panics (`catch_unwind` around the run future) → `Internal`.
- **Performance targets:** warm `print(1)` ≤ 150 ms (CPython) and ≤ 20 ms (QuickJS), measured by a release-mode test. `import json, csv, re` ≤ 300 ms once Q2 is done. Startup with a warm cache is about 15 ms (two deserializes).
- **Concurrency:** `Sandbox` is `Send + Sync`. Each run has its own `Store`. N concurrent runs share the engine and modules. U5 bounds N.
- **Testing:** acceptance criteria 1 (hello.py / hello.js), 2 (timeout ≤ 2.2 s; fuel), 3 (1 GB alloc under 128 MiB) and 6 (numpy). Also: output caps, exit codes, traps, stdin, args, env, `/code` read-only, artifacts round trip, 20 concurrent runs, cache hit/miss/corruption (a tampered `.cwasm` is detected and recompiled), panic isolation, and a fuel calibration report (fuel per `print(1)` and per 1M-iteration loop).

## 7. Infrastructure
None. New dependencies: `tokio` (sync), `bytes`. CI already runs the tests on 3 OSes. CPython tests take about 10 s per binary after the cache warms; CI caches `<cache>/modules` keyed by the asset hash.
