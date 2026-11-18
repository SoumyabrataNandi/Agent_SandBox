# U4 Runtime — Code Summary & Test Results (2026-11-18)

Design answers Q1–Q6: all recommended (verified disk module cache, in-sandbox `compileall`, post-run native detection, read-only `/code`, ES modules, fuel + wall clock with calibration).

| File | Content |
|---|---|
| `src/sandbox.rs` | `Sandbox::new` (engine with fuel + epoch, cache load, stdlib + bytecode, `InstancePre` ×2, 10 ms epoch ticker) and `Sandbox::execute`: validation → tighten → `run.start` → RunFs + `/code` → WASI ctx → limits → run with outer timeout → classification → artifacts → native detection → `limit.hit` / `run.end`. Panics are isolated via `tokio::spawn` + `JoinError` |
| `src/cache.rs` | `ModuleCache` (the only `unsafe`, with a SAFETY comment: sha256 sidecar verified before `deserialize_file`; key = asset sha + engine compat hash + crate version; atomic writes; corrupt → recompile). `ensure_bytecode` runs `compileall --invalidation-mode unchecked-hash` inside the sandbox once |
| `src/stream.rs` | `CappedStream`: wasmtime-wasi `StdoutStream` that streams chunks, caps bytes, and fails writes after the cap |
| `src/native.rs` | Post-run `ModuleNotFoundError` parser + list of 46 native packages |
| `src/types.rs` | `Language`, `RunRequest`, `RunResult`, `RunEvent`, `RunError` (stable codes), `Timings` |
| `src/seams.rs` | `FallbackBackend`, `SessionStore`, `NetworkBroker` (interfaces only) |
| `tests/runtime.rs` | 19 integration tests against real CPython 3.15 + QuickJS-ng 0.18 |

**Tests:** 21 (2 unit + 19 integration). Workspace total: **69**. fmt and clippy `-D warnings` are clean.

## Acceptance criteria covered
| AC | Test | Result |
|---|---|---|
| 1 hello.py / hello.js | `ac1_*` (JS: ES module, top-level await, `qjs:std`) | ✅ |
| 2 timeout ≤ 2.2 s / fuel | busy loop 2 s → `wall_clock` (run ≤ 2.2 s); `time.sleep(30)` with 1 s → `wall_clock` (outer timeout covers host calls); fuel 200M → `cpu`; JS `for(;;)` → `wall_clock` | ✅ |
| 3 1 GB alloc under 128 MiB | `[memory]`, peak ≤ 128 MiB, next run healthy | ✅ |
| 6 numpy | `UNSUPPORTED_NATIVE_EXTENSION{numpy}`; a comment mentioning numpy is not flagged | ✅ |

Also: stdout cap, exit codes, tracebacks (`File "/code/main.py", line 2`), stdin/args/env, `/code` read-only, inputs → artifacts round trip, override widening refused, sessions → `NotImplemented`, streamed events end with `Finished`, 20 concurrent runs, the audit trail, and **cache tamper detection**.

## Performance (debug build of host code; guest code is Cranelift-compiled either way)
| Workload | Total ms | Fuel |
|---|---|---|
| Cold `Sandbox::new` (compile both + stdlib + bytecode) | 34 600 | — |
| **Warm `Sandbox::new` (cache hit)** | **107** | — |
| Python `print(1)` | 183 | 58 M |
| Python `import json, csv, re, datetime` | **158** (433 without .pyc) | 138 M |
| Python 1M-iteration loop | 580 | 2.7 G |
| JS `console.log` | **6** | 2.4 M |
| JS 1M-iteration loop | 74 | 665 M |
| 20 concurrent Python runs | 1 290 (all) | — |

NFR-3 (CPython ≤ 300 ms, QuickJS ≤ 50 ms): ✅ met. The release build is faster still (86–116 ms measured in design).

## Calibration finding → policy default changed
CPython burns about **4.7 G fuel per CPU-second**. The U1 default `fuel = 2G` stopped a plain 1M-iteration loop (0.4 s CPU) while the 5 s wall clock still had room. **The default is now `20G` (≈ 4 s CPU)**, so the wall clock is the binding limit by default and fuel is the deterministic backstop. Policy tests are unaffected (range is unchanged).

## Fixes made during testing
1. CPython 3.15 appends a hint after `No module named 'numpy'`, so the parser now extracts the quoted name. A regression case with the exact 3.15 text was added.
2. Outcome rule: a non-zero exit **caused by** a limit (e.g. a write error after the stdout cap) is `Limit`, not `Exit`. The exit code is kept.
3. The test harness built the shared Sandbox inside a tokio runtime. It now warms up on its own thread.
