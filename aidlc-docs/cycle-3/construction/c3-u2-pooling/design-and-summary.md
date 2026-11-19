# C3-U2 Pooling Allocator — Design & Code Summary (combined gate)

**Requirement:** FR-P1 (P1.1–P1.4), AC 1 · **ADR:** ADR-C3-3

## Design
| Decision | Choice | Why |
|---|---|---|
| Mode | `[runtime] pooling = "auto" \| "on" \| "off"` (server config; default `auto`). `RuntimeConfig.pooling` + `pool_slots` (library default: `Auto`, 64). | P1.1. `on` makes a pool failure a start-up error; `auto` falls back and logs it. |
| Slot size | wasmtime's default pool limits: **4 GiB per memory slot** (the whole wasm32 range, already the default reservation on 64-bit), 20,000 table elements, 1 MiB instance metadata. Measured: CPython's table has 6,005 entries, QuickJS's 595. | No policy memory limit can exceed a slot, so sizing reduces to the **slot count**. The policy limit is still enforced by our `ResourceLimiter`. |
| Slot count | Binary: `max_concurrent + 2` (start-up tasks: stdlib/helper bytecode, probes). C3-U4 adds `session.max_sessions`. | ADR-C3-3 |
| No failures from exhaustion | A semaphore with one permit per slot is held for each run's `Store` lifetime. When all slots are busy, runs **wait** (inside the admission window) instead of failing. | P1.3 |
| Early validation | With pooling, both interpreters are instantiated once at start-up (`probe_instantiate`, no `_start`). Pool limits therefore fail during warm-up, where `auto` can fall back, never in a run. | P1.3 |
| Reset | wasmtime resets or decommits linear memory when a slot is reused (copy-on-write memory init where supported). | P1.2 |
| Cache | The `.cwasm` key already includes `Engine::precompile_compatibility_hash()`, so pooled and on-demand engines keep separate, valid caches. | — |
| Metrics | `sandboxd_pool_slots` and `sandboxd_pool_slots_in_use` (Prometheus), plus `sandboxd.pool.*` (OTLP). Updated around every run and at start-up. | P1.4 |

## Files
- `Cargo.toml`: wasmtime feature `pooling-allocator`.
- `crates/sandboxd-runtime/src/sandbox.rs`: `PoolingMode`, `PoolStatus`; `Sandbox::new` dispatches to `build(pool)` with fallback; `PoolingAllocationConfig`; `probe_instantiate`; slot semaphore; `pool_status()`. `WarmupReport` gains `pooling` and `pooling_fallback`, and is no longer `Copy`.
- `crates/sandboxd-server`: `[runtime] pooling` config + test; `Metrics::pool_set`; OTel gauges; `RunService::pool_status`.
- `crates/sandboxd/src/main.rs`: pooling mode and slot count from config/admission; warning on fallback.
- `crates/sandboxd-runtime/tests/pool.rs` (new).

## Tests
| Test | Proves |
|---|---|
| `pooled_memory_is_reset_between_instances` | **AC 1:** 200 consecutive instances on the pooled engine. Each grows to 64 pages and must see **all zeros**, then fills them with a canary. Any remnant of a previous instance fails the test (slot affinity makes reuse the normal case). |
| `runs_work_and_slots_are_released` | Python + JS runs on the pool; `in_use` returns to 0 |
| `more_concurrent_runs_than_slots_wait_instead_of_failing` | 2 slots, 8 concurrent runs: all succeed, in order of arrival |
| `auto_falls_back…` / `off_uses_on_demand…` | A 0-slot pool: `auto` → on-demand + recorded reason; `on` → error. `off` → no pool |
| `runtime_pooling_mode` (server) | Config parsing incl. invalid values and unknown keys |
| Existing suites | All runtime (20), network (14) and server tests and the escape suite now run **pooled by default** |

Performance numbers (pooled vs. on-demand, Linux with copy-on-write init) are measured by the C3-U5 benchmark job. On Windows, pooling works but isn't tuned by wasmtime (NFR-P5).
