# Cycle 3 Execution Plan — Performance (Phase 5)

**Inputs:** approved `cycle-3/inception/requirements/requirements.md` (2026-11-19).

## Change impact
| Dimension | Assessment |
|---|---|
| Type | Brownfield. Runtime internals are reworked (allocator, instantiation, a persistent-instance mode), there are new server endpoints and MCP tools, and there is a new **build pipeline for interpreters** |
| Security impact | **High.** Pooling reuses memory across runs; sessions keep state across calls; snapshots bake state into a module. Each could leak data between runs or principals if done wrong (NFR-P2) |
| Touched crates | runtime (pool, snapshot restore, session instances), vfs (session `/work`, per-call `/out`), policy (`[runtime]`?, `[session]` keys), server (session store, endpoints, MCP tools, metrics), audit (session events, `session_id`), assets (custom interpreter entries), escape suite |
| New pieces | `.github/workflows/interpreters.yml` (wasi-sdk builds + release), `.github/workflows/bench.yml`, `scripts/bench/`, guest session loop helper, `wasmtime-wizer` dependency |
| API impact | Additive: `/v1/sessions*`, MCP `session_*`, `run_code.session_id`, `[runtime]`/`[session]` keys, `session.*` audit events |
| Risk hot spots | (1) Building CPython for WASI with an init export, and keeping behaviour byte-identical after restore (argv/env/hash seeds). (2) Re-applying per-run WASI state to a pre-initialised instance (preopens/fds captured at init). (3) Wizer/wasmtime version alignment. (4) Pooling sizing vs. per-policy memory limits. (5) Session lifecycle races (expiry vs. an in-flight call). (6) CI-only builds and auth for downloading private release assets on the laptop |

## Stage decisions
| Stage | Decision | Why |
|---|---|---|
| Reverse Engineering | ⏭ Skip | Cycle-1/2 artifacts are current |
| User Stories | ⏭ Skip | Acceptance criteria in the requirements |
| **Application Design** | ▶ Execute | ADRs needed: interpreter build + init export; snapshot creation/restore and per-run state injection; pool sizing/fallback; session architecture (instance ownership, guest loop protocol, store, expiry); bench harness design |
| **Units Generation** | ▶ Execute (light) | 6 units with a **spike gate** |
| Functional Design | ▶ Per unit | Session protocol/lifecycle and snapshot restore need precise definition |
| NFR Requirements / Design | ▶ Per unit (scaled) | Threat-model additions (cross-run leakage, session ownership, snapshot integrity) and new escape cases |
| Infrastructure Design | ▶ Execute (light) | Two new CI workflows (interpreter builds + release, benchmarks); asset fetch authentication |
| Code Generation / Build & Test | ▶ Always | |

## Preliminary units
| # | Unit | Covers | Depends on | Gate |
|---|---|---|---|---|
| C3-U1 | **Snapshot spike**: CI interpreter builds (CPython 3.15 + QuickJS-ng with init export, pinned wasi-sdk), Wizer pre-init, measurement | FR-S1.0, S1.1 (build workflow) | — | **Go/no-go** on AC 2. No-go → FR-S1 deferred; U3 is dropped |
| C3-U2 | **Pooling allocator** | FR-P1 | — | Normal |
| C3-U3 | **Snapshot integration**: fetch/pin custom assets, Wizer at start-up with preloads, cache + sidecar, per-run restore, `[runtime] snapshots` | FR-S1.1–S1.6 | U1 go, U2 | Full flow |
| C3-U4 | **Sessions**: policy keys, runtime persistent instance + guest loop, session store/expiry, HTTP + MCP, audit | FR-SE1 | U2 (U3 optional: sessions work on either interpreter path) | Full flow |
| C3-U5 | **Benchmarks**: `scripts/bench/`, `bench.yml`, `docs/BENCHMARKS.md` | FR-B1 | U2–U4 | Light |
| C3-U6 | **Escape cases, threat model, docs, release** | NFR-P2, AC 1/3/6/7/10, THREAT_MODEL, README/MCP docs | all | Medium |

**Build order:** U1 (spike, runs mostly in CI) and U2 **in parallel** → U3 → U4 → U5 → U6. If the spike is no-go: U2 → U4 → U5 → U6.

**Practical note:** U1's builds happen only on GitHub Actions (NFR-P6). Each iteration is: push → you run or confirm the workflow → I read its results. I can't see Actions from here (no `gh` CLI), so I'll ask you for the run results or the logs I need, or design the workflow to commit a small results file back to the repo, which I can pull. Application Design picks the mechanism.

## Success criteria
- Cycle-3 AC 1–10 pass, or AC 2/3 are formally deferred after a no-go.
- No regressions in the 166 cycle-1/2 tests or E-NET.
- Published `docs/BENCHMARKS.md` from the CI job.
- cargo-deny and cargo-audit pass with no new ignores.
