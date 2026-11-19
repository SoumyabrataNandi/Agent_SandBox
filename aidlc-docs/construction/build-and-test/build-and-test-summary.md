# Build & Test Summary — sandboxd cycle 1 (Phases 1–3)

**Date:** 2026-11-18 · **Host:** Windows 11 (no admin), Rust 1.100.0, portable MSVC 14.52 · **Repo:** github.com/SoumyabrataNandi/Agent_SandBox

## How to build and test
```powershell
. .\scripts\dev-env.ps1                       # Windows without admin (see docs/DEV_SETUP.md)
python scripts/fetch-assets.py                # pinned, hash-verified interpreters
cargo build --release -p sandboxd
cargo test --workspace -- --test-threads=4    # unit + integration + escape suite
cargo test --release -p sandboxd-runtime --test perf -- --ignored --nocapture
```
The first test run compiles the interpreters and the stdlib bytecode (about 30 s) into a shared cache. After that, the full suite takes about 1–2 minutes.

## Test inventory
| Crate | Unit | Integration | Notes |
|---|---|---|---|
| sandboxd-assets | 2 | — | pins, magic bytes; build refuses tampered assets |
| sandboxd-policy | 4 | 20 | incl. TOML↔YAML parity (AC 9), proptests |
| sandboxd-audit | 3 | 9 | redaction, backpressure, fail-closed |
| sandboxd-vfs | 4 | 6 | real CPython through the interposer |
| sandboxd-runtime | 2 | 20 (+1 perf) | AC 1, 2, 3, 6; cache tamper; recursion regression |
| sandboxd-server | 2 | 9 | AC 7 (in-memory + HTTP), AC 8 |
| sandboxd (bin) | — | 5 | real binary; AC 7 via stdio child process |
| **escape-suite** | — | **17** | release gate (AC 4, 5, 10) |
| **Total** | **17** | **86** | **103 passing**, + 1 perf |

## Acceptance criteria
| AC | Status | Evidence |
|---|---|---|
| 1 hello.py / hello.js on 3 OSes | ✅ Windows, Linux x64/arm64, macOS (CI 2026-11-19) | runtime `ac1_*`, CLI tests |
| 2 timeout ≤ 2.2 s; fuel → cpu | ✅ | runtime `ac2_*`, E-CPU |
| 3 1 GB under 128 MiB contained | ✅ | runtime `ac3_*`, E-MEM |
| 4 no host data; denials audited | ✅ | E-FS-1…5, E-ENV, canaries |
| 5 ro input; `/out` artifact with sha256 | ✅ | vfs + runtime round trip, E-FS-4 |
| 6 numpy → UNSUPPORTED_NATIVE_EXTENSION | ✅ | runtime `ac6_*`, MCP test |
| 7 MCP from Claude | ✅ | stdio child process, in-memory, HTTP + token |
| 8 auth + bind safety | ✅ | server + CLI tests, E-AUTH |
| 9 TOML/YAML parity | ✅ | policy golden tests |
| 10 escape suite on 3 OSes | ✅ all 4 CI runners (2026-11-19) | escape-suite (CI job `escape-suite`) |

## NFR status
| NFR | Status |
|---|---|
| NFR-1 3 OSes first-class | ✅ test + escape-suite green on ubuntu x64/arm64, macOS, Windows (CI) |
| NFR-2 single binary, embedded assets | ✅ release binary embeds both interpreters (≈16.5 MB + deps) |
| NFR-3 latency | ✅ 92 ms / 149 ms / 6 ms (release) |
| NFR-4 security baseline + escape suite | ✅ one `unsafe` (documented); 2 defects found and fixed; threat model final |
| NFR-6 observability | ✅ JSONL audit + Prometheus; ⚠ OTLP deferred (R6) |
| NFR-7 license | ✅ Apache-2.0; third-party licenses shipped in release archives |

## Open items for the user
1. ✅ CI green on all OSes except the supply-chain job, which was fixed 2026-11-19 (zip 9, humantime removed, publish=false, scoped chrono ignore). Make `escape-suite` and `supply chain` **required status checks** for `main`.
2. To cut a release: `git tag v0.1.0 && git push origin v0.1.0` → review the draft release → publish.
3. Deferred to the next cycle: OTLP exporter (R6); Phase 4 network broker (ADR-002); Phase 5 snapshots/pooling/sessions/benchmarks.
