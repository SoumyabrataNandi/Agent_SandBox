# Cycle 2 — Build & Test Summary

**Scope:** Phase 4 network broker + OTLP exporter (units C2-U1 … C2-U5), approved 2026-11-19.
**Commits:** 4af38c2 (C2-U1) · fe6d08a (C2-U2) · 20c3ee6 (C2-U3) · 0b67631 (C2-U4) · f0036df (C2-U5), all on `origin/main`.

## Build
| Build | Command | Result |
|---|---|---|
| Default | `cargo build --release -p sandboxd` | ok. **No** OpenTelemetry/prost crates (`cargo tree`, CI-enforced) |
| OTLP | `cargo build --release -p sandboxd --features otel` | ok. A single reqwest 0.13 shared with the broker |
| Lint | `cargo clippy --workspace --all-targets --locked -D warnings` (+ the `otel` variant) | clean |
| Format | `cargo fmt --check` | clean |
| Supply chain | `cargo deny check` (all features) | advisories, bans, licenses, sources ok. ISC/CDLA re-allowed for the TLS stack (C2-U2); RUSTSEC-2026-0543 (chrono via rmcp) ignored and tracked |

## Tests (local, Windows, CI flags)
| Suite | Tests |
|---|---|
| `sandboxd-net` (unit + proptest / broker integration) | 15 / 11 |
| `sandboxd-runtime` (unit / network / runtime) | 6 / 14 / 20 |
| `sandboxd-server` (unit / server / OTLP with `otel`) | 3 / 9 / 2 |
| `sandboxd-policy`, `sandboxd-audit`, `sandboxd-vfs`, `sandboxd-assets`, CLI | 27, 13, 11, 2, 5 |
| **Escape suite** (release gate): cycle 1 / **E-NET** | 17 / **11** |
| **Total** | **166** (136 workspace + 28 escape + 2 `otel`). Cycle 1 ended at 107 + 17. |

Performance (release, fuel = deterministic instruction count): Python `print(1)` 58.07 M vs 58.03 M before cycle 2; JavaScript `console.log` +1.4 M (< 1 ms). Broker overhead per HTTP request is 0.36–0.54 ms (NFR-N3 target: 5 ms).

## Acceptance criteria
AC 1–10 are mapped to evidence in [c2-u5-enet-release/summary.md](../c2-u5-enet-release/summary.md#cycle-2-acceptance-criteria), and all pass locally. For AC 10, the GitHub Actions run of f0036df (4 OS runners, the `otel` job, Node 24 actions) is the CI confirmation. The user approved closing the cycle on 2026-11-19; that run was not observed from this session (no `gh` CLI).

## Defects found and fixed during cycle 2
| Unit | Defect | Fix |
|---|---|---|
| C2-U1 | `max_requests` default 0 (latent once grants became allowed) | Default 100 |
| C2-U2 | reqwest retries on by default (an un-audited extra request) | Retries off |
| C2-U2 | TLS errors classified as CONNECT | Classifier looks inside `io::Error` |
| C2-U2 | Feature-unified reqwest TLS made rmcp's client panic without a crypto provider | `ensure_crypto_provider()` |
| C2-U3 | CPython `open()` on virtual fds failed (`fd_filestat_get`) | Interposer fix |
| C2-U3 | Bootstrap frames in tracebacks; half-built `HTTPResponse` on failure; JS method `FALSE` | Fixed; tracebacks byte-identical to cycle 1 |
| C2-U3 | Bootstrap cost +31 M fuel per Python run (CPython AST init on the first `compile()`) | `.pyc` helpers + bootstrap only when networking is possible |
| C2-U4 | OTLP client panicked without a rustls provider | `Telemetry` installs it |
| C2-U4 | A stdlib cache that lost the empty `lib-dynload` dir printed warnings on every run | `ensure_stdlib` restores it |
| C2-U5 | — (E-NET found no isolation defect) | — |

## Carried forward
- **Cycle 3:** Phase 5 performance (wizer snapshots, instance pooling, sessions, Docker benchmarks).
- **Residual risks:** R8–R10 (THREAT_MODEL.md).
- **Watch:** one unreproduced `twenty_concurrent_runs` failure under heavy local load; it now has diagnostics.
