# Cycle 2 Execution Plan — Network Broker + OTLP

**Inputs:** approved `cycle-2/inception/requirements/requirements.md` (2026-11-19).

## Change impact
| Dimension | Assessment |
|---|---|
| Type | Brownfield feature addition + one new crate |
| Security impact | **Very high.** This opens the first egress path out of the sandbox, so SSRF, exfiltration and redirect abuse are the main risks |
| Touched cycle-1 crates | policy (schema, `ensure_supported`), audit (event fields, `LimitKind::Network`), runtime (device wiring, bootstraps, guest helpers mount), server (config, OTLP), escape suite |
| New crate | `sandboxd-net` (broker: allowlist, URL normalization, SSRF, DNS pinning, HTTP client, TLS trust, proxy, TCP, quotas, audit) |
| API impact | Additive only (NFR-N6) |
| Risk hot spots | Getting a pinned-IP HTTPS client right (SNI + verification against the hostname); guest-side shims that keep `urllib`/`fetch` faithful; Windows trust store behaviour |

## Stage decisions
| Stage | Decision | Why |
|---|---|---|
| Reverse Engineering | ⏭ Skip | Cycle-1 artifacts are current |
| User Stories | ⏭ Skip | Same as cycle 1; acceptance criteria are in the requirements |
| **Application Design** | ▶ Execute | New crate boundaries; ADRs for the HTTP client stack, the device wire protocol and the guest bootstrap mechanism |
| **Units Generation** | ▶ Execute (light) | 5 units with a clear order |
| Functional Design | ▶ Per unit | Matching/normalization rules, SSRF ranges, protocol envelope and shim behaviour need precise definition |
| NFR Requirements / Design | ▶ Per unit (scaled) | A threat-model extension (T13+) and E-NET mapping |
| Infrastructure Design | ▶ Light | Local test servers + a test CA in CI; `otel` feature job |
| Code Generation / Build & Test | ▶ Always | |

## Preliminary units
| # | Unit | Covers | Depends on |
|---|---|---|---|
| C2-U1 | Policy, config and audit extensions | FR-N11, N3.1 `scheme`, N6 timeouts, `LimitKind::Network`, `net.request`/`net.connect` fields | — |
| C2-U2 | **`sandboxd-net` broker core** | FR-N1, N3–N10 (host side) | C2-U1 |
| C2-U3 | Guest integration | FR-N2 (Python `sandbox_net` + urllib/socket shims; JS `fetch`), runtime device registration, bootstraps, embedded helper mount | C2-U2 |
| C2-U4 | OTLP exporter | FR-O1 (`otel` feature) | C2-U1 (independent of U2/U3) |
| C2-U5 | E-NET escape suite + CI | NFR-N1/N2, AC 1–10 end to end, threat model T13+ | C2-U2, C2-U3 |

**Build order:** U1 → U2 → U3 → U5. U4 can be built any time after U1 (planned in parallel with U2).

## Success criteria
- Cycle-2 AC 1–10 pass.
- E-NET passes on all 4 CI runners.
- No regressions in the 103 cycle-1 tests or the perf smoke.
- cargo-deny and cargo-audit pass with no new ignores.
