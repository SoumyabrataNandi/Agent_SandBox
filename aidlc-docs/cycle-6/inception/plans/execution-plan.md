# Cycle 6 Execution Plan — Client libraries, container checks, gVisor

**Inputs:** `cycle-6/inception/requirements/requirements.md` (approved 2026-11-26, all defaults).

## Change impact
| Dimension | Assessment |
|---|---|
| Type | Brownfield, additive. New `clients/python` and `clients/js`; new `container.yml`; `packaging/container/smoke.sh`; edits to `ci.yml`, `release.yml`, `bench.yml` and docs. No Rust changes are planned |
| Security impact | **Low.** Clients are callers of the existing API (no new server surface). They must not log tokens, and must keep TLS verification on by default. The container check has read-only permissions |
| Risk hot spots | (1) SSE parsing in two languages. (2) Python 3.10 compatibility with stdlib-only code. (3) First run of the new workflows (only CI can run Docker) |

## Stage decisions
| Stage | Decision |
|---|---|
| Reverse Engineering, User Stories | ⏭ Skip (artifacts current; AC in requirements) |
| Application Design | ⏭ Light: the clients mirror the HTTP API; unit summaries record the design |
| Units | C6-U1 container check · C6-U2 gVisor · C6-U3 Python client · C6-U4 JS client · C6-U5 release v0.3.0 |
| Code generation / Build & test | ▶ Always |

## Units
| # | Unit | Covers | Verification |
|---|---|---|---|
| C6-U1 | Container check | FR-CT1 | first `container` run green; release uses the same script |
| C6-U2 | gVisor comparator | FR-GV1 | tarball install verified locally (layout + checksum); bench run by the owner |
| C6-U3 | Python client | FR-CL1, CL2 | unit tests + integration tests against `sandboxd serve` (local + CI) |
| C6-U4 | JavaScript client | FR-CL1, CL2 | `node --test` against `sandboxd serve` (local + CI); `tsc` type check of the declarations |
| C6-U5 | Release v0.3.0 | FR-CL2, FR-R3 | draft release with the client packages and the image |

**Order:** U1 → U2 → U3 → U4 → U5 (U1 and U2 are small and independent).
