# Cycle 4 Execution Plan — Ship and pilot

**Inputs:** `cycle-4/inception/requirements/requirements.md` (approved 2026-11-24, all defaults).

## Change impact
| Dimension | Assessment |
|---|---|
| Type | Brownfield. Repo automation, docs, a pilot script, a release. No crate changes unless the pilot finds a defect |
| Security impact | Positive: advisories surface daily; disclosure policy. New workflow permissions are scoped per job |
| Risk hot spots | (1) `release.yml` has never run; `macos-15-intel` is untested. (2) The pilot may find real MCP defects that need crate changes. (3) Issue automation needs `issues: write` and must not spam |

## Stage decisions
| Stage | Decision | Why |
|---|---|---|
| Reverse Engineering | ⏭ Skip | Cycle 1–3 artifacts current |
| User Stories | ⏭ Skip | Acceptance criteria in requirements |
| Application Design | ⏭ Skip | No new components; decisions are in the requirements answers |
| Units Generation | ▶ Light (below) | |
| Functional / NFR / Infra design | ▶ Combined into each unit's summary | Small units |
| Code Generation / Build & Test | ▶ Always | |

## Units
| # | Unit | Covers | Verification |
|---|---|---|---|
| C4-U1 | Supply-chain automation + `SECURITY.md` | FR-SC1, FR-SP1 | Workflow lint by GitHub on push; `security.yml` green on dispatch/schedule; `security/latest.json` on `ci-results` |
| C4-U2 | MCP pilot + fixes | FR-PL1 | Pilot passes locally and in the new CI job on Linux + Windows |
| C4-U3 | Getting started, changelog, release packaging | FR-DOC1 | Docs reviewed; release.yml packaging change exercised by U4 |
| C4-U4 | Release v0.1.0 | FR-R1 | Draft release with 5 archives + `SHA256SUMS` (public API) |

**Order:** U1 → U2 → U3 → (CI green) → U4. Approval: blanket (user, 2026-11-24); each unit is committed and pushed when done.
