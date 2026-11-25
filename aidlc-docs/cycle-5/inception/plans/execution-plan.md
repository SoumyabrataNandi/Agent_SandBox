# Cycle 5 Execution Plan — First start, packages, container

**Inputs:** `cycle-5/inception/requirements/requirements.md` (approved 2026-11-24, all defaults).

## Change impact
| Dimension | Assessment |
|---|---|
| Type | Brownfield. `sandboxd` (mcp start-up, config, `packages` command), `sandboxd-server` (deferred service in MCP, config), `sandboxd-runtime` (wheelhouse validation/extraction, mount, boot helpers), `sandboxd-vfs` (`Packages` mount kind), `sandboxd-policy` (`[python] packages`), packaging + release workflow |
| Security impact | **Medium.** Packages add operator-supplied code to the guest's import path (read-only, appended, pure Python, hash-lockable). Wheel extraction is a classic traversal/zip-bomb surface (validated, size-capped). The image runs as non-root |
| Risk hot spots | (1) Snapshot + session paths must also see the mount. (2) Zip handling on the host (traversal, symlinks, bombs). (3) A deferred service vs. shutdown ordering. (4) buildx multi-arch in the release workflow (first run) |

## Stage decisions
| Stage | Decision |
|---|---|
| Reverse Engineering, User Stories | ⏭ Skip (artifacts current; AC in requirements) |
| Application Design | ⏭ Light: decisions are in the answers; per-unit summaries record the design |
| Units | C5-U1 start-up · C5-U2 packages · C5-U3 container · C5-U4 release v0.2.0 |
| Code generation / Build & test | ▶ Always |

## Units
| # | Unit | Covers | Verification |
|---|---|---|---|
| C5-U1 | Non-blocking MCP start-up | FR-ST1 | server tests (deferred ready, startup failure); pilot `initialize` < 2 s on a cold cache |
| C5-U2 | Operator wheelhouse | FR-PK1 | runtime tests (fresh/snapshot/session imports, opt-out, read-only, no shadowing), validation unit tests, escape cases |
| C5-U3 | Container image | FR-CI1 | release-run smoke test; GHCR push |
| C5-U4 | Release v0.2.0 | FR-R2 | draft release + image |

**Order:** U1 → U2 → U3 → U4.
