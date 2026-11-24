# Cycle 4 Requirements — Ship and pilot

**Status:** Approved (user blanket approval, all recommended defaults) · **Date:** 2026-11-24 · **Answers:** Q1–Q7 all A.
Cycle 1–3 requirements stay in force. This cycle adds no sandbox features; it makes sandboxd installable, keeps it patched, and proves the agent path end to end.

## 1. Intent
Publish the first release (v0.1.0) that people can download and verify, make security advisories surface on their own instead of on the next push, and run a repeatable agent-style pilot over MCP that fixes what it finds.

**Out of scope:** new sandbox features (packages, native-extension fallback), a container image, publishing the release (a human step), an external security audit.

## 2. Functional requirements

### FR-SC1 Supply-chain automation (Q2)
- **SC1.1** `.github/dependabot.yml`: weekly updates for `cargo` (grouped minor/patch, one PR) and `github-actions`.
- **SC1.2** `.github/workflows/security.yml`: daily schedule + `workflow_dispatch`, against `main`: `cargo deny check advisories` and `cargo audit`.
- **SC1.3** On failure: open one issue titled `Security advisory affects main` with label `security`, or comment on it if it's already open; include the advisory IDs. On success with the issue open: comment and close it.
- **SC1.4** Every run writes `security/latest.json` (`{sha, date, ok, advisories[]}`) to the `ci-results` branch.
- **SC1.5** Least privilege: `contents: write` only for the `ci-results` push, `issues: write` only for the issue step.

### FR-SP1 Security policy (Q3)
- **SP1.1** `SECURITY.md`: private reporting through GitHub security advisories; scope (sandbox escape, policy/limit bypass, cross-principal or cross-session access, audit evasion, host DoS through the API); out of scope (code that a policy intentionally grants); supported versions (latest release); acknowledgement within 3 working days, fix target for critical issues within 14 days; references to `THREAT_MODEL.md` and the escape suite.

### FR-PL1 MCP pilot (Q4)
- **PL1.1** `scripts/pilot/mcp_pilot.py` (standard library only, `python -I` safe): starts `sandboxd mcp` with a temporary config (temp cache/work dirs, a session-enabled `notebook` policy), performs `initialize` / `notifications/initialized`, and exits non-zero on any failed check. Prints a summary table; `--json` writes results.
- **PL1.2** Scenarios, each with explicit checks:
  1. `tools/list` has `run_code`, `list_policies`, `session_create`, `session_close`; the server's `instructions` mention the stdlib-only rule.
  2. `list_policies` lists `default` and `notebook`.
  3. Python CSV analysis: CSV in `files`, aggregate with `csv` + `statistics`, JSON on stdout, a chart-like file to `/out` returned as an embedded resource.
  4. A Python exception returns `isError`-style content with a traceback that names the user's line.
  5. An infinite loop with `limits.wall_clock` hits the limit quickly and says which limit.
  6. `import numpy` returns the documented unsupported-native-extension guidance.
  7. JavaScript run with JSON processing.
  8. Session: create, three cells building state (variable, import, `/work` file), close, then a call to the closed session fails cleanly.
  9. Progress streaming: a run with a progress token produces progress notifications carrying stdout.
  10. Bad input: unknown language / unknown policy produce clear errors, not a crash; the server stays usable afterwards.
- **PL1.3** CI job `mcp pilot` on ubuntu-latest and windows-latest after `test`.
- **PL1.4** Findings are recorded in the unit summary; each is fixed in this cycle or logged as a cycle 5 candidate.

### FR-DOC1 Getting started and changelog (Q5)
- **DOC1.1** `docs/GETTING_STARTED.md`: download, verify (`sha256sum -c`, `gh attestation verify`), first run, Claude Code / Claude Desktop, HTTP service with a token, a first policy, where the cache/audit live, troubleshooting.
- **DOC1.2** `CHANGELOG.md` with a `[0.1.0] - 2026-11-24` entry summarising cycles 1–4.
- **DOC1.3** README: an Install section pointing to releases and the guide; the Quick start keeps the build-from-source route.
- **DOC1.4** `release.yml` ships `GETTING_STARTED.md`, `CHANGELOG.md` and `SECURITY.md`, and uses the changelog entry for the tag as the draft's release notes (with the existing verification line).

### FR-R1 Release v0.1.0 (Q6)
- **R1.1** Tag `v0.1.0` on a commit whose CI run is fully green.
- **R1.2** `release.yml` succeeds on all 5 targets (escape suite per target) and creates a draft release with 5 archives + `SHA256SUMS`.
- **R1.3** Release-workflow problems found by the first run (e.g. the untested `macos-15-intel` target) are fixed and the tag is re-pointed only if no release was published from it.
- **R1.4** The user publishes the draft.

## 3. Non-functional
- **NFR-4.1** No change to sandbox behaviour; all existing suites stay green.
- **NFR-4.2** New scripts are stdlib-only Python, run with `python -I`.
- **NFR-4.3** Workflows pin action majors as the existing ones do and run on Node 24.

## 4. Acceptance criteria
1. Dependabot config is valid (GitHub shows no config error) and `security.yml` runs green via `workflow_dispatch` or schedule, writing `security/latest.json`.
2. `SECURITY.md` is present and linked from the README.
3. The MCP pilot passes locally (Windows) and in CI (Linux + Windows); findings are recorded.
4. Getting-started guide and changelog exist; README links them.
5. A `v0.1.0` draft release exists with 5 archives and `SHA256SUMS`, each built after its escape suite passed.
