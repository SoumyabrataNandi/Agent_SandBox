# C4-U3 Getting started, changelog, release packaging — Summary

**Requirements:** FR-DOC1 · **AC:** 2, 4

- **`docs/GETTING_STARTED.md`**: download (platform table), verify (`sha256sum --ignore-missing -c`, `gh attestation verify`, PowerShell `Get-FileHash`), install and **`sandboxd cache warm`** (pilot finding F1), first run, Claude Code / Claude Desktop, HTTP service with a token and TLS advice, a first policy, and a troubleshooting table (first-start timeout and `MCP_TIMEOUT`, native extensions, unknown policy, ended sessions, limits, disk space).
- **`CHANGELOG.md`** (Keep a Changelog): `[0.1.0] - 2026-11-24` covering cycles 1–4, the two security upgrades, and known limitations.
- **README**: new Install section (releases, guide, changelog, SECURITY.md); "Quick start" renamed "Quick start (from source)".
- **`release.yml`**:
  - archives also ship `SECURITY.md`, `CHANGELOG.md` and `GETTING_STARTED.md`;
  - the draft's notes are the changelog section for the tag (extracted with awk; the job fails if the section is missing), followed by the verification line and a link to the guide.

Verification: the awk extraction was run locally against CHANGELOG.md for 0.1.0; YAML parses. The packaging change is exercised by the v0.1.0 release run (C4-U4).
