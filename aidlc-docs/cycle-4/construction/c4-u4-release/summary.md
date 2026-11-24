# C4-U4 Release v0.1.0 — Summary

**Requirements:** FR-R1 · **AC:** 5

## Before the tag
- Dependabot's first 3 PRs were merged after their CI passed:
  - #2: `toml`, `zip`, `clap` patches;
  - #3: `sha2` 0.11.1;
  - #1: actions checkout 7, setup-python 7, cache 6, upload-artifact 7, download-artifact 8, attest-build-provenance 4. Their breaking changes don't affect us: the checkout change concerns `pull_request_target` (unused); download-artifact now fails on a hash mismatch (safer).
- The workspace compiles locally with the merged dependencies (`cargo check --workspace --all-targets --locked`).
- CI on `main` at d4fe4f5 (run 45390124962) was green: 4 OSes, test + MCP pilot, escape suite, otel, perf smoke, supply chain.

## Release
- Annotated tag `v0.1.0` → d4fe4f5.
- Release workflow run 45398159049 succeeded. All 5 targets passed (x86_64/aarch64 Linux, aarch64/x86_64 macOS, x86_64 Windows), each running the escape suite before building, with build-provenance attestation. `draft-release` then created the draft with the archives, `SHA256SUMS` and notes from CHANGELOG.md.
- `macos-15-intel` (never built in CI before) passed first time; no workflow fixes were needed.

## Remaining (owner)
- Review and **publish** the draft (Releases → sandboxd v0.1.0 → Publish). Drafts aren't visible through the anonymous API, so the asset list is checked on publish.
- Enable private vulnerability reporting (Settings → Code security), referenced by SECURITY.md.
