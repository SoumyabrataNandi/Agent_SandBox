# C4-U1 Supply-chain automation and security policy — Summary

**Requirements:** FR-SC1, FR-SP1 · **AC:** 1, 2

## What was added
- **`.github/dependabot.yml`**: weekly (Monday) updates for `cargo` (minor and patch grouped into one PR, at most 5 open) and `github-actions` (one grouped PR). The `wasmtime*` and `wiggle` crates are ignored: they are pinned with `=` and must move together with the snapshot and escape suites, so they're upgraded by hand (as for RUSTSEC-2026-0587).
- **`.github/workflows/security.yml`**: daily at 05:17 UTC and on `workflow_dispatch`, against `main`.
  - `advisories` job (read-only): `cargo deny check advisories` and `cargo audit` (binaries from `taiki-e/install-action`); collects the RUSTSEC IDs mentioned; writes `security.json` (`sha, date, ok, advisories, run_id`) and a job summary; uploads the logs.
  - `publish` job (`contents: write` only): pushes `security/latest.json` to `ci-results`, retrying 3 times if another workflow pushed first.
  - `issue` job (`issues: write` only): on failure, opens **one** issue titled "Security advisory affects main" (label `security`, created if missing), or comments on the open one; after a clean run, closes it with a comment.
- **`SECURITY.md`**: private reporting through GitHub private vulnerability reporting; what to include; response targets (acknowledge ≤ 3 working days, confirm ≤ 7, critical fix ≤ 14 days); scope and out-of-scope lists matching THREAT_MODEL; supported versions (latest release only, pre-1.0).

## Design notes
- The check runs against `main` on a schedule, so a newly published advisory is found within a day even when nobody pushes (the gap that let RUSTSEC-2026-0587 and -0592 surface only on the next push).
- The job's pass/fail is the tools' exit codes; the ID list is informational (it may include unmaintained/yanked warnings).
- **Owner action needed:** private vulnerability reporting is a repository setting (Settings → Code security → Private vulnerability reporting → Enable). `SECURITY.md` points to it.

## Verification
- GitHub validates `dependabot.yml` on push (Insights → Dependency graph → Dependabot shows errors, if any).
- `security.yml` is verified by its first run (schedule or dispatch): green, `security/latest.json` on `ci-results`.
