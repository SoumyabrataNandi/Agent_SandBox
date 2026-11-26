# C6-U1 Container check — Summary

**Requirements:** FR-CT1 · **AC:** 2

- **`packaging/container/smoke.sh <image> <sandboxd>`:** the release smoke test, moved into a script both workflows run.
  - Checks: `version`, readiness within 300 s, an authenticated `print(6*7)` → `42`, `401` without a token, uid 10001.
  - The container is bound to 127.0.0.1, named per run, and removed on exit. On failure the script prints the last 100 log lines.
- **`.github/workflows/container.yml`:**
  - Triggers: pushes to `main` and PRs that touch `packaging/container/**`, `.dockerignore`, `container.yml` or `release.yml`; also on demand.
  - Builds `sandboxd` (release, x86_64 Linux), builds the amd64 image with buildx and runs `smoke.sh`.
  - Read-only permissions; nothing is pushed. Dependabot's base-image PRs touch the Dockerfile, so they are tested too.
- **`release.yml`:** the `image` job calls `smoke.sh` instead of its inline copy.

Docker isn't available on the development laptop, so the first `container` run is the verification.
