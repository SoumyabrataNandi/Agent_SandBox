# C6-U5 Release v0.3.0 — Summary

**Requirements:** FR-CL2, FR-R3 · **AC:** 3, 4

- **CI before the tag:**
  - b687399: `ci`, the first `container` run and a `bench` run (started by the owner) are all green.
  - 010e33c (the 0.3.0 bump): `ci` green.
- **Benchmarks (a8531eb):** BENCHMARKS.md was regenerated from bench run 45853737600, with gVisor `runsc release-20261123.1` installed from the tarball; nothing was skipped.
  - Python `print(1)` p50: sandboxd 2.22 ms; gVisor `docker exec` 34.5 ms; gVisor `docker run` 133.6 ms.
  - 1,302 runs/s.
  - Every NFR-P1 target is met.
- **Version:** workspace and both clients at 0.3.0 (`scripts/client_versions.py --set`); CHANGELOG `[0.3.0] - 2026-11-26`.
- **Tag v0.3.0 on 010e33c.** The first two pushes timed out waiting for a Git Credential Manager sign-in. After the owner signed in, a non-interactive push went through.
- **Release run 45957479130:** all jobs green: 5 builds, `client packages`, `draft-release` and `container image`.
  - The draft release has the archives, `sandboxd_client-0.3.0-py3-none-any.whl` and `sandboxd-client-0.3.0.tgz`, with `SHA256SUMS`.
  - `ghcr.io/soumyabratanandi/sandboxd:0.3.0` can be pulled anonymously.
- **Owner action:** publish the v0.3.0 draft. Installing the clients from the release URLs works only once the release is published (AC 3), because draft assets need authentication.
