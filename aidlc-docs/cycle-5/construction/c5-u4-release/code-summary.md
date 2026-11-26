# C5-U4 Release v0.2.1 — Summary

- **v0.2.0** (tag on 19a7130; CI run 45605655436 green). Release run 45607615703 built all five
  binaries and the draft release, but the `container image` job failed in its smoke test (curl exit 22).
  Cause: the smoke test posted to `/v1/runs` with `curl -d`, which sends a form content type; the server
  answered `415` (reproduced locally). The README and GETTING_STARTED `curl` examples had the same mistake.
- **Fix (8b861fd, v0.2.1):** `Content-Type: application/json` in the smoke test and both docs; the
  readiness loop now fails with the container logs instead of falling through. The v0.2.0 tag was not
  moved (it is public); v0.2.1 replaces it.
- **v0.2.1** (CI run 45764897523 green; release run 45773070665): all builds, the draft release and
  the container image succeeded. `ghcr.io/soumyabratanandi/sandboxd:0.2.1` and `:latest` (amd64 + arm64,
  with provenance) can be pulled anonymously.
- **Owner actions:** publish the v0.2.1 draft release; delete the v0.2.0 draft (superseded).
