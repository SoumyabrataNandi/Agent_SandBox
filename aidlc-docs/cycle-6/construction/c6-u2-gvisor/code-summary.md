# C6-U2 gVisor comparator — Summary

**Requirements:** FR-GV1 · **AC:** 4

- **Cause of the skip:** run 45334900239's "Install gVisor" step failed with wget exit 8. `releases/release/latest/<arch>/runsc` no longer exists (404); gVisor now publishes `gvisor.tar.bz2` (+ `.sha512`, `.tar.zstd`) containing `runsc`, `containerd-shim-runsc-v1` and `gvisor-bin/`. The step is `continue-on-error`, so the run stayed green and the harness recorded "runsc runtime not registered with docker".
- **Fix (`bench.yml`):** download `gvisor.tar.bz2` and its `.sha512`, verify, extract `runsc` and the shim, install them, `runsc install`, restart Docker, then a test container.
  - A new step, "gVisor outcome", writes "installed: <version>", "install failed (...)" or "not requested" to the job summary.
  - Verified locally: the tarball's layout and SHA-512 (84.9 MB, checksum OK).
- **Pending (owner):** run Actions → bench; BENCHMARKS.md is then re-rendered from `ci-results` `bench/latest.json` (`scripts/bench/render.py`).
