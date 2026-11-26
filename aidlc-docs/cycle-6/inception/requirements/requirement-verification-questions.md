# Cycle 6 — Requirements Verification Questions (client libraries, container checks, gVisor)

## Starting point
v0.2.1 is published (cycle 5) with binaries for five platforms and a multi-arch image on ghcr.io. Three gaps remain:
- **No client libraries.** Agent frameworks call the HTTP API with hand-written requests. The v0.2.0 release showed how easy that is to get wrong: a `curl -d` example without `Content-Type: application/json` got a 415.
- **The container image is only tested at release time.** A broken Dockerfile, entrypoint or base-image update (Dependabot now proposes these) is found only when a version is tagged, as happened with v0.2.0.
- **gVisor was never measured.** The bench workflow's gVisor install failed with wget exit 8: gVisor no longer publishes a bare `runsc` under `releases/release/latest/<arch>/`, only `gvisor.tar.bz2` (+ `.sha512`). The step is `continue-on-error`, so the run looked green and BENCHMARKS.md says "skipped".

User instruction (2026-11-26): *"start cycle 6 with all defaults"*. Every answer below is the recommended option.

---

### Question 1 — Scope
A) **All of it:** Python and JavaScript client libraries, a container check on every change to the container files, the gVisor bench fix; then release v0.3.0. **(Recommended)**
B) Clients only
C) Other

[Answer]: A

### Question 2 — Client libraries: languages and dependencies
A) **Python and JavaScript/TypeScript, with no third-party dependencies.** Python uses only the standard library (`urllib`, `json`), for Python ≥ 3.10. JavaScript is one ES module on `fetch` (Node ≥ 18, Deno, Bun, browsers) with hand-written TypeScript types. Both are versioned with sandboxd and live in `clients/python` and `clients/js`. **(Recommended: nothing to audit, installs anywhere, including air-gapped hosts)**
B) Use `httpx` / `axios`
C) Python only

[Answer]: A

### Question 3 — Client features
A) **The whole HTTP API, with friendly types:**
- `run` (files given as text or bytes, args, stdin, limits, policy);
- streaming runs (stdout/stderr/limit events, then the result);
- sessions (create, run, info, close, plus a context manager or `using`-style close);
- `policies`, `health`;
- artifacts decoded to bytes;
- errors as one exception type carrying the server's `code`, HTTP status and message;
- automatic retry of `429` (`OVERLOADED`, `SESSION_LIMIT`) honouring `Retry-After`, up to 3 times;
- `Content-Type: application/json` and the bearer token are always sent.

A guest failure (exception, exit code, limit) is a normal result, not an exception. Same as the API. **(Recommended)**
B) Only `run`

[Answer]: A

### Question 4 — Distribution
A) **Release assets:** the release workflow builds `sandboxd_client-<ver>-py3-none-any.whl` and `sandboxd-client-<ver>.tgz` (npm pack) and attaches them to the GitHub release, with their checksums in `SHA256SUMS`. Install with `pip install <url>` / `npm install <url>`. PyPI and npm publishing need registry accounts the owner controls, so they are left for later. **(Recommended)**
B) Publish to PyPI and npm now

[Answer]: A

### Question 5 — Container check
A) **A `container` workflow** runs on pushes and PRs that change `packaging/container/**`, `release.yml` or itself (and on demand). It builds a Linux release binary, builds the amd64 image, and runs the same smoke test as the release. The smoke test moves into `packaging/container/smoke.sh`, shared by both workflows. Nothing is pushed. **(Recommended)**
B) Build the image in every CI run

[Answer]: A

### Question 6 — gVisor
A) **Install from the tarball:** download `gvisor.tar.bz2` and its `.sha512`, verify, extract `runsc`, then `runsc install`. Keep the step optional, but write its outcome (version or the reason it failed) to the job summary, so a skip is visible. The owner re-runs Actions → bench; BENCHMARKS.md is re-rendered from the new results. **(Recommended)**
B) Drop gVisor from the benchmarks

[Answer]: A

### Question 7 — Release
A) **v0.3.0** after green CI: the same draft-release flow, plus the client packages; the owner publishes. **(Recommended)**
B) No release

[Answer]: A
