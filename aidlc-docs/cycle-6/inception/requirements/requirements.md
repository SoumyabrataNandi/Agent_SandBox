# Cycle 6 Requirements — Client libraries, container checks, gVisor

**Status:** Approved (user: "start cycle 6 with all defaults") · **Date:** 2026-11-26 · **Answers:** Q1–Q7 all A.
Cycle 1–5 requirements stay in force.

## FR-CL1 Client libraries (Q2, Q3)
- **CL1.1** `clients/python`: package `sandboxd-client`, module `sandboxd_client`, Python ≥ 3.10, standard library only, typed (`py.typed`).
- **CL1.2** `clients/js`: package `sandboxd-client`, one ES module using `fetch` (Node ≥ 18, Deno, Bun, browsers), no dependencies, with TypeScript declarations.
- **CL1.3** Both cover the HTTP API:
  - `run(code, language, …)` with `policy`, `files`, `args`, `stdin`, `limits`. Files may be text or bytes; bytes are sent base64.
  - Streaming runs: an iterator (Python) or async iterator (JS) of `stdout`, `stderr` and `limit` events, ending with the result. A server `error` event raises.
  - Sessions: `create_session` / `createSession` returns a session object with `run`, `info` and `close`. Python sessions are context managers; JS sessions have `close()` and `[Symbol.asyncDispose]`.
  - `policies()` and `health()`.
- **CL1.4** Results expose every API field. Artifacts are decoded to bytes (`Uint8Array` in JS); `ok` is true when `outcome == "ok"`. A guest failure is a result, not an exception.
- **CL1.5** Any non-2xx response raises one error type (`SandboxdError`) with `code`, `status` and `message`. `429` responses are retried up to 3 times, waiting for `Retry-After` (capped at 10 s).
- **CL1.6** Every request sends `Content-Type: application/json`, and `Authorization: Bearer <token>` when a token is given. The URL and token can come from `SANDBOXD_URL` / `SANDBOXD_TOKEN`. Timeouts are configurable.
- **CL1.7** Tests run against a real `sandboxd serve` in CI (Linux): run, files and artifacts, a non-zero exit, a limit, streaming, sessions, a 401, a 404 policy, and a 400 for a bad request.

## FR-CL2 Distribution (Q4)
- **CL2.1** The release workflow builds the wheel and the npm tarball at the release version and attaches both to the GitHub release, with checksums in `SHA256SUMS`.
- **CL2.2** The client versions follow the workspace version. A CI check fails if they differ.
- **CL2.3** Docs: README, `clients/*/README.md`, and a GETTING_STARTED section show install-from-release and a first run.

## FR-CT1 Container check (Q5)
- **CT1.1** The smoke test moves from `release.yml` to `packaging/container/smoke.sh <image> <sandboxd-binary>`. It checks `version`, readiness within 300 s, an authenticated `print(6*7)` → `42`, `401` without a token, and uid 10001. On failure it prints the container logs.
- **CT1.2** Workflow `container.yml` runs on pushes to `main` and on PRs that touch `packaging/container/**`, `.github/workflows/container.yml` or `.github/workflows/release.yml`, and on `workflow_dispatch`. It builds `sandboxd` (release) for Linux amd64, builds the image and runs `smoke.sh`. It has no write permissions.

## FR-GV1 gVisor comparator (Q6)
- **GV1.1** `bench.yml` installs gVisor from `releases/release/latest/<arch>/gvisor.tar.bz2`, verified against `gvisor.tar.bz2.sha512`.
- **GV1.2** The step stays optional, but its outcome (the `runsc` version, or "install failed") goes into the job summary.
- **GV1.3** After the owner runs the bench workflow, BENCHMARKS.md is rendered from the new results.

## FR-R3 Release v0.3.0 (Q7)
- CHANGELOG `0.3.0`; tag after green CI; draft release with the client packages and the image; the owner publishes.

## Acceptance criteria
1. Both client test suites pass against a real server in CI.
2. The `container` workflow passes on its first run.
3. The release attaches the wheel and the npm tarball, and both install from the release URLs.
4. A bench run with gVisor reports gVisor numbers (needs the owner to start the bench run).
5. All existing suites stay green.
