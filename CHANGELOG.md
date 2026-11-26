# Changelog

All notable changes to sandboxd are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (pre-1.0: a minor version may change behaviour).

## [Unreleased]

### Added
- **Client libraries:** `sandboxd-client` for Python (≥ 3.10, standard library only) and for
  JavaScript/TypeScript (one ES module on `fetch`, with type declarations). Both cover runs, files
  and artifacts, streaming, sessions, policies and health. They raise one error type with the
  server's code and retry `429` answers. The wheel and the npm package are attached to each release.
- **Container check:** the `container` workflow builds and smoke-tests the image whenever the
  container files change. The smoke test is shared with the release (`packaging/container/smoke.sh`).

### Fixed
- Benchmarks: gVisor installs again (it now ships as a tarball), and the bench summary says
  whether gVisor was installed.

### Changed
- Release workflow: the Docker actions moved to their Node 24 versions (setup-qemu and setup-buildx v4,
  login v4, build-push v7), which removes the Node 20 deprecation warning.
- The container base image is pinned by digest, and Dependabot now proposes updates to it weekly.

## [0.2.1] - 2026-11-26

### Fixed
- The container image is now published: the v0.2.0 release smoke test sent its request
  without `Content-Type: application/json`, the server answered 415, and the image was never pushed.
- The `curl` examples in the README and the getting-started guide now send
  `Content-Type: application/json` (without it the server answers 415).

## [0.2.0] - 2026-11-24

### Added
- **Operator Python packages:** `[packages] dir` points at a directory of pure-Python wheels
  (`py3-none-any`), optionally pinned with `[packages] sha256`. They're validated at start-up (native
  code, unsafe paths and oversized wheels are refused), extracted once, compiled inside the sandbox,
  and importable read-only in every Python run (fresh, snapshot and session), after the stdlib.
  Policies can opt out with `[python] packages = false`. `sandboxd packages list` validates the
  directory and prints a lock; `list_policies` tells agents which packages exist.
- **Container image** `ghcr.io/soumyabratanandi/sandboxd` (linux/amd64 + arm64): non-root,
  `sandboxd serve` on 8080, tokens via `SANDBOXD_TOKENS`, cache volume. Built from the release
  binaries and smoke-tested before it is pushed.

### Changed
- **`sandboxd mcp` connects immediately.** The handshake no longer waits for the cache build; tool
  calls wait instead (with a progress message), and a failed start-up is reported to every call as
  `STARTUP_FAILED`. MCP clients with short connect timeouts no longer give up on the first start.
- The MCP pilot checks that `initialize` answers within 10 s on a cold cache.

## [0.1.0] - 2026-11-24

The first release: everything from the original brief (phases 1–5).

### Added
- **Sandbox runtime:** CPython 3.15 (WASI) and QuickJS-ng 0.18 on wasmtime 50, with deny-by-default
  WASI preopens, wall-clock, CPU (fuel), memory, output and file limits, and native-extension detection
  (`UNSUPPORTED_NATIVE_EXTENSION`). Interpreters are pinned by SHA-256 and embedded in the binary.
- **Interfaces:** `sandboxd run` (CLI), an HTTP API (`/v1/runs`, server-sent event streaming,
  `/metrics` for Prometheus, bearer tokens stored as hashes) and an MCP server (stdio and Streamable
  HTTP) with `run_code`, `list_policies`, `session_create` and `session_close`.
- **Policies:** named TOML/YAML policies with limits, read-only or read-write mounts and literal env
  vars; agents can only tighten them. `sandboxd policy check|list|new`.
- **Audit:** every run and capability use as JSON lines (file or stdout), with redaction.
- **Network broker:** off by default; per-policy HTTP(S)/TCP allowlists through an SSRF-hardened,
  audited broker (`urllib`, `http.client`, `socket.create_connection` and `fetch` work unchanged).
- **Telemetry:** optional OTLP/HTTP export of metrics and one span per run (`--features otel`).
- **Performance:** pooled instance slots, Wizer snapshots of pre-initialised interpreters, and
  persistent **sessions** (notebook-style state across calls, per-call limits). Python `print(1)`
  in 3.25 ms and 884 runs/s through the server on a 4-vCPU runner ([BENCHMARKS.md](docs/BENCHMARKS.md)).
- **Security testing:** a release-blocking escape suite (filesystem, env, resource bombs, sockets,
  policy widening, auth, the E-NET network family, pool remnants, session hijacking and leakage,
  snapshot tampering), run on Linux, macOS and Windows and against every release binary.
  Threat model in [THREAT_MODEL.md](THREAT_MODEL.md).
- **Operations:** daily RustSec advisory checks, Dependabot, [SECURITY.md](SECURITY.md),
  an MCP agent pilot in CI, and a [getting-started guide](docs/GETTING_STARTED.md).

### Security
- wasmtime 50.0.3 (RUSTSEC-2026-0587, Windows WASI filesystem escape via drive-prefixed paths) and
  url 2.5.9 (RUSTSEC-2026-0592).

### Known limitations
- No NumPy/pandas or other native extensions; no `pip install`.
- Sessions live in memory: a restart ends them.
- The first start builds the cache (run `sandboxd cache warm` once after installing).

[Unreleased]: https://github.com/SoumyabrataNandi/Agent_SandBox/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/SoumyabrataNandi/Agent_SandBox/releases/tag/v0.2.1
[0.2.0]: https://github.com/SoumyabrataNandi/Agent_SandBox/releases/tag/v0.2.0
[0.1.0]: https://github.com/SoumyabrataNandi/Agent_SandBox/releases/tag/v0.1.0
