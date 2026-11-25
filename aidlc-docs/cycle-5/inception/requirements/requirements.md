# Cycle 5 Requirements — First start, packages, container

**Status:** Approved (standing instruction: all recommended defaults) · **Date:** 2026-11-24 · **Answers:** Q1–Q6 all A.
Cycle 1–4 requirements stay in force.

## FR-ST1 Non-blocking MCP start-up (Q2)
- **ST1.1** `sandboxd mcp` (stdio) starts serving the MCP protocol before the sandbox is built: `initialize` and `tools/list` are answered at once.
- **ST1.2** Tool calls made before the sandbox is ready wait for it (no timeout of their own). With a progress token, the call first sends one progress notification: "sandboxd is starting (building the interpreter cache)…".
- **ST1.3** If start-up fails, every tool call returns `isError` with `STARTUP_FAILED: <reason>`, and the reason is logged to stderr.
- **ST1.4** The HTTP server (`serve`, including `/mcp`) keeps today's order: it binds only when ready.
- **ST1.5** Shutdown still closes sessions and flushes the audit log, also when stdin closes during start-up.

## FR-PK1 Operator wheelhouse (Q3, Q4)
- **PK1.1** Config: `[packages] dir = "<path>"` and an optional `sha256 = { "<file>.whl" = "<hex>" }` lock. Without `dir`, nothing changes.
- **PK1.2** At start-up every `*.whl` in `dir` is validated. A server with any invalid wheel **refuses to start**, naming the file and the reason:
  - it is a readable zip;
  - its filename tags are pure Python (`py3-none-any` or `py2.py3-none-any`);
  - it contains no native binaries (`.so`, `.pyd`, `.dll`, `.dylib`);
  - it has no absolute paths and no `..` entries;
  - it is ≤ 64 MiB uncompressed per wheel;
  - its SHA-256 matches the lock (if a lock is given; a lock entry without a file is an error too).
- **PK1.3** The wheels are extracted (`*.data/purelib` content flattened, other `*.data` ignored) into `<cache>/packages/<hash>/site` atomically, with a marker, and reused while the set is unchanged. The hash covers the sorted (file, sha256) list and the helpers' hash. Two wheels writing the same file, or a wheel providing a top-level name of a sandboxd helper, is a start-up error.
- **PK1.4** *(Amended during C5-U2.)* The package directory is a **copy of the guest helpers plus the extracted wheels**, mounted read-only **in place of the helpers** at `/usr/local/lib/sandboxd` for Python runs that use packages. Reason: the snapshot interpreter runs `/code/main.py` from C with a `sys.path` fixed at snapshot time, which already ends with the helper directory (after the stdlib); a new mount path would need an interpreter rebuild. Fresh runs with packages always use the boot launcher (which appends the helper directory). Reads are summarised in the audit log like helper reads. JavaScript runs are unaffected.
- **PK1.5** Policy `[python] packages = false` mounts the plain helpers for that policy (imports of packages then fail normally).
- **PK1.6** `sandboxd version` (and the start event) list the package set (count + hash); `list_policies` / MCP instructions mention that operator packages may be available, and `sandboxd packages list` prints name, version and SHA-256.
- **PK1.7** Escape and safety cases: a wheel with a native library, a traversal entry, or a hash mismatch is refused; the packages mount is read-only (writes fail); a policy with `packages = false` can't import them.

## FR-CI1 Container image (Q5)
- **CI1.1** `Dockerfile` (in `packaging/container/`): `debian:trixie-slim`, the binary at `/usr/local/bin/sandboxd`, user `sandboxd` (uid 10001), `/etc/sandboxd/sandboxd.toml` (listen `0.0.0.0:8080`, cache `/var/cache/sandboxd`, work `/var/lib/sandboxd/work`, policies `/etc/sandboxd/policies`, audit to stdout), `VOLUME /var/cache/sandboxd`, `EXPOSE 8080`, `ENTRYPOINT ["sandboxd"]`, `CMD ["serve"]`, and a `HEALTHCHECK` is omitted (no curl in slim; orchestrators use `/healthz`).
- **CI1.2** `release.yml` job `image`: after `build`, downloads the two Linux archives, builds a multi-arch image (amd64 + arm64) with buildx, smoke-tests amd64 (`version`; `serve` + `/healthz` + one authenticated run), then pushes `ghcr.io/<owner lowercase>/sandboxd:<version>` and `:latest` with a provenance attestation. Permissions: `packages: write` only in that job.
- **CI1.3** Docs: GETTING_STARTED gets a container section (token via env/config mount, volume for the cache, `--read-only` friendly).

## FR-R2 Release v0.2.0 (Q6)
- CHANGELOG `0.2.0`; tag after green CI; draft release + image; the owner publishes the release.

## Acceptance criteria
1. Pilot: with a cold cache, `initialize` answers in < 2 s, and the first tool call succeeds after the build (new pilot check; CI Linux + Windows).
2. Start-up failure is reported to tool calls (test).
3. Packages: a pure wheel imports in fresh, snapshot and session runs; invalid wheels are refused with clear errors; read-only; opt-out works; stdlib can't be shadowed (tests + escape cases).
4. The image smoke test passes in the release run, and the image is on GHCR.
5. All existing suites stay green.
