# sandboxd

**Run untrusted, agent-generated code in a WebAssembly sandbox: fast, self-hosted, deny-by-default.**

Agents write code and run it. That code is untrusted by definition. `sandboxd` is a single Rust
binary that runs Python (CPython 3.15 WASI) and JavaScript (QuickJS) inside wasmtime. It grants
nothing the operator's policy doesn't allow, enforces CPU, wall-clock, memory and output limits, and
audits every capability use. Agents reach it over a CLI, an HTTP API, or as an MCP `run_code` tool.

> Most agent code doesn't need a VM. Stop paying for one.

| | |
|---|---|
| Python `print(1)` | ~0.1–0.2 s end to end (stdlib bytecode precompiled) |
| JavaScript `console.log` | ~6 ms |
| Warm start (cached modules) | ~0.1 s |
| Isolation | wasmtime + WASI preopens; no sockets, no env inheritance, no host paths outside mounts |

## Quick start
```bash
python scripts/fetch-assets.py            # pinned, hash-verified interpreters
cargo build --release
./target/release/sandboxd run examples/hello.py
./target/release/sandboxd run job.py --input data.csv --timeout 2s --memory 128mb
```
The first run compiles and caches the interpreters (~30 s). After that, runs start in milliseconds.

### As an MCP tool (Claude Code / Claude Desktop)
```bash
claude mcp add sandboxd -- /path/to/sandboxd mcp
```
See [docs/MCP.md](docs/MCP.md) for Claude Desktop, HTTP transport, tokens and policies.

### As an HTTP service
```bash
sandboxd token new --name ci              # add the printed hash to sandboxd.toml
sandboxd serve --config sandboxd.toml
curl -H "Authorization: Bearer $TOKEN" -d '{"language":"python","code":"print(6*7)"}' \
     http://127.0.0.1:8080/v1/runs
```
`POST /v1/runs?stream=true` streams stdout/stderr as server-sent events. `/metrics` is Prometheus.

## What runs, and what doesn't
- ✅ Logic, string processing, JSON/CSV, `statistics`, `decimal`, `datetime`, `re`: the Python stdlib. Also modern JavaScript.
- ❌ NumPy/pandas and other native extensions. These return `UNSUPPORTED_NATIVE_EXTENSION`; a container/microVM fallback is a planned extension point.
- ❌ Network access (a brokered, allowlisted network is designed for a later phase), and `pip install`.

## Security testing
`tests/escape-suite` is an adversarial, release-blocking suite: traversal, symlinks, env reads,
CPU/memory/output bombs, subprocess/socket attempts, policy widening, auth bypass and input abuse.
Every case plants random canaries on the host that must never appear in any output, artifact or audit
line. It runs on Linux, macOS and Windows in CI and against every release binary.

## Policies
Operators define named policies in TOML or YAML: limits, read-only or read-write mounts, literal env
vars. Agents choose a policy by name and can only *tighten* its limits. See [docs/MCP.md](docs/MCP.md#example-policy-policiesdatatoml).

## Build
See [docs/DEV_SETUP.md](docs/DEV_SETUP.md) (no admin rights needed on Windows).

## Design
The requirements, architecture decisions and per-unit designs are in `aidlc-docs/` (AI-DLC workflow).
The threat model is in [THREAT_MODEL.md](THREAT_MODEL.md).

## License
Apache-2.0. Embedded interpreters keep their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
