# sandboxd

**Run untrusted, agent-generated code in a WebAssembly sandbox: fast, self-hosted, deny-by-default.**

Agents write code and run it. That code is untrusted by definition. `sandboxd` is a single Rust
binary that runs Python (CPython 3.15 WASI) and JavaScript (QuickJS) inside wasmtime. It grants
nothing the operator's policy doesn't allow, enforces CPU, wall-clock, memory and output limits, and
audits every capability use. Agents reach it over a CLI, an HTTP API, or as an MCP `run_code` tool.

> Most agent code doesn't need a VM. Stop paying for one.

| | |
|---|---|
| Python `print(1)` | milliseconds through the server: runs start from a pre-initialised interpreter snapshot in a pooled instance slot ([measured numbers](docs/BENCHMARKS.md)) |
| JavaScript `console.log` | a few milliseconds |
| Sessions | Optional persistent interpreters (like a notebook kernel): state carries over between calls, each call keeps its own limits |
| Warm start (cached modules) | ~0.1 s |
| Isolation | wasmtime + WASI preopens; no sockets, no env inheritance, no host paths outside mounts |
| Network | Off by default. Per-policy HTTP(S)/TCP allowlists through an SSRF-hardened, audited broker |

## Install
Download the archive for your platform from [Releases](https://github.com/SoumyabrataNandi/Agent_SandBox/releases/latest),
verify it against `SHA256SUMS` and its build attestation, then run `sandboxd cache warm` once.
Step by step, including MCP setup: **[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)**.
Changes: [CHANGELOG.md](CHANGELOG.md). Reporting a vulnerability: [SECURITY.md](SECURITY.md).

## Quick start (from source)
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
- ✅ Network access **when a policy grants it**: `urllib`, `http.client`, `socket.create_connection` and `fetch` work unchanged, through an allowlisting broker. See [docs/NETWORK.md](docs/NETWORK.md).
- ✅ Pure-Python packages **the operator provides** (`[packages] dir` of `py3-none-any` wheels, optionally hash-locked), read-only and after the stdlib. See [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md#8-python-packages-optional).
- ❌ `pip install` by agents, and non-blocking/async sockets.

## Performance features (cycle 3)
- **Snapshots** (`[runtime] snapshots = "auto"`): CPython and QuickJS are built from pinned sources in CI,
  pre-initialised with Wizer and pinned by SHA-256. At start-up the server compiles and caches the
  snapshots; each run starts from one instead of booting the interpreter. Runs whose policy memory
  limit is below the snapshot's floor use the upstream interpreter.
- **Pooling** (`[runtime] pooling = "auto"`): instance slots are reserved once and reused; wasmtime
  resets their memory between runs. Runs wait for a free slot instead of failing.
- **Sessions** (`[session] enabled = true` in a policy): `POST /v1/sessions`, then
  `POST /v1/sessions/{id}/runs`, or the MCP tools `session_create` / `run_code {session_id}` /
  `session_close`. Bound to the creating principal; ended by idle TTL, lifetime, call count, a limit
  or close. See [docs/MCP.md](docs/MCP.md#sessions-cycle-3).

## Benchmarks
[docs/BENCHMARKS.md](docs/BENCHMARKS.md) compares sandboxd with `docker run`, `docker exec` and gVisor
on a GitHub-hosted Linux runner: latency, throughput, memory and session calls. It is generated
from the `bench` workflow's results (`scripts/bench/`), never edited by hand.

## Security testing
`tests/escape-suite` is an adversarial, release-blocking suite: traversal, symlinks, env reads,
CPU/memory/output bombs, subprocess/socket attempts, policy widening, auth bypass and input abuse,
plus the **E-NET** network family (SSRF in every IP encoding, DNS-to-private, redirects, header
injection, downgrades, proxies, quotas, slowloris). Forbidden servers must never see a connection.
Cycle 3 adds pool remnants, session hijacking and leakage, the session channel, snapshot tampering
and host data in snapshots (E-POOL, E-SES, E-SNAP).
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
