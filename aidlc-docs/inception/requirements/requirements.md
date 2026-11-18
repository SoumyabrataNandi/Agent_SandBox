# Requirements — sandboxd

**Status:** Draft for approval · **Date:** 2026-11-18 · **Source:** `requirement-verification-questions.md` (all 22 answered)

## 1. Intent

`sandboxd` is a self-hosted, single Rust binary that runs **untrusted, agent-generated Python and JavaScript** inside WebAssembly. Access is deny-by-default and controlled by operator-owned policy files. Every capability use is audited. Agents reach it through a CLI, an HTTP API, or an MCP `run_code` tool.

**Positioning:** this is the fast, safe tier. Most agent code doesn't need a VM. Code that needs the full native Python ecosystem gets a clear error and goes to a fallback backend, which is pluggable but not built yet.

## 2. Scope of this cycle

| Phase | Content | This cycle |
|---|---|---|
| 1 | CLI: run a script with limits, capture output | **Build** |
| 2 | Virtual filesystem: read-only inputs, `/out` artifacts | **Build** |
| 3 | MCP server (`run_code`) + HTTP API | **Build** |
| 4 | Network broker | **Design interfaces only** |
| 5 | Snapshots, pooling, sessions, benchmarks | **Design interfaces only** |

(Q1=B, Q2=A) The architecture must have clear seams for phases 4–5: the broker trait, the instance-pool trait, the session handle and the policy schema sections. Building them later must not require breaking changes to the policy format or the API.

## 3. Functional requirements

### FR-1 Execution engine
- **FR-1.1** Embed wasmtime and run guest interpreters compiled to `wasm32-wasip1`.
- **FR-1.2 Python:** a prebuilt CPython **3.15.2** WASI build (`wasm32-wasip1`), pinned by SHA-256 (Q5=A; version updated at the U0 gate, 2026-11-18).
- **FR-1.3 JavaScript:** QuickJS compiled to WASI (Q4=B).
- **FR-1.4** Request input: `{language, code, policy?, files?, args?, stdin?}`. Output: `{exit_code, stdout, stderr, artifacts[], limits_hit[], timings, run_id}`.
- **FR-1.5** If code imports a known native-extension package (numpy, pandas, scipy, etc.), return a structured `UNSUPPORTED_NATIVE_EXTENSION` error that names the module. Define a `FallbackBackend` trait with no implementation in this cycle (Q3=A).

### FR-2 Resource limits (Q12=A,B,C,D,E)
- **FR-2.1** CPU: fuel metering, with a fuel budget derived from policy.
- **FR-2.2** Wall clock: epoch interruption, using a host ticker thread.
- **FR-2.3** Memory: a linear-memory cap via a wasmtime `ResourceLimiter`.
- **FR-2.4** Output caps: stdout/stderr bytes, artifact count and total artifact bytes.
- **FR-2.5** A server-wide limit on concurrent runs. Requests over the limit are queued with a timeout or rejected (HTTP 429 or the MCP equivalent).
- **FR-2.6** Every limit breach terminates the run cleanly, is reported in `limits_hit` and is audited.

### FR-3 Virtual filesystem (Phase 2)
- **FR-3.1** Request-supplied input files go to an in-memory or temp-dir mount, read-only.
- **FR-3.2** Policy-declared host directories are exposed through WASI preopens with a per-mount `ro`/`rw` mode.
- **FR-3.3** `/out` is writable. Its contents come back as artifacts (name, size, sha256, content inline or by reference) after the size caps are applied.
- **FR-3.4** Nothing outside the declared mounts is visible. The guest gets no env vars except those the policy whitelists, no host clock precision beyond what the policy sets, and no sockets.
- **FR-3.5** Each run's scratch space is destroyed after the run.

### FR-4 Policy engine
- **FR-4.1** Policies can be written in **TOML or YAML** (Q10=C). Both parse into one canonical, versioned schema (`version = 1`), with identical validation and error messages.
- **FR-4.2** Policies are **operator-owned and named**. Agents choose one by name and can never send inline or widened permissions (Q11=A). Unknown policy name → error, never a fallback to permissive defaults.
- **FR-4.3** Schema sections: `limits`, `filesystem`, `env`, `network` (designed now, enforced in Phase 4), `session` (designed now), `audit`.
- **FR-4.4** Policies are fully validated at load. Unknown keys are an error. `sandboxd policy check <file>` explains the effective policy.
- **FR-4.5** A built-in `default` policy that grants nothing beyond stdout/stderr and `/out`.

### FR-5 Interfaces
- **FR-5.1 CLI:** `sandboxd run <file> [--lang] [--policy] [--timeout 2s] [--memory 128mb] [--input path] [--out dir]`. CLI flags can only **tighten** the selected policy. Also `sandboxd serve`, `sandboxd mcp`, `sandboxd policy check`, `sandboxd version`.
- **FR-5.2 HTTP API** (axum, Q6=B): `POST /v1/runs` (sync), `POST /v1/runs?stream=true` (SSE: stdout/stderr/limit/exit events), `GET /v1/policies`, `GET /healthz`, `GET /metrics`.
- **FR-5.3 MCP server** (Q7=B): stdio and Streamable HTTP transports. Tools: `run_code(language, code, policy?, files?)` and `list_policies`. Output streams as MCP progress notifications (Q8=B), and the final result includes text output plus artifacts as embedded resources.
- **FR-5.4 Auth** (Q9=B): network listeners bind to `127.0.0.1` by default. Static bearer tokens come from config or env. Binding to a non-loopback address without tokens configured is refused at startup.

### FR-6 Audit & telemetry (Q18=B)
- **FR-6.1** JSON Lines audit events: `run.start`, `run.end`, `fs.open` (path, mode, allowed/denied), `env.read`, `limit.hit`, `policy.denied`, and later `net.request`. Every event carries `run_id`, timestamp, policy name and token identity (a hash, never the token itself).
- **FR-6.2** OpenTelemetry traces and metrics over OTLP, optional and off by default. Metrics: run count, duration histogram, limit hits, queue depth, cold-start time.
- **FR-6.3** Guest code is logged only if the policy allows it (`audit.log_code`, default: hash only).

### FR-7 Network broker — designed, not built (Q15=A,B; Q16=B)
- **FR-7.1** The guest never gets real sockets. All egress goes through host functions that check the allowlist, perform the I/O, and log it.
- **FR-7.2 HTTP(S):** a `fetch`-style API with an allowlist of `{host, port, methods, path_prefix}`, including TLS done by the host.
- **FR-7.3 Raw TCP:** allowlisted `host:port` stream connections. These are **off by default** and a policy must opt in per destination. *Note:* the host can't inspect raw TCP content, so exfiltration control is limited to destination plus byte counts. The audit log records that too.
- **FR-7.4** Per-run limits on request count, body size and total bandwidth. Secrets matching configured patterns are redacted from logs.
- **FR-7.5** DNS resolution happens on the host and the resolved IP is checked as well, to block DNS rebinding and private-IP bypass.

### FR-8 Performance & sessions — designed, not built
- **FR-8.1** An `InstancePool` trait. This cycle ships a naive "instantiate per run" implementation that uses wasmtime's pre-compiled modules (`Module::serialize`/`deserialize`, or `InstancePre`).
- **FR-8.2** A `SessionId` concept reserved in the API and policy schema (`session.enabled`, `session.idle_ttl`), returning "not implemented".

## 4. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-1 Platforms (Q17=C) | **Linux (x86_64, arm64), macOS (arm64, x86_64) and Windows (x86_64) are all first-class.** CI builds and runs the full test suite, including escape tests, on all three. No `unix`-only APIs without a Windows equivalent. |
| NFR-2 Distribution (Q19=A) | A single binary per platform with the CPython and QuickJS `.wasm` files embedded (compressed). The binary pre-compiles them on first use into a cache directory that's validated by hash and wasmtime version. |
| NFR-3 Performance targets (this cycle) | QuickJS hello-world end-to-end ≤ 50 ms, CPython ≤ 300 ms (no snapshots yet), measured on a warm compiled cache. Phase 5 targets will be set later. |
| NFR-4 Security (Q13=A, Q14=A) | Security baseline rules are **blocking**: a threat model document, `cargo audit` + `cargo deny` in CI, no `unsafe` outside reviewed modules, input validation on every API, secrets never logged, least-privilege defaults. The **adversarial escape suite is release-blocking.** It covers path traversal (`../`, absolute paths, symlinks), env var reads, infinite loops, memory bombs, recursion depth, output floods, artifact bombs, socket/subprocess attempts, and policy-widening attempts through the API. |
| NFR-5 Reliability | A guest crash, trap or limit hit never crashes the server. Each run is isolated in its own `Store`. |
| NFR-6 Observability | See FR-6. Structured logs via `tracing`. |
| NFR-7 License (Q21=A) | Apache-2.0. Third-party wasm binaries need their licenses bundled (CPython PSF, QuickJS MIT). |
| NFR-8 Toolchain (Q22=A) | The Windows dev host gets `rustup` stable, the `wasm32-wasip1` target and `wasmtime-cli`. `wizer` is installed when Phase 5 starts. |

## 5. Out of scope (this cycle)
NumPy/pandas under WASI, a working fallback backend, network broker implementation, snapshots/wizer, pooling, persistent sessions, Docker benchmarks, mTLS, multi-tenant quotas, package installation (`pip install`) inside the sandbox.

## 6. Acceptance criteria (replace User Stories per Q20=A)
1. `sandboxd run hello.py` and `sandboxd run hello.js` print output and exit 0 on Linux, macOS and Windows.
2. `while True: pass` with `--timeout 2s` terminates in ≤ 2.2 s with `limits_hit=["wall_clock"]`. A fuel-exhaustion case reports `cpu`.
3. Allocating 1 GB under a 128 MB policy fails with `limits_hit=["memory"]` and the server stays healthy.
4. `open("/etc/passwd")`, `open("../secret")` and `os.environ` show no host data. Denials are audited.
5. A file mounted read-only can be read but writing to it fails. A file written to `/out/result.csv` comes back as an artifact with a correct sha256.
6. `import numpy` returns `UNSUPPORTED_NATIVE_EXTENSION`.
7. Claude Desktop/Code configured with `sandboxd mcp` can call `run_code` and see streamed output.
8. The HTTP API rejects unauthenticated requests when tokens are configured, and refuses to start on `0.0.0.0` without tokens.
9. The same policy written in TOML and in YAML produces identical effective policies (golden test).
10. The escape suite passes on all three operating systems in CI.

## 7. Open items, to be resolved in Application Design
- Choosing the guest↔host network bridge: custom CPython with a `_sandbox` C module, a virtual-device-file protocol, or `wasi:http` components. This doesn't block the current scope.
- How QuickJS is sourced: a prebuilt WASI build, or our own build of `quickjs-ng` for wasm32-wasip1.
