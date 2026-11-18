# Requirements Verification Questions — sandboxd

## Intent analysis (my reading of the request)

| Aspect | Assessment |
|---|---|
| **Request type** | New project (greenfield) |
| **Scope** | System-wide: CLI, runtime, policy engine, VFS, network broker, MCP/HTTP API, telemetry, benchmarks |
| **Complexity** | High. wasmtime embedding, WASI preopens, fuel/epoch/memory limits, snapshotting (wizer), host-function networking, MCP protocol |
| **Depth chosen** | Comprehensive |

**Core intent:** a self-hosted single Rust binary, `sandboxd`, that runs untrusted agent-written Python and JavaScript inside WebAssembly. Access is deny-by-default and set by a policy file. Every run is audited. The binary is exposed to agents as an MCP `run_code` tool. The pitch is: *most agent code doesn't need a VM, so stop paying for one.*

**Technical risks I've already found (they inform the questions below):**
1. **Networking from the guest.** The CPython WASI build has no sockets and no way to call custom host imports from Python code unless a C extension is compiled into the interpreter. The broker therefore needs one of these: (a) a custom CPython build with a small `_sandbox` C module, (b) a virtual "device file" protocol (for example `/dev/sandbox/http`) that the host implements, or (c) a WASI 0.2 / `wasi:http` component build of the interpreter. Each option costs something different. I'll settle it in Application Design.
2. **pandas/NumPy under WASI.** No mainstream maintained WASI wheels exist for them. That's the "go deep" decision (Q3).
3. **Windows dev host.** Rust isn't installed here yet. wasmtime supports Windows, but wizer, the CPython WASI build tooling and the benchmark comparison against Docker are smoother on Linux/WSL.
4. **Persistent sessions** mean keeping a wasmtime `Store` alive between calls. That interacts with pooling, memory caps and idle eviction.

---

## How to answer
Put the letter of your choice after each `[Answer]:` tag. If no option fits, pick the last one ("Other") and describe what you want. **(Recommended)** marks my suggested default. If you're happy with every recommendation, you can just reply **"accept recommended defaults"**.

---

## A. Scope & strategy

### Question 1 — Release scope for this AI-DLC cycle
Which build phases should this cycle cover, from requirements through code and tests?

A) Phase 1 only (CLI: `sandboxd run script.py --timeout 2s --memory 128mb`)
B) Phases 1–3 (CLI + filesystem + MCP server): the first demo people want to try **(Recommended)**
C) Phases 1–4 (adds the network broker)
D) All 5 phases (adds snapshots, pooling, sessions and benchmarks)
E) Other (please describe after [Answer]: tag below)

[Answer]: B

### Question 2 — Even if not all are built now, should the architecture be designed up front for all 5 phases?
A) Yes. Design the interfaces (policy schema, broker seam, pool trait) for all 5 phases, but build only the chosen scope **(Recommended)**
B) No. Design only for the chosen scope and refactor later
C) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 3 — Python native-extension strategy (NumPy/pandas)
A) Fast-tier positioning: pure Python + stdlib in WASM, with a clean "needs full ecosystem" error and a pluggable fallback interface (container or microVM) that isn't implemented yet **(Recommended)**
B) Fast tier + an actual working Docker fallback backend in this cycle
C) Go deep: make NumPy/pandas work under WASI as the flagship feature (high risk, research-heavy)
D) Pure Python only, no fallback concept at all
E) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 4 — Guest languages for this cycle
A) Python (CPython WASI) only
B) Python + JavaScript (QuickJS compiled to WASM) **(Recommended)**
C) JavaScript only first (smaller, easier interpreter)
D) Other (please describe after [Answer]: tag below)

[Answer]: B

### Question 5 — Python version / interpreter source
A) Use a prebuilt official CPython 3.13 WASI (wasm32-wasip1) build, downloaded and pinned by hash at build time **(Recommended)**
B) Build CPython for WASI from source in our own pipeline (needed later if we add a `_sandbox` C module)
C) Other (please describe after [Answer]: tag below)

[Answer]: A

## B. Interfaces

### Question 6 — API surface
A) CLI + MCP server only
B) CLI + MCP server + HTTP/JSON REST API (axum) **(Recommended)**
C) CLI + HTTP only (MCP later)
D) Other (please describe after [Answer]: tag below)

[Answer]: B

### Question 7 — MCP transport
A) stdio only (what Claude Desktop / Claude Code launch locally)
B) stdio + Streamable HTTP **(Recommended)**
C) Other (please describe after [Answer]: tag below)

[Answer]: B

### Question 8 — Output delivery
A) Buffered: return stdout/stderr/artifacts when the run ends
B) Streaming stdout/stderr (SSE over HTTP; MCP progress notifications), with artifacts at the end **(Recommended)**
C) Other (please describe after [Answer]: tag below)

[Answer]: B

### Question 9 — Authentication for network-exposed modes (HTTP API / MCP over HTTP)
A) None, bind to localhost only
B) Static bearer token(s) from config, bound to localhost by default **(Recommended)**
C) mTLS
D) Other (please describe after [Answer]: tag below)

[Answer]: B

## C. Policy & security

### Question 10 — Policy file format
A) TOML **(Recommended, idiomatic for Rust and readable for security teams)**
B) YAML
C) Both
D) Other (please describe after [Answer]: tag below)

[Answer]: C

### Question 11 — Who chooses the policy for a run?
A) Operator only: named policies on the server, and the agent picks one by name; the agent can never widen permissions **(Recommended)**
B) Agent can send an inline policy, clamped to an operator ceiling
C) Agent can send any policy
D) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 12 — Resource limits to enforce in v1 (choose all that apply, e.g. "A,B,C,D")
A) CPU via fuel metering (instruction count)
B) Wall-clock via epoch interruption
C) Linear memory cap
D) Output size cap (stdout/stderr bytes, artifact bytes/count)
E) Max concurrent runs per server
F) Other (please describe after [Answer]: tag below)

**(Recommended: A,B,C,D,E)**

[Answer]: A,B,C,D,E

### Question 13 — Should we include an adversarial "escape test" suite (filesystem traversal, env-var reads, infinite loops, memory bombs, fork/socket attempts) as release-blocking tests?
A) Yes, release-blocking **(Recommended)**
B) Yes, but advisory
C) No
D) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 14 — Security extension rules
Should security baseline rules (input validation, secrets handling, dependency auditing with `cargo audit`/`cargo deny`, least-privilege defaults, threat model doc) be enforced as blocking constraints across all stages?
A) Yes, enforce them all as blocking constraints **(Recommended for a security product)**
B) No, best-effort only
C) Other (please describe after [Answer]: tag below)

[Answer]: A

## D. Network broker (if in scope or designed for)

### Question 15 — Network capability shape
A) HTTP(S) only, through a host-brokered `fetch`-style API with a host/port/method allowlist **(Recommended)**
B) HTTP + raw TCP to allowlisted hosts
C) Other (please describe after [Answer]: tag below)

[Answer]: A,B

### Question 16 — Broker extras
A) Allowlist + full request logging only
B) Also enforce limits on body size, request count and per-run bandwidth, and redact secrets from logs **(Recommended)**
C) Also do secret injection, where the host adds auth headers so the guest never sees credentials
D) Other (please describe after [Answer]: tag below)

[Answer]: B

## E. Operations

### Question 17 — Target host platforms
A) Linux x86_64/arm64 first-class; macOS and Windows supported for development **(Recommended)**
B) Linux only
C) All three first-class (Linux, macOS, Windows)
D) Other (please describe after [Answer]: tag below)

[Answer]: C

### Question 18 — Audit log format & sink
A) JSON Lines to a file/stdout
B) JSON Lines + OpenTelemetry traces/metrics (OTLP export) **(Recommended)**
C) Other (please describe after [Answer]: tag below)

[Answer]: B

### Question 19 — Distribution
A) Single static binary with interpreters embedded **(Recommended)**
B) Binary + interpreters downloaded and cached on first run
C) Binary + Docker image
D) Other (please describe after [Answer]: tag below)

[Answer]: A

## F. Process

### Question 20 — Run the User Stories stage?
This is a developer and infrastructure tool, so personas are mostly "agent developer", "platform/security engineer" and "AI agent".
A) Skip it and use the acceptance criteria in requirements.md **(Recommended)**
B) Yes, generate personas + user stories
C) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 21 — Licensing / ownership
A) Open source, Apache-2.0 **(Recommended for the "get noticed" goal)**
B) Open source, MIT
C) Proprietary / internal
D) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 22 — Toolchain setup on this machine
Rust isn't installed. Construction needs `rustup` (stable), the `wasm32-wasip1` target and probably `wasmtime-cli` and `wizer` for tests.
A) Yes, install them on Windows when Construction starts
B) I'll build in WSL2 / a Linux box; generate code here and give me the commands **(Recommended, given Q17)**
C) I'll install them myself
D) Other (please describe after [Answer]: tag below)

[Answer]: A
