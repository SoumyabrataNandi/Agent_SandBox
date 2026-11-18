# U5 Server + CLI — Design Questions

Design: `design.md`. Answer after each `[Answer]:` tag, or reply **"accept recommended defaults"**.

### Question 1 — Artifacts over HTTP
A) Inline in the JSON response as base64 (bounded by the policy's `artifact_bytes`, 16 MiB by default). One round trip, no server-side state **(Recommended for this cycle)**
B) Store them server-side with a TTL and return download URLs (`GET /v1/runs/{id}/artifacts/{name}`)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 2 — Artifacts in MCP `run_code` results
A) As embedded resources (text if UTF-8, else a base64 blob), plus a summary list in the text content **(Recommended; the agent can read them directly)**
B) Summary only (names, sizes, hashes); content omitted
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 3 — Input files from agents
A) Allowed in both HTTP and MCP: `files: [{name, content, encoding: utf8|base64}]`, validated by U3 rules and capped by `input_bytes` **(Recommended)**
B) HTTP only (MCP tool takes code only)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 4 — Server config file format
A) TOML (`sandboxd.toml`), consistent with policies and Rust tooling **(Recommended)**
B) TOML or YAML (like policies)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 5 — How tokens are configured
A) **Named SHA-256 hashes in config** (no plaintext secrets at rest), plus an optional `SANDBOXD_TOKEN` env var for single-token setups. `sandboxd token new --name ci` prints a fresh token and its hash line **(Recommended)**
B) Plaintext tokens in config / env only
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 6 — Concurrency defaults
A) `max_concurrent` = number of CPUs, `queue_depth` = 64, `queue_timeout` = 10 s; 429 with `Retry-After` beyond that **(Recommended)**
B) Unbounded queue (just a concurrency cap)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 7 — OpenTelemetry (FR-6.2, moved here from U2)
A) Prometheus `/metrics` always. **OTLP export (metrics + traces) behind a cargo feature `otel`**, off in default builds, so the default binary stays small and free of the fast-moving opentelemetry crates **(Recommended)**
B) Prometheus only in this cycle; OTLP deferred
C) OTLP always compiled in, enabled by config
D) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 8 — `sandboxd run` (CLI)
A) Runs **in-process** (no server needed); same engine, policies, audit **(Recommended)**
B) Acts as a client of a running `sandboxd serve`
C) Both (`--remote URL` switches to client mode)
D) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 9 — Where the audit log goes by default
A) `serve` → `stdout` (container/12-factor friendly). `mcp` → a file under the OS data dir (stdout is the MCP channel). `run` → a file as well. All overridable in config **(Recommended)**
B) Always a file
C) Other (please describe after [Answer]: tag below)

[Answer]: 
