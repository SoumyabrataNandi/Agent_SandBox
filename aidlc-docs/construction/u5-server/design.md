# U5 Server + CLI — Functional, NFR & Infrastructure Design

**Crates:** `sandboxd-server` (C5: RunService, HTTP, MCP, auth, metrics) and `sandboxd` (C6: CLI, config, wiring).
**Inputs:** U4 `Sandbox`, U1 `PolicyDir`, U2 `AuditSink` (fail-closed health), FR-5, FR-6.2, FR-2.5, AC 7 and 8.
**Dependencies (current):** axum 0.8.9, rmcp 3.11 (official MCP SDK), clap 4.6, tower-http 0.7, prometheus-client 0.26, tracing 0.1, schemars 1.2, base64 0.23, subtle 2.6. OTLP is optional (Q7).

## 1. RunService (the only path to the sandbox)
```rust
pub struct RunService { sandbox: Sandbox, policies: PolicyDir, audit: Arc<dyn AuditSink>, admission: Admission, metrics: Metrics }
impl RunService {
    pub async fn submit(&self, principal: &Principal, req: ApiRunRequest, events: Option<mpsc::Sender<RunEvent>>)
        -> Result<RunResult, ServiceError>;
    pub fn policies(&self) -> Vec<PolicySummary>;
    pub fn health(&self) -> Health;   // audit healthy? cache warm? queue depth
}
```
| Step | Rule |
|---|---|
| S1 | **Fail closed** (U2 Q6): if `audit.is_healthy()` is false → `AUDIT_UNAVAILABLE` (HTTP 503). |
| S2 | Policy lookup by name (default `"default"`). Unknown → `POLICY_NOT_FOUND` (404). Never fall back. |
| S3 | **Admission** (FR-2.5): a `Semaphore(max_concurrent)`, a bounded queue (`queue_depth`), and a `queue_timeout`. Full queue → `OVERLOADED` (429, `Retry-After`). Timed out in queue → `OVERLOADED`. `timings.queued_ms` is filled in. |
| S4 | Convert `ApiRunRequest` → `RunRequest` (decode base64 inputs; size checks happen *before* decoding via the body limit). |
| S5 | `sandbox.execute(...)` → `RunResult`, then metrics are updated. |

## 2. HTTP API (axum)
| Method + path | Auth | Description |
|---|---|---|
| `POST /v1/runs` | bearer | JSON request → JSON `RunResult` |
| `POST /v1/runs?stream=true` | bearer | SSE: `stdout`/`stderr` (base64 chunks + utf-8 text when valid), `limit`, then `result` (same JSON as sync) |
| `GET /v1/policies` | bearer | `[{name, description, overrides_builtin}]` (no host paths) |
| `GET /healthz` | none | `200 {"status":"ok"}` or `503` when audit is unhealthy |
| `GET /metrics` | bearer (configurable: `metrics_public`) | Prometheus text |
| `/mcp` | bearer | MCP Streamable HTTP (§3) |

**Request:**
```json
{ "language": "python", "code": "...", "policy": "default",
  "files": [{"name": "data/a.csv", "content": "...", "encoding": "utf8|base64"}],
  "args": [], "stdin": null, "limits": {"wall_clock": "1s", "memory": "64MiB"} }
```
**Response:**
```json
{ "run_id", "outcome", "exit_code", "stdout", "stderr", "stdout_truncated", "stderr_truncated",
  "artifacts": [{"name","size","sha256","content_base64"}], "limits_hit": [...],
  "error": {"code","message"} | null, "fuel_used", "peak_memory", "timings" }
```
- `stdout`/`stderr` are lossy UTF-8; each also has a `_base64` variant included only when the bytes aren't valid UTF-8.
- **Errors** use a JSON envelope `{"error":{"code","message"}}` with these statuses: 400 (`INVALID_REQUEST`, `POLICY_VIOLATION`), 401, 404, 413 (body too large), 429, 503. A guest failure is **not** an HTTP error: it returns 200 with an `outcome` field.
- **Body limit:** `max_request_bytes` (default 64 MiB). This is checked by tower-http *before* the body is parsed.

## 3. MCP server (rmcp)
| Tool | Input schema | Output |
|---|---|---|
| `run_code` | `language` (python\|javascript), `code`, `policy?`, `files?` [{name, content, encoding?}], `args?`, `stdin?` | Text content: a compact summary (outcome, exit code, limits, error) plus stdout/stderr. Artifacts as **embedded resources** (`sandboxd://runs/<id>/<name>`, text if UTF-8 else blob). `structuredContent` holds the full result JSON. `isError` is true only for service errors and traps, not for non-zero exits. |
| `list_policies` | — | Names and descriptions (no host paths) |

- **Transports:** `sandboxd mcp` uses stdio. stdout is reserved for JSON-RPC; logs go to stderr and audit to a file (Q9). `sandboxd serve` mounts Streamable HTTP at `/mcp` on the same listener, with the same bearer auth.
- **Streaming:** while a run executes, stdout/stderr chunks are sent as `notifications/progress` when the client supplied a `progressToken`. Progress is the elapsed fraction of the wall-clock budget, and the message is the chunk text.
- **Tool descriptions** tell the model the sandbox rules plainly: no network, no pip, the stdlib only, `/in` inputs and `/out` artifacts, and the limits from the selected policy. This is how an agent learns to use the tool well.

## 4. Auth (FR-5.4, AC 8)
- Tokens come from config as **named SHA-256 hashes** (`[[auth.tokens]] name = "ci", sha256 = "…"`), plus an optional single `SANDBOXD_TOKEN` env var (Q5).
- **Comparison:** hash the presented token, then use a constant-time compare (`subtle`) against every configured hash.
- **Principal:** the token's name, or `token:<hash prefix>` for the env token. It goes into every audit event.
- **Bind safety:** if the listen address is not loopback and no tokens are configured, startup is **refused** with an explanatory error. Loopback with no tokens is allowed but warned about (local dev).
- `sandboxd mcp` (stdio) needs no token: the parent process is the trust boundary.

## 5. CLI (clap)
```
sandboxd run <file|-> [--lang py|js] [--policy NAME] [--timeout 2s] [--memory 128mb] [--fuel 5G]
                     [--input PATH]... [--out DIR] [--arg A]... [--json]
sandboxd serve [--listen 127.0.0.1:8080] [--config sandboxd.toml]
sandboxd mcp   [--config sandboxd.toml]
sandboxd policy check <file>...  |  sandboxd policy list
sandboxd cache warm | cache clear | cache path
sandboxd version
```
- `run` executes **in-process** (Q8), with no server. The language comes from the extension or `--lang`. CLI limits are `Overrides` (tighten only). Inputs become `/in/<basename>` (or `--input name=path`). Artifacts are written to `--out` (default `./sandboxd-out/<run_id>/`), with path components validated. Exit status: 0 if `Ok`, 1 if `Exit`, 2 for usage, 3 for `Limit`, 4 for `Trap`/`Error`. `--json` prints the API JSON.
- `policy check` validates files, prints `explain()` and warnings, and reports `ensure_supported` failures. It exits non-zero on any error.

**Config (`sandboxd.toml`, Q4):**
```toml
policy_dir = "./policies"            # optional; built-in default only if absent
cache_dir  = "..."                   # default: OS cache dir (U3 Q6)
[server]  listen = "127.0.0.1:8080"; max_concurrent = 0 # 0 → CPU count; queue_depth = 64; queue_timeout = "10s"
          max_request_bytes = "64MiB"; metrics_public = false
[auth]    tokens = [ { name = "ci", sha256 = "…" } ]
[audit]   sink = "file" | "stdout" | "none"; path = "..."; redact = [ { name = "emp", regex = "EMP-\\d{6}" } ]
[telemetry] otlp_endpoint = ""       # Q7
```
The cache dir, work dir, audit-log dir and policy dir are passed to `LoadOptions.forbidden_host_roots`, so a policy can't mount sandboxd's own state.

## 6. Metrics (FR-6.2)
Prometheus: `sandboxd_runs_total{language,policy,outcome}`, `sandboxd_run_duration_seconds{language}` (histogram), `sandboxd_limits_hit_total{kind}`, `sandboxd_queue_depth`, `sandboxd_running`, `sandboxd_rejected_total{reason}`, `sandboxd_audit_healthy`, `sandboxd_startup_seconds`.

## 7. NFR (scaled)
- **Security:**
  - `#![forbid(unsafe_code)]`.
  - Tokens are never logged.
  - No host paths in API responses (policy origin is hidden; trap messages are already sanitized).
  - CORS is off, and there is no cookie auth, so browsers can't call the API cross-origin.
  - Request IDs are the run IDs.
- **Reliability:** graceful shutdown on Ctrl-C/SIGTERM: stop accepting, drain running runs (up to the max wall clock + 5 s), emit `server.stop`, flush audit.
- **Testing:**
  - AC 7: MCP over stdio is driven by an in-process rmcp *client*, `run_code` and `list_policies` are called, and streamed progress is asserted.
  - AC 8: 401 without or with a wrong token, 200 with the right one, and startup refusal on `0.0.0.0` without tokens.
  - HTTP sync and SSE, 404/413/429, the 503 fail-closed path (failing audit sink), metrics exposure, and CLI end to end (`sandboxd run hello.py` exit code and artifact files).
  - A manual Claude Desktop/Code config snippet in the docs.

## 8. Infrastructure
None new. CI already runs on 3 OSes. A release workflow comes in U6.
