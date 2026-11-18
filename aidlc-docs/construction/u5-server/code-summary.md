# U5 Server + CLI — Code Summary & Test Results (2026-11-18)

Design answers Q1–Q9: all recommended (inline base64 artifacts, MCP embedded resources, input files on both APIs, TOML config, hashed named tokens + `SANDBOXD_TOKEN`, CPU-count concurrency with queue 64 and 10 s timeout, Prometheus + OTLP behind a feature, in-process `run`, per-mode audit defaults).

| File | Content |
|---|---|
| `sandboxd-server/src/service.rs` | `RunService`: fail-closed audit check → policy lookup (audited denial with principal) → decode → admission (semaphore, queue depth, queue timeout) → `Sandbox::execute` → metrics |
| `…/http.rs` | axum router: `POST /v1/runs` (JSON / SSE `stdout`,`stderr`,`limit`,`result`,`error`), `GET /v1/policies`, `/healthz` (public), `/metrics`, MCP Streamable HTTP at `/mcp`; bearer middleware puts `Principal` in request extensions; body limit; structured error envelope with `Retry-After` / `WWW-Authenticate` |
| `…/mcp.rs` | rmcp 3.11 `SandboxMcp`: `run_code` (progress-notification streaming, artifacts as embedded resources with MIME type, `structuredContent`, `isError` only for trap/error/service errors; principal taken from HTTP `Parts` extensions or the transport label), `list_policies`, server instructions written for the model |
| `…/api.rs` | Wire types with JSON Schema (used for the MCP tool schema), base64 inputs, limit overrides, result mapping (lossy UTF-8 + base64 when not UTF-8) |
| `…/auth.rs` | SHA-256 token hashes, constant-time compare (`subtle`), `Bearer` parsing, `generate_token` |
| `…/config.rs` | `sandboxd.toml` (deny unknown fields, relative paths resolved against the file), bind-safety check |
| `…/metrics.rs` | prometheus-client registry: runs, duration histogram, limits hit, rejected, queue depth, running, audit health, startup |
| `sandboxd/src/main.rs` | clap CLI: `run` (streams live, writes artifacts with safe joins, exit codes 0/1/2/3/4/5), `serve` (graceful shutdown, `server.start/stop`), `mcp` (stdio), `policy check|list`, `cache warm|clear|path`, `token new`, `version` |
| `docs/MCP.md`, `README.md`, `examples/` | Claude Code / Desktop setup, HTTP usage, example config and policy |

**Tests:** 16 (2 unit + 9 server integration + 5 binary end-to-end). Workspace total: **85**. fmt and clippy `-D warnings` are clean.

| Acceptance criterion | Evidence |
|---|---|
| **AC 7** MCP from Claude | ✅ in-memory MCP (tools, schema, embedded artifact, **streamed progress**, numpy code, tool errors); ✅ MCP over **Streamable HTTP with bearer token**, principal = token name in audit; ✅ **real `sandboxd mcp` child process over stdio** (exactly the Claude Desktop/Code launch path) |
| **AC 8** auth + bind safety | ✅ 401 without/with a wrong token, 200 with the right one, `/healthz` public, `/metrics` protected; ✅ `serve --listen 0.0.0.0:0` without tokens exits 5 "refusing to listen" |

Also: SSE ordering (stdout before result), 404/400/413 envelopes, policy violation = 200 + error code, 429 + `Retry-After` under load with the metric counted, 503 fail-closed + `/healthz` 503, CLI exit statuses (0/1/2/3), artifact files on disk, audit file contains `run.start` with principal `cli` / `mcp-stdio`.

## Notes / deviations
- **OTLP:** the `otel` cargo feature is reserved in config (`telemetry.otlp_endpoint`). The exporter is **not implemented in this cycle**; Prometheus `/metrics` is. Recorded as a follow-up for U6 or the next cycle.
- The default cache/work/audit location is `%LOCALAPPDATA%\sandboxd` (about 55 MB on C:). `cache_dir` / `work_dir` / `[audit] path` move it (documented in docs/MCP.md).
- With no tokens configured (loopback only), requests are accepted as principal `local-unauthenticated`, and a warning is printed at startup.
