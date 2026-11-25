# Using sandboxd from MCP clients

`sandboxd` exposes these MCP tools:

| Tool | What it does |
|---|---|
| `run_code` | Runs Python 3.15 or JavaScript (QuickJS, ES module) in the sandbox. Returns stdout, stderr, the outcome and the exit code. Files written to `/out` come back as embedded resources. Output streams as progress notifications while the run executes. With `session_id`, the code runs in that session instead of a fresh sandbox. |
| `list_policies` | Lists the operator policies you can pass as `policy`, with their limits and data mounts. |
| `session_create` | Starts a persistent session (like a notebook kernel) under a policy that enables sessions. Returns `session_id`, `expires_at` and the idle timeout. |
| `session_close` | Ends a session. |

`sandboxd mcp` answers the MCP handshake immediately; on a cold cache, the first tool call waits
while the interpreters are compiled (a progress message says so when the client asks for progress).

The server's `instructions` tell the model the rules: no network, no pip/npm, standard library only, inputs under `/in`, outputs under `/out`, nothing persists between calls unless a session is used.

## Sessions (cycle 3)
A session keeps one interpreter alive across calls: Python globals and imports, JavaScript global
declarations, and files under the session-private `/work` carry over. Each call still gets its own
stdout/stderr, `/out` (collected, then cleared), wall-clock limit and fuel budget. JavaScript cells run
as global scripts with top-level `await`; use `await import(...)` instead of `import` statements.

A session ends when it is closed, after `idle_ttl` without a call, at `max_lifetime`, after
`max_calls`, when a call hits the wall-clock or CPU limit, or when the guest exits. Sessions are
in memory only (a server restart ends them) and belong to the principal that created them: anyone
else gets `404 SESSION_NOT_FOUND`. One call runs at a time (`409 SESSION_BUSY`).

Sessions are off unless a policy enables them:
```toml
[session]
enabled = true
idle_ttl = "10m"        # default
max_lifetime = "1h"     # default
max_calls = 1000        # default
max_sessions = 100      # per policy; the server-wide cap is [runtime] max_sessions (default 16)
```
Over HTTP: `POST /v1/sessions` `{language, policy}` → `201` with `session_id`;
`POST /v1/sessions/{id}/runs` `{code, files?, args?, limits?}` (`?stream=true` for SSE);
`GET /v1/sessions/{id}`; `DELETE /v1/sessions/{id}`. Session calls don't take `stdin` (send a file),
and their `limits` may only tighten `wall_clock` and `fuel`.

## Claude Code (stdio)
```bash
claude mcp add sandboxd -- /path/to/sandboxd mcp
# with a config file (policies, cache location, audit path):
claude mcp add sandboxd --env SANDBOXD_CONFIG=/path/to/sandboxd.toml -- /path/to/sandboxd mcp
```

## Claude Desktop (stdio)
Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "sandboxd": {
      "command": "D:\\tools\\sandboxd\\sandboxd.exe",
      "args": ["mcp"],
      "env": { "SANDBOXD_CONFIG": "D:\\tools\\sandboxd\\sandboxd.toml" }
    }
  }
}
```
In stdio mode, stdout carries the protocol and the audit log goes to a file (default: `<OS cache dir>/sandboxd/audit.jsonl`, or `[audit] path` in the config). The principal recorded for each run is `mcp-stdio`.

## Remote / shared (Streamable HTTP)
```bash
sandboxd token new --name claude        # prints a token + the config line with its hash
sandboxd serve --config sandboxd.toml   # MCP at http://<host>:8080/mcp, same bearer auth as /v1
claude mcp add --transport http sandboxd http://127.0.0.1:8080/mcp --header "Authorization: Bearer <token>"
```
The audit log records the token's **name** as the principal, never the token itself.

## Example `sandboxd.toml`
```toml
policy_dir = "policies"
cache_dir  = "D:/sandboxd/cache"     # ~55 MB: compiled interpreters + stdlib bytecode
work_dir   = "D:/sandboxd/work"

[server]
listen = "127.0.0.1:8080"
max_concurrent = 4

[auth]
tokens = [ { name = "claude", sha256 = "<from `sandboxd token new`>" } ]

[audit]
sink = "file"
path = "D:/sandboxd/audit.jsonl"

# Performance (cycle 3). Both default to "auto".
# [runtime]
# pooling = "auto"     # reuse pre-reserved instance slots; "off" allocates per run
# snapshots = "auto"   # start runs from pre-initialised interpreters (built once at start-up,
#                      # cached); "off" uses the upstream interpreters
# max_sessions = 16    # live sessions server-wide; each holds an interpreter (up to its policy's
#                      # memory limit) until it ends

# Operator Python packages (cycle 5): a directory of pure-Python wheels (py3-none-any), validated
# at start-up and importable in Python runs unless a policy sets [python] packages = false.
# `sandboxd packages list` checks the directory and prints a lock for [packages.sha256].
# [packages]
# dir = "D:/sandboxd/wheels"

# Optional OTLP/HTTP export of the /metrics instruments plus one `sandboxd.run` span per run.
# Needs a build with `cargo build --release -p sandboxd --features otel`; other builds ignore it
# with a warning. Spans never contain code, output, paths or principals.
# [telemetry]
# otlp_endpoint = "http://otel-collector:4318"   # /v1/metrics and /v1/traces are appended
# otlp_interval = "30s"                          # metric export interval (1s–1h)
```

## Example policy (`policies/data.toml`)
```toml
version = 1
name = "data"
description = "Read-only reference data, 10 s, 512 MiB"

[limits]
wall_clock = "10s"
memory = "512MiB"

[[filesystem.mount]]
guest = "/data"
host = "D:/datasets/reference"
mode = "ro"
```
Check it with `sandboxd policy check policies/data.toml`.
