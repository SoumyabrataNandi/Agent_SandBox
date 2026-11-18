# Using sandboxd from MCP clients

`sandboxd` exposes two MCP tools:

| Tool | What it does |
|---|---|
| `run_code` | Runs Python 3.15 or JavaScript (QuickJS, ES module) in the sandbox. Returns stdout, stderr, the outcome and the exit code. Files written to `/out` come back as embedded resources. Output streams as progress notifications while the run executes. |
| `list_policies` | Lists the operator policies you can pass as `policy`, with their limits and data mounts. |

The server's `instructions` tell the model the rules: no network, no pip/npm, standard library only, inputs under `/in`, outputs under `/out`, nothing persists between calls.

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
