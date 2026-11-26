# Getting started

This guide takes you from a downloaded release to an agent running code in sandboxd: about 10 minutes.
sandboxd is one self-contained binary; the Python and JavaScript interpreters are embedded in it.

## 1. Download
Pick the archive for your platform from the [latest release](https://github.com/SoumyabrataNandi/Agent_SandBox/releases/latest):

| Platform | Archive |
|---|---|
| Linux x86-64 | `sandboxd-<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 | `sandboxd-<version>-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Apple silicon | `sandboxd-<version>-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `sandboxd-<version>-x86_64-apple-darwin.tar.gz` |
| Windows x86-64 | `sandboxd-<version>-x86_64-pc-windows-msvc.zip` |

Download `SHA256SUMS` from the same release.

## 2. Verify
Every archive was built in GitHub Actions after the escape suite passed against it on its own platform.
Check the download before you run it:
```bash
sha256sum --ignore-missing -c SHA256SUMS          # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
gh attestation verify sandboxd-<version>-<target>.tar.gz --repo SoumyabrataNandi/Agent_SandBox
```
On Windows (PowerShell), compare `(Get-FileHash .\sandboxd-<version>-x86_64-pc-windows-msvc.zip).Hash`
with the line in `SHA256SUMS`.

## 3. Install and warm the cache
Unpack the archive anywhere you like; no admin rights are needed. Put `sandboxd` on your `PATH`, or call it by its full path.
```bash
tar xzf sandboxd-<version>-<target>.tar.gz
cd sandboxd-<version>-<target>
./sandboxd version
./sandboxd cache warm      # once: compiles the interpreters and builds the snapshots (~20–70 s)
```
**Run `cache warm` once after installing.** Without it, the first tool call after starting
`sandboxd mcp` waits while the cache is built (the MCP connection itself is immediate).

The cache lives in your OS cache directory (`sandboxd cache path` prints it); it is under 100 MB.
Set `cache_dir` in a config file to put it elsewhere (for example on a larger drive).

## 4. First run
```bash
echo 'import statistics; print(statistics.mean([3, 4, 5]))' > hello.py
./sandboxd run hello.py
./sandboxd run job.py --input data.csv --timeout 2s --memory 128mb   # data.csv appears as /in/data.csv
```
Programs can read their inputs under `/in` and write results to `/out`. They get the Python
standard library (or plain JavaScript), no network unless a policy allows it, and no access to your files.

## 5. Connect an agent (MCP)
**Claude Code:**
```bash
claude mcp add sandboxd -- /full/path/to/sandboxd mcp
```
**Claude Desktop:** add this to `claude_desktop_config.json`, then restart Claude Desktop:
```json
{
  "mcpServers": {
    "sandboxd": { "command": "C:\\tools\\sandboxd\\sandboxd.exe", "args": ["mcp"] }
  }
}
```
Ask the agent something like *"Use sandboxd to compute the median of these numbers…"*. It gets four
tools: `run_code`, `list_policies`, `session_create` and `session_close`. Details: [MCP.md](MCP.md).

## 6. Run it as a service (HTTP + remote MCP)
```bash
./sandboxd token new --name my-agent     # prints a token and the config line with its hash
```
Create `sandboxd.toml`:
```toml
policy_dir = "policies"

[server]
listen = "127.0.0.1:8080"

[auth]
tokens = [ { name = "my-agent", sha256 = "<hash printed above>" } ]

[audit]
sink = "file"
path = "audit.jsonl"
```
```bash
./sandboxd serve --config sandboxd.toml
curl -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"language":"python","code":"print(6*7)"}' \
     http://127.0.0.1:8080/v1/runs
```
The same server speaks MCP at `/mcp` for remote agents. Put TLS (a reverse proxy) in front of it
before exposing it beyond localhost.

## 7. Write a policy
Policies are TOML files in `policy_dir`. Agents pick one by name and can only make its limits stricter.
```toml
# policies/data.toml
version = 1
name = "data"
description = "Read-only reference data, 10 s, 512 MiB"

[limits]
wall_clock = "10s"
memory = "512MiB"

[[filesystem.mount]]
guest = "/data"
host = "/srv/datasets"
mode = "ro"
```
```bash
./sandboxd policy check policies/data.toml
./sandboxd policy list --config sandboxd.toml
```
Sessions (persistent interpreters) need `[session] enabled = true`; network access needs an allowlist.
See [MCP.md](MCP.md#sessions-cycle-3) and [NETWORK.md](NETWORK.md).

## 8. Python packages (optional)
Agents can't `pip install`. You can give them **pure-Python** packages from a directory of wheels:
```bash
mkdir wheels && pip download --only-binary=:all: --no-deps -d wheels tabulate python-dateutil six
sandboxd packages list --config sandboxd.toml      # validates, and prints a lock you can paste
```
```toml
[packages]
dir = "wheels"
# Optional but recommended: pin every wheel (sandboxd refuses to start on a mismatch).
# [packages.sha256]
# "tabulate-0.9.0-py3-none-any.whl" = "<sha256>"
```
Only wheels tagged `py3-none-any` (or `py2.py3-none-any`) are accepted; anything with native code
is refused at start-up, naming the file. Packages are read-only, come after the standard library on
`sys.path`, and are available in every Python run unless a policy sets `[python] packages = false`.
`list_policies` tells agents which packages exist.

## 9. Container image
Each release also publishes `ghcr.io/soumyabratanandi/sandboxd:<version>` (linux/amd64 and
linux/arm64). It runs `sandboxd serve` on port 8080 as a non-root user, with the audit log on stdout.
```bash
sandboxd token new --name my-agent          # any sandboxd binary, or: docker run --rm <image> token new --name my-agent
docker run -d -p 8080:8080 \
  -e SANDBOXD_TOKENS="my-agent=<sha256 printed above>" \
  -v sandboxd-cache:/var/cache/sandboxd \
  ghcr.io/soumyabratanandi/sandboxd:<version>
curl http://127.0.0.1:8080/healthz          # ready once the cache is built (first start: about 20-60 s)
```
- Keep the cache volume so restarts skip the build.
- Your own config: mount it at `/etc/sandboxd/sandboxd.toml` (and policies at `/etc/sandboxd/policies`,
  wheels anywhere you point `[packages] dir` to); then don't set `SANDBOXD_TOKENS`.
- `--read-only` works with `--tmpfs /tmp --tmpfs /var/lib/sandboxd/work` and the cache volume.
- Put TLS in front of it (ingress or reverse proxy) before exposing it beyond the host.

## Troubleshooting
| Symptom | Fix |
|---|---|
| The first tool call takes a while | Since 0.2.0 the MCP server connects at once and the first call waits for the cache build. Run `sandboxd cache warm` after installing to avoid that wait. |
| `UNSUPPORTED_NATIVE_EXTENSION` | NumPy, pandas and other native extensions don't run in WebAssembly. Use the standard library (`csv`, `statistics`, `json`, `decimal`). |
| `POLICY_NOT_FOUND` | The name isn't in `policy_dir`; `sandboxd policy list` shows what's loaded. |
| `SESSION_NOT_FOUND` | The session ended (idle timeout, limit, close or server restart) or belongs to another token. Create a new one. |
| A run ends with `limits hit: wall_clock` or `fuel` | It ran longer than the policy allows. Raise the limit in the policy (agents can't raise it themselves). |
| `packages: <file>: ...` at start-up | A wheel in `[packages] dir` was refused (native code, not `py3-none-any`, unsafe entries, or a lock mismatch). Remove or replace it; `sandboxd packages list` checks the directory. |
| Low disk space | `sandboxd cache clear` removes the cache (rebuilt on next use). Set `cache_dir` and `work_dir` to another drive. |

Security problems: please follow [SECURITY.md](../SECURITY.md), not public issues.
