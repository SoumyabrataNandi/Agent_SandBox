# Network access

Sandboxed programs have **no network access** unless the run's policy grants it. A policy can grant two kinds of egress, and nothing else is reachable:

- **HTTP(S) requests** to listed destinations;
- **raw TCP connections** to listed `host:port` pairs (opt-in).

Every request goes through a broker inside the sandboxd process. The broker:

- checks the allowlist before any DNS lookup;
- blocks private, loopback, link-local and cloud-metadata addresses (SSRF), including encoded IP forms and names that resolve to them;
- pins each connection to the address it checked (no DNS rebinding);
- follows redirects itself and re-checks every hop;
- controls framing headers (`Host`, `Content-Length`, …);
- enforces quotas and timeouts;
- records every request in the audit log.

Programs use ordinary libraries: Python `urllib.request`, `http.client`, `socket.create_connection`, and JavaScript `fetch`.

## 1. Grant access in a policy

```toml
# policies/github.toml
version = 1
name = "github"
description = "Read-only GitHub API"

[network]
http = [
  { host = "api.github.com", methods = ["GET"], path_prefix = "/repos/" },
]
```

A rule matches when **all** of its fields match:

| Field | Default | Meaning |
|---|---|---|
| `host` | (required) | Exact host name, or an IP literal. No wildcards. Matching is case-insensitive. An IP literal in a URL only matches an IP rule. |
| `scheme` | `"https"` | `"http"` must be explicit. A redirect from https to http is always refused. |
| `port` | 443 / 80 | Port number |
| `methods` | `["GET"]` | Any of `GET HEAD POST PUT PATCH DELETE OPTIONS` |
| `path_prefix` | `"/"` | Matched by segment against the **normalized** path. `/repos/` does not match `/repos-admin`. `..`, `%2e%2e` and `//` are resolved first. Encoded `/` or `\` (`%2F`, `%5C`) is refused. |

Raw TCP (for databases, SMTP and similar protocols) is listed separately. The broker can audit only the destination and byte counts, not the content:

```toml
[network]
tcp = [ { host = "db.internal.example", port = 5432 } ]
allow_private_ips = true      # db.internal.example resolves to 10.x
```

### Limits (per run)
| Key | Default | Notes |
|---|---|---|
| `max_requests` | 100 | Counts HTTP requests and TCP connections. Each redirect hop is one request. |
| `max_request_bytes` | 1 MiB | Largest request body |
| `max_response_bytes` | 10 MiB | Largest response body. Responses are buffered; larger ones fail with `RESPONSE_TOO_LARGE`. |
| `max_total_bytes` | 50 MiB | All traffic in both directions |
| `connect_timeout` | 5s | 100 ms – 60 s |
| `request_timeout` | 30s | 100 ms – 10 min. Also the idle timeout for TCP reads and writes. |

Network time counts against the run's `wall_clock`. Exceeding a quota or timeout makes the run's outcome `limit`, with `network` in `limits_hit`.

### Private addresses and cloud metadata
`allow_private_ips = false` is the default. It blocks loopback, RFC 1918, CGNAT, link-local, ULA, multicast, documentation ranges, and IPv6 transition forms that embed one of those addresses. If **any** address a name resolves to is blocked, the request is refused.

For internal services, set `allow_private_ips = true` **and** list the exact hosts. Cloud metadata endpoints (`169.254.169.254`, `100.100.100.200`, `168.63.129.16`, `fd00:ec2::254`) stay blocked even then, unless a rule names the IP literal.

Check a policy before deploying it:
```sh
sandboxd policy check policies/github.toml
```

## 2. Server settings (`sandboxd.toml`)
```toml
[network]
enabled = true                 # kill switch: false refuses every policy that grants egress
proxy = "http://proxy.corp:3128"   # optional operator proxy (http:// or https://)
no_proxy = ["api.internal.corp"]   # destinations that bypass the proxy
use_env_proxy = false          # true: also honour HTTPS_PROXY/NO_PROXY from sandboxd's environment
extra_ca_file = "corp-ca.pem"  # added to the OS trust store (for TLS-inspecting proxies, internal CAs)
```

### Proxy guidance
- **Only the operator configures a proxy.** Proxies set by the program are refused: `HTTP_PROXY` in a policy's env, urllib's `ProxyHandler`, `http.client` `set_tunnel`, and absolute-form requests. The system proxy is never used implicitly.
- **With a proxy, the proxy resolves host names**, so sandboxd can't pin addresses or check what a name resolves to (residual risk R8). sandboxd still enforces the allowlist and IP-literal checks first. **Configure the proxy to deny private, loopback, link-local and metadata ranges.** Alternatively, use `no_proxy` for internal destinations, which sandboxd connects to directly with full SSRF checks.

## 3. Using the network from programs

### Python
```python
import json, urllib.request
with urllib.request.urlopen("https://api.github.com/repos/python/cpython") as r:
    print(json.load(r)["stargazers_count"])

import http.client                       # HTTPSConnection works (TLS is done by the broker)
c = http.client.HTTPSConnection("api.github.com")
c.request("GET", "/repos/python/cpython", headers={"User-Agent": "agent"})
print(c.getresponse().status)

import sandbox_net                       # small direct API
r = sandbox_net.fetch("https://api.github.com/repos/python/cpython", headers={"Accept": "application/json"})
print(r.status, r.json()["name"])

import socket                            # raw TCP (needs a `tcp` rule)
s = socket.create_connection(("db.internal.example", 5432))
```
Errors are standard exceptions. Each carries a `.code` attribute with the broker code (section 4). With `urllib`, they arrive as `URLError` whose `.reason` is the exception, just as for a refused connection.
```
urllib.error.URLError: <urlopen error no rule allows https://10.0.0.5:443>
PermissionError: network access is not allowed by policy 'default'
```
Notes:
- **Requests:** the network APIs block until the response arrives. There are no non-blocking sockets, `select()` or asyncio networking. `socket.socket()` itself is unavailable; use `socket.create_connection`.
- **TLS:** the `ssl` module is unavailable. `HTTPSConnection` uses the broker's TLS, verified against the OS trust store plus `extra_ca_file`.
- **Bodies:** responses are passed through unchanged, so decompress them yourself if needed.

### JavaScript
```js
const r = await fetch('https://api.github.com/repos/python/cpython', { headers: { Accept: 'application/json' } });
if (!r.ok) throw new Error(`HTTP ${r.status}`);
const repo = await r.json();
console.log(repo.stargazers_count, r.headers.get('content-type'));
```
- **API:** `fetch`, `Headers` and `Response` follow the WHATWG API. `fetch` supports `method`, `headers`, `body` (string, `ArrayBuffer`, typed array) and `redirect: 'follow'`. `Response` supports `text()`, `json()`, `arrayBuffer()`, `bytes()` and `clone()`.
- **Errors:** network errors reject with `TypeError`. `e.cause.code` holds the broker code.
- **Blocking:** a request blocks the single guest thread while it runs.
- **Raw TCP:** there is no raw TCP API in JavaScript.

## 4. Error codes
| Code | Meaning | Python | JS |
|---|---|---|---|
| `NETWORK_DISABLED` | The policy grants no (HTTP or TCP) access | `PermissionError` | `TypeError` |
| `DENIED` | No rule matches (host, port, scheme, method or path), a disallowed redirect hop, an https→http downgrade, or a proxy attempt | `PermissionError` | `TypeError` |
| `SSRF` | The destination resolves to, or is, a blocked address | `PermissionError` | `TypeError` |
| `DNS` | The name could not be resolved | `socket.gaierror` | `TypeError` |
| `CONNECT` / `TLS` | Connection or certificate failure | `ConnectionError` | `TypeError` |
| `TIMEOUT` | `connect_timeout` / `request_timeout` / run deadline | `TimeoutError` | `TypeError` |
| `QUOTA` / `RESPONSE_TOO_LARGE` | A per-run quota is exhausted, or the response is larger than `max_response_bytes` | `OSError` | `TypeError` |
| `TOO_MANY_REDIRECTS` | More than 5 hops | `OSError` | `TypeError` |
| `PROTOCOL` | Invalid header (CR/LF/NUL), method or URL | `OSError` | `TypeError` |

## 5. Audit
Each hop of each HTTP request produces a `net.request` event. Each TCP connection produces a `net.connect` event when it closes. Both record whether the request was allowed or denied, and why.

| Event | Fields |
|---|---|
| `net.request` | `scheme`, `host`, resolved `ip`, `port`, `method`, `path`, `status`, `hop`, bytes out/in, `duration_ms` |
| `net.connect` | `host`, `ip`, `port`, bytes, `duration_ms` |

Query strings are logged as `?…[N params]`; query **values**, headers and bodies are never logged. Quota and timeout limits add a `limit.hit` event of kind `network`.

## 6. Security model
See [THREAT_MODEL.md](../THREAT_MODEL.md): threats T13–T18, residual risks R5 and R8–R10. Every guarantee above is exercised by the release-blocking **E-NET** escape-suite family on Linux, macOS and Windows. E-NET uses real Python and JavaScript programs against local servers, and fails if any forbidden destination is contacted even once.
