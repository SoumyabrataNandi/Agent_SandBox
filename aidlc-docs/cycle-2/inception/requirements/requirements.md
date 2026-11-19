# Cycle 2 Requirements — Network Broker (Phase 4) + OTLP

**Status:** Draft for approval · **Date:** 2026-11-19 · **Answers:** Q1–Q10 all recommended (A).
Cycle-1 requirements (FR-1…FR-8, NFR-1…NFR-8) remain in force. This cycle **replaces FR-7** and **completes FR-6.2**.

## 1. Intent
Let sandboxed code reach **operator-approved** HTTP(S) endpoints and TCP services, **only** through a host-side broker that enforces the policy allowlist, blocks SSRF, applies quotas, and audits every connection. The guest never gets a socket, never does TLS, never sees credentials, and never chooses a proxy. Also add an optional OTLP exporter for metrics and traces.

**Out of scope (this cycle):** credential/header injection (Q8), wildcard host rules, WebSockets, HTTP/2 or streaming bodies to the guest (responses are buffered up to a cap), guest-side TLS over raw TCP, Phase 5 performance work.

## 2. Functional requirements

### FR-N1 Broker and devices (implements ADR-002)
- **N1.1** A host `NetworkBroker` implementation registers two device families in the run's `VirtualFdTable`, and only when the policy grants that kind of egress:
  - `/dev/sandbox/http`: request/response devices. Each `open` is one HTTP exchange: the guest writes a JSON request envelope, then reads a JSON response envelope with the body base64-encoded.
  - `/dev/sandbox/tcp/<host>:<port>`: a bidirectional byte stream.
- **N1.2** All network I/O is async and host-side, and it counts against the run's **wall clock**. A request's timeout is the smaller of the policy's per-request timeout and the time left in the run.
- **N1.3** When a run ends, every open connection is closed and **audited**.

### FR-N2 Guest APIs (Q2 = transparent)
- **N2.1 Python:** a `sandbox_net` module (`fetch(url, method=, headers=, body=, timeout=) → Response(status, headers, body, url)` and `connect(host, port) → stream` with `send/recv/sendall/close/makefile`). A small bootstrap installs it as a **`urllib.request` handler** and patches **`socket.create_connection`**, so standard code works unchanged. The bootstrap runs `/code/main.py` with `runpy`, so tracebacks and `sys.argv` stay the same as in cycle 1.
- **N2.2 JavaScript:** a global WHATWG-style **`fetch()`** (Request/Response subset: `status`, `ok`, `headers`, `text()`, `json()`, `arrayBuffer()`). The program is imported dynamically after the bootstrap.
- **N2.3** When the policy grants nothing, these APIs still exist and fail clearly, e.g. `PermissionError: network access is not allowed by policy 'default'`.

### FR-N3 HTTP semantics
- **N3.1** Methods are limited to the rule's `methods`. Schemes are `https`, and `http` only where a rule sets `scheme = "http"` (new optional policy field, default `https`).
- **N3.2 Headers:** the guest may set ordinary headers. The broker controls `Host`, `Content-Length`, `Transfer-Encoding`, `Connection` and the other hop-by-hop headers, and `Proxy-*`. CR/LF or NUL in a header name or value → rejected.
- **N3.3 Redirects:** up to **5**, and **every hop is re-checked** against the allowlist (scheme, host, port, method, path prefix) and SSRF rules (N5). A redirect to a disallowed target ends the request with an error, and each hop is audited.
- **N3.4 Responses** are buffered up to `max_response_bytes`. Beyond that the request fails with a `network` limit. Decompression is the guest's job, so the broker passes encoded bodies through unchanged.

### FR-N4 Allowlist matching
- **N4.1** Matching is exact and case-insensitive on host (an IP literal only matches an IP rule), plus port, method, and path prefix on the **normalized** path (percent-decoding of unreserved characters, `..` / `.` removed, `//` collapsed; a path that can't be normalized is denied).
- **N4.2** The first rule that matches wins. No match → denied, audited, and an error to the guest.

### FR-N5 SSRF and DNS rebinding protection (Q7)
- **N5.1** DNS is resolved on the host. **Every** resolved address is checked. If any address is in a blocked range, the request is denied unless `allow_private_ips = true`.
- **N5.2 Blocked ranges:**
  - loopback (`127.0.0.0/8`, `::1`);
  - RFC 1918, CGNAT `100.64.0.0/10`, ULA `fc00::/7`;
  - link-local (`169.254.0.0/16`, `fe80::/10`);
  - cloud metadata (`169.254.169.254`, `fd00:ec2::254`);
  - unspecified, broadcast and multicast;
  - IPv4-mapped/compatible IPv6 forms of all of the above.
- **N5.3** The connection is **pinned** to the checked IP, so no second resolution happens. TLS SNI and certificate validation use the hostname.
- **N5.4** The cloud-metadata addresses stay blocked **even when** `allow_private_ips = true`, unless they're explicitly listed as an IP rule.

### FR-N6 Quotas
Per run, from the policy's `[network]` section: `max_requests`, `max_request_bytes`, `max_response_bytes`, `max_total_bytes` (in + out, HTTP and TCP combined), plus a new `connect_timeout` and `request_timeout`. Exceeding a quota → a guest error, a new `LimitKind::Network` in `limits_hit`, and a `limit.hit` audit event.

### FR-N7 Raw TCP (Q3)
- **N7.1** Only to `tcp` rules (`host`, `port`). Off by default, opt-in per destination, with the same SSRF rules as N5.
- **N7.2** A plain byte stream: no host-side TLS and no protocol inspection. Byte counts are applied to `max_total_bytes`, and the stream has an idle timeout.
- **N7.3** Audit when the connection closes: destination, resolved IP, bytes in and out, duration and close reason. The content is **not** inspected or logged; this is residual risk R5.

### FR-N8 TLS trust (Q4)
The **OS trust store** (Windows, macOS, Linux) through a platform verifier, plus an optional `network.extra_ca_file` (PEM) in `sandboxd.toml`. There is no option to disable verification.

### FR-N9 Proxy (Q5)
- **N9.1** `sandboxd.toml` `[network] proxy = "http://proxy:8080"`, with a `no_proxy` list. The process environment's `HTTPS_PROXY`/`NO_PROXY` is used **only if** `use_env_proxy = true`.
- **N9.2** SSRF checks (N5) still apply to the *target* host. When a proxy is used, the target hostname is checked by resolution on the host (the proxy itself is trusted operator infrastructure).

### FR-N10 Audit (Q10)
- **N10.1** A `net.request` event for every request and every redirect hop, recording:
  - `proto`, `method`, `scheme`, `host`, resolved `ip`, `port`;
  - `path`, with the query string redacted (`?…[N params]`);
  - `status`, `bytes_out`, `bytes_in`, `duration_ms`;
  - `decision` (`allow`/`deny`) and `reason`.
- **N10.2** A `net.connect` event for TCP sessions.
- **N10.3** **Bodies and header values are never logged.** Header names are logged.

### FR-N11 Policy and server configuration
- **N11.1** `Policy::ensure_supported` **accepts** network grants (sessions stay refused). The policy gains optional per-rule `scheme` and section-level `connect_timeout` / `request_timeout`.
- **N11.2** A server-wide kill switch, `sandboxd.toml` `[network] enabled = true|false` (default `true`). When it's `false`, policies that grant egress are **refused at load** with a clear error.
- **N11.3** `policy check` explains every rule and warns about `allow_private_ips`, `http` (unencrypted) rules and TCP rules.

### FR-O1 OTLP exporter (Q9)
- **O1.1** A cargo feature `otel` (off in default builds). With it on and `telemetry.otlp_endpoint` set, the same counters and histograms as `/metrics` are exported over OTLP/HTTP.
- **O1.2** One **span per run** (`sandboxd.run`) with attributes for language, policy, outcome, limits hit, fuel, timings and request count. It contains **no** code, output, paths or URLs beyond the host name.
- **O1.3** The exporter shuts down cleanly with the server. A failing exporter never blocks or fails a run.

## 3. Non-functional requirements
| ID | Requirement |
|---|---|
| NFR-N1 Security | The escape suite gains an **E-NET** family, release-blocking on 3 OSes. It covers: non-allowlisted host, port, method or path; path traversal in the URL; IP-literal SSRF (loopback, metadata, IPv4-mapped IPv6, decimal/octal IP forms); a redirect to a disallowed target; header CRLF injection and Host spoofing; `http` downgrade; quota exhaustion; slowloris-style slow responses (timeout); TCP to an unlisted port; DNS names resolving to private IPs; guest attempts to use a proxy. **No canary may leak, and no unlisted destination may be contacted.** |
| NFR-N2 Testability | All network tests run against **in-process local servers** (HTTP, HTTPS with a test CA, TCP echo), with no internet dependency in CI. Positive tests use a policy with `allow_private_ips = true`; SSRF tests use the default. |
| NFR-N3 Performance | Broker overhead per HTTP request is ≤ 5 ms (local server, excluding the remote's time). A run without network grants pays nothing measurable. |
| NFR-N4 Platforms | Linux, macOS and Windows, including the OS trust stores. |
| NFR-N5 Supply chain | New dependencies (HTTP client, TLS verifier, opentelemetry under `otel`) pass cargo-deny and cargo-audit with no new ignores. |
| NFR-N6 Compatibility | Cycle-1 APIs, policies and audit schema stay backward compatible. New audit fields and event kinds are additive. |

## 4. Acceptance criteria
1. A policy allowing `GET https://<local test server>/api/` lets Python `urllib.request.urlopen` and JS `fetch` read the response. Both are audited with the redacted query.
2. The same code against a non-allowlisted host, port, method or path fails with a clear error and a `deny` audit event; the test server records **no** connection.
3. `http://127.0.0.1`, `http://169.254.169.254`, `http://[::ffff:127.0.0.1]`, `http://2130706433` and a hostname resolving to `127.0.0.1` are all refused under the default policy.
4. A redirect from an allowed URL to a disallowed host is refused at the hop, and both hops are audited.
5. `max_requests`, `max_response_bytes` and `max_total_bytes` are each enforced, with `limits_hit` containing `network`.
6. TCP to an allowed `host:port` echoes bytes through `sandbox_net.connect` and `socket.create_connection`. Other ports are refused. The session is audited with byte counts.
7. HTTPS to a test server with a CA in `extra_ca_file` succeeds. Without that CA it fails certificate validation.
8. With `[network] enabled = false`, a granting policy is refused at load.
9. With `--features otel` and a local OTLP collector stub, a run produces one span and its metrics. The default build contains no opentelemetry code.
10. The escape suite, including E-NET, passes on all CI runners, and cargo-deny and cargo-audit pass.
