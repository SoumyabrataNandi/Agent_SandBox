# C2-U2 `sandboxd-net` Broker — Functional, NFR & Infrastructure Design

**Implements:** FR-N1, N3–N10 (host side), ADR-C2-1/2/4/5. **Depends on:** C2-U1 (policy `NetworkPolicy`, audit `NetRequest`/`NetConnect`, `LimitKind::Network`), `sandboxd-vfs` (`VirtualDevice`, `VirtualFdTable`).

## 1. Module layout
```
sandboxd-net/src/
  lib.rs        Broker, BrokerConfig, RunCtx, RunNet, NetReport, NetError
  url.rs        parse + canonicalize target URLs (FR-N4.1)
  allow.rs      rule matching (HTTP, TCP)
  ip.rs         IP classification incl. IPv6 transition forms (FR-N5.2)
  resolve.rs    PinningResolver (reqwest::dns::Resolve) + preflight for IP literals
  quota.rs      per-run counters (requests, bytes, limit flag)
  frame.rs      device wire codec (ADR-C2-2)
  http.rs       HttpDevice + exchange (redirect loop, header policy, capped body)
  tcp.rs        TcpDevice (connect, idle timeout, byte accounting)
  audit.rs      net.request / net.connect / limit.hit helpers, query redaction
```

## 2. Target URL rules (FR-N4.1)
Parsing uses the WHATWG `url` crate, which already canonicalizes `http://2130706433/` → `127.0.0.1`, `0x7f.1` → `127.0.0.1`, IPv6 brackets, IDNA/punycode, and dot segments, including `%2e%2e`.

| ID | Rule |
|---|---|
| U1 | Scheme must be `http` or `https`; anything else → `PROTOCOL` |
| U2 | **userinfo** (`user:pass@host`) → deny. Credentials in URLs never leave the guest. |
| U3 | The fragment is dropped. The query is kept for the request and **redacted** for audit (`?…[3 params]`). |
| U4 | The path is the canonical one from `url`, after dot-segment removal. **Encoded separators `%2F`, `%5C` (any case) or a raw `\`** → deny (Q3), because they bypass prefix rules on servers that decode them. |
| U5 | Path prefix match is **segment-aware**: a prefix ending in `/` → `starts_with`; otherwise `path == prefix` or `path.starts_with(prefix + "/")`. So `/v1` matches `/v1` and `/v1/x`, but not `/v1admin`. |
| U6 | Host matching is exact and case-insensitive on the canonical host. An IP literal only matches an IP rule with the same canonical form. |

## 3. Allowlist (FR-N4.2)
A request is allowed if **some** HTTP rule matches on scheme, host, port (explicit, or the scheme's default), method and path prefix. The first match wins. The decision carries a reason such as `no rule for https://x:443`, `method POST not allowed`, `path /admin outside /v1/`, or `scheme http not allowed`.

## 4. SSRF classification (FR-N5)
`ip::classify(addr) -> Class::{Public, Private(&'static str), Metadata}`

| Class | Ranges |
|---|---|
| Metadata (always blocked unless an **IP rule** names it) | `169.254.169.254`, `fd00:ec2::254`, `100.100.100.200` (Alibaba), `168.63.129.16` (Azure wireserver) |
| Private (blocked unless `allow_private_ips`) | `0.0.0.0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`, `192.168/16`, `198.18/15`, `224/4` (multicast), `240/4`, `255.255.255.255`; `::`, `::1`, `fc00::/7`, `fe80::/10`, `ff00::/8`; **Teredo `2001::/32`** (Q7) |
| Embedded IPv4 (classified by the inner address) | IPv4-mapped `::ffff:0:0/96`, IPv4-compatible `::/96`, 6to4 `2002::/16`, NAT64 `64:ff9b::/96` |

- **Resolver:** `tokio::net::lookup_host((name, 0))` returns every address. If it returns none → `DNS`. If **any** address is not `Public` (respecting `allow_private_ips` and the metadata rule) → **the whole name is rejected** (`SSRF: example.internal resolves to 10.0.0.5`). Otherwise the vetted addresses are returned to reqwest, which connects only to them. That's one resolution per connection, so the connection is pinned.
- **IP-literal targets** (reqwest skips the resolver for them) are checked by `preflight()` before sending. TCP targets use the same resolver logic.
- **Proxy configured:** the proxy host is exempt from the check, since it's operator infrastructure. The target is pre-resolved and checked (residual risk R8).

## 5. HTTP exchange (FR-N3)
**Per-run `reqwest::Client`** (ADR-C2-5):
- `dns_resolver(PinningResolver)`, `redirect::Policy::none()`, **retries disabled**, `referer(false)`;
- no automatic decompression (bodies pass through), `connect_timeout(policy)`, and the pool is dropped when the run ends;
- extra CA added with `tls_certs_merge(from_pem_bundle)`, and the proxy set by config (`no_proxy()` otherwise).

| Step | Rule |
|---|---|
| H1 Frame | Header JSON ≤ 64 KiB, ≤ 100 headers, each value ≤ 8 KiB (Q5). Body = `body_len` ≤ `max_request_bytes`. |
| H2 Headers | Names must be RFC 7230 tokens; values must not contain CR, LF or NUL → otherwise `PROTOCOL`. **Dropped:** `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Proxy-*`, plus any header listed in `Connection`. The broker sets `Host` from the URL. |
| H3 Quota | `requests += 1` per hop and `bytes += body_len` (out) before sending. Over quota → `QUOTA` + limit `network`. |
| H4 Timeout | Smaller of `request_timeout` and the run's remaining wall clock, applied to the whole exchange including redirects. |
| H5 Response | Status + headers (hop-by-hop removed, Q2), body streamed via `chunk()` up to `max_response_bytes`, with every chunk counted toward `max_total_bytes`. Over the cap → `RESPONSE_TOO_LARGE` + limit `network`. |
| H6 Redirects (Q4, Q6) | 301/302/303 → `GET` with no body (`HEAD` stays `HEAD`); 307/308 keep the method and body. `Location` is resolved relative to the current URL. **Each hop:** U1–U6 + allowlist + preflight/resolver again; **an https → http downgrade is refused** even if an http rule exists; hop ≤ 5 (else `TOO_MANY_REDIRECTS`). `Authorization` and `Cookie` headers are **dropped on cross-origin hops**. Each hop is audited. |
| H7 Errors | The response frame has `status: 0` and `error: {code, message}`. Codes: `DENIED`, `SSRF`, `DNS`, `CONNECT`, `TLS`, `TIMEOUT`, `QUOTA`, `RESPONSE_TOO_LARGE`, `TOO_MANY_REDIRECTS`, `PROTOCOL`, `NETWORK_DISABLED`. Messages name the host but never echo header values or bodies. |

### Device state machine (`HttpDevice`)
`Writing(buf)` → (first read with a complete frame) → `Done(response_frame, offset)` → reads drain it → `0`. A read before the frame is complete → `EINVAL`. A write after the exchange → `EBADF`. Each open fd is one exchange; the shims open a new fd per request.

## 6. TCP (FR-N7)
`open("/dev/sandbox/tcp/<host>:<port>")`:
1. parse (`host` may be `[v6]`);
2. match a TCP rule (exact host + port);
3. quota `requests += 1`;
4. resolve and check (§4);
5. `TcpStream::connect` to the vetted addresses in order, with `connect_timeout`.

Errors: no rule → `EACCES`, SSRF → `EACCES`, DNS → `ENOENT`, refused → `ECONNREFUSED`, timeout → `ETIMEDOUT`. Reads and writes are counted toward `max_total_bytes`, and the idle timeout is `request_timeout`. On close, or at run end, a `net.connect` event is written with bytes and duration. **When an operator proxy is configured, TCP connects directly** (Q1); the proxy setting applies to HTTP(S) only.

## 7. Audit (FR-N10)
`net.request` per hop records `proto="http"`, `scheme`, `host`, `ip` (from `Response::remote_addr`, or the IP that was refused), `port`, `method`, `path` (query redacted), `status`, `hop`, bytes out/in, `duration_ms`, `decision`, `reason`. A denial before any connection still produces an event with `decision: deny`. Header names, header values and bodies are **never** recorded.

## 8. Public API
```rust
pub struct BrokerConfig { pub proxy: Option<String>, pub no_proxy: Vec<String>, pub use_env_proxy: bool, pub extra_ca_pem: Option<Vec<u8>> }
pub struct Broker { … }                                   // Clone; validated at server start
impl Broker {
    pub fn new(cfg: BrokerConfig) -> Result<Broker, NetError>;   // parses proxy + CA bundle eagerly
    pub fn for_run(&self, policy: &Policy, ctx: RunCtx) -> Result<Option<RunNet>, NetError>; // None = no grants
}
pub struct RunCtx { pub run_id: RunId, pub policy: String, pub deadline: Instant, pub audit: Arc<dyn AuditSink> }
impl RunNet {
    pub fn register(&self, vfds: &mut VirtualFdTable);   // "http" if http rules, "tcp" if tcp rules
    pub fn finish(&self) -> NetReport;                   // { requests, bytes_in, bytes_out, limit_hit }
}
```

## 9. NFR (scaled)
- **Security:** `#![forbid(unsafe_code)]`. Every check is applied per hop and per connection. Panics in device futures are impossible by construction (no `unwrap`/`expect` outside tests); errors become frames or errnos.
- **Performance:** the client is built only when a policy grants egress. Target: ≤ 5 ms broker overhead per request (local server), and build time is measured in the tests. No-grant runs register nothing (zero cost).
- **Tests:**
  - **Unit + proptests** for `url`, `allow`, `ip` (every range in §4, mapped/6to4/NAT64/Teredo, decimal/octal/hex IPv4 via `url`) and `frame` (fuzz-ish roundtrip, truncated frames).
  - **Integration** drives `HttpDevice`/`TcpDevice` directly against local servers: an axum HTTP server, an HTTPS server with a **test CA generated at test time** (`rcgen`, dev-dependency), and a TCP echo server.
  - Positive cases use `allow_private_ips = true`. SSRF cases use the default and assert the server **never saw a connection**. Also covered: redirects (allowed → disallowed, https → http downgrade, loops > 5), quotas, timeouts (a slow server), header injection, TLS failure without the CA, and audit fields.
- **Infrastructure:** none new. CI runs it on the 4 runners. Dependencies: `reqwest` (already in tree), `url`, and `rcgen` (dev).
