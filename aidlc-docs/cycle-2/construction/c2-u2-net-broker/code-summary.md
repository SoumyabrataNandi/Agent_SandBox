# C2-U2 `sandboxd-net` Broker — Code Summary & Test Results

Design answers Q1–Q7: all recommended (direct TCP even when a proxy is configured; all response headers except hop-by-hop; deny encoded separators; browser-compatible redirects with cross-origin credential drop; 64 KiB / 100 / 8 KiB frame limits; refuse https→http; classify 6to4/NAT64 by embedded IPv4, block Teredo).

| File | Content |
|---|---|
| `src/ip.rs` | `classify` / `permitted`: v4 special ranges, v6 ranges, embedded IPv4 (mapped, compatible, 6to4, NAT64), Teredo blocked, 4 cloud-metadata endpoints that need `allow_private_ips` **and** an explicit IP rule |
| `src/target.rs` | WHATWG URL canonicalization (`2130706433`, `0x7f.1` and `0177.0.0.1` all → `127.0.0.1`; `%2e%2e` → removed). Rejects userinfo, backslashes and `%2F`/`%5C`. Segment-aware prefixes. Allowlist matching with precise reasons. TCP spec parsing. |
| `src/resolve.rs` | `resolve_checked` (any blocked address rejects the name) and `PinningResolver` for reqwest (vetted addresses only; the proxy host is exempt) |
| `src/frame.rs` | Length-prefixed codec with strict JSON (`deny_unknown_fields`), size limits, partial-frame handling |
| `src/http.rs` | `HttpDevice` state machine. The exchange: allowlist → IP-literal / proxy pre-check → quota → send (timeout = min(request_timeout, guest timeout, run deadline)) → capped body → per-hop audit → broker-managed redirects (re-checked, downgrade refused, 303 → GET, cross-origin credential drop, ≤ 5). Header policy (CR/LF/NUL rejected; Host, framing, `Proxy-*` and Connection-listed headers dropped). Error classification (SSRF/DNS/TLS/TIMEOUT/CONNECT). |
| `src/tcp.rs` | `TcpDevice`: the factory checks the rule synchronously; `opened()` does quota + SSRF + connect (so errors surface at `open`); read/write with idle timeout and byte quotas; `net.connect` audit on close or drop |
| `src/lib.rs` | `Broker` (proxy/CA validated at start; `ring` provider; never uses system proxies implicitly), `Broker::for_run` (None when there are no grants; a per-run reqwest client with **retries off**, redirects off, referer off, pinning resolver), `RunNet::register` / `finish`, quotas, audit helpers |
| `sandboxd-vfs` (ext) | `VirtualDevice::opened()` (async, default no-op); `VirtualFdTable::open` is now async, so a TCP connect failure surfaces as the `open` errno |

## Tests: 26 (15 unit/proptest + 11 integration), all passing
The integration tests run against **in-process** servers: an axum HTTP server, an HTTPS server with a **test CA generated at runtime** (rcgen), and a TCP echo server.

| Test | Proves |
|---|---|
| allowed roundtrip | POST with body + header reaches the server. The audit has the real peer IP, `?…[2 params]`, byte counts, and **no** query values or body. |
| non-allowlisted | 9 variants (port, method, path, `..`, `%2F`, scheme, name-vs-IP rule, userinfo, `file://`) → `DENIED`; **servers saw 0 requests** |
| SSRF (default policy) | `127.0.0.1`, `2130706433`, `0x7f.1`, `localhost` (a **name** resolving to loopback), `[::ffff:127.0.0.1]` → `SSRF`; **server saw 0 requests** |
| redirects | allowed → disallowed port: hop 0 allowed, hop 1 denied, target never contacted. A loop → `TOO_MANY_REDIRECTS`. 303 → GET without body; 307 keeps POST and body; cross-origin drops `Authorization`/`Cookie`, same-origin keeps them. |
| header policy | CRLF injection and invalid names → `PROTOCOL`; Host spoofing, `Proxy-Authorization`, Connection-listed and `Transfer-Encoding` dropped |
| quotas / timeouts | `max_requests`, `max_response_bytes`, `max_total_bytes` across requests, `max_request_bytes` at the frame, `request_timeout` (< 1.5 s for a 0.5 s limit), the run deadline |
| TLS | Without the CA → `TLS`. With `extra_ca_pem` → 200 (OS store **plus** extra CA). https → http redirect refused even with an http rule. Bad PEM rejected at broker start. |
| TCP | Echo via the device with `net.connect` bytes 4/4; unlisted port refused by the factory; loopback refused under the default policy with the server untouched |
| frame errors | Read before a complete frame → `EINVAL`; garbage → `PROTOCOL` frame |
| zero-cost + perf | No grants → no broker. **Per-run client build 0.3–0.7 ms; per request 0.36–0.54 ms** (debug, local), well under the 5 ms target |

## Issues found and fixed during implementation
1. **reqwest retries** are on by default in 0.13. They're now disabled, because a silent retry would be an extra, un-audited request.
2. **Feature unification:** reqwest's `system-proxy` could be enabled by another crate. The broker therefore always calls `.no_proxy()` or `.proxy(operator)`, so a system proxy is never used implicitly; this is a code-level guarantee.
3. **TLS errors were mis-classified as CONNECT:** hyper-rustls wraps `rustls::Error` in `io::Error`, whose `source()` skips the wrapped error. The classifier now also looks inside `io::Error::get_ref()`.
4. **Crypto provider:** `ring` instead of aws-lc-rs, because aws-lc-sys can need NASM/CMake on Windows and `ring` builds with MSVC/ARM/macOS out of the box. The OS trust store still comes from rustls-platform-verifier (ADR-C2-1 amendment).
5. **Licenses:** ISC (`ring`, `rustls-webpki`, `untrusted`) and CDLA-Permissive-2.0 (`webpki-root-certs`) re-added to `deny.toml`, with a comment. cargo-deny: all ok.
6. **Test expectations:** IPv4-mapped IPv6 displays as `::ffff:127.0.0.1`. `https:///nohost` is valid per WHATWG (host `nohost`, still subject to the allowlist); this is documented by a test.
7. **Regression caught by the cycle-1 server tests:** enabling reqwest's `rustls-no-provider` (feature-unified) also gave TLS to rmcp's own reqwest client, which then needs a process-wide rustls crypto provider and panicked without one (AC 7 over HTTP). Fix: `sandboxd_net::ensure_crypto_provider()` (idempotent) is called by `Broker::new` and the server tests, and will be called in the binary's `main` in C2-U3.

**Workspace:** 133 tests pass (107 earlier + 26 broker). Clippy `-D warnings` and fmt are clean. cargo-deny: advisories, bans, licenses and sources ok.
