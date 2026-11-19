# sandboxd threat model

Finalized in U6 (2026-11-18); extended in cycle 2 (C2-U5, 2026-11-19) for network egress (T13–T18,
R8) and OTLP export. Every threat maps to tests in `tests/escape-suite` (release-blocking on
Linux x64/arm64, macOS and Windows) or to unit/integration tests in the named crate.

## Assets
- Host filesystem outside declared mounts; host environment variables and secrets
- Host network and internal services
- Host availability: CPU, memory, disk, file descriptors, the server process itself
- Confidentiality and integrity of concurrent runs
- Integrity of the audit log; API tokens
- Integrity of the interpreter binaries and the compiled-module cache

## Adversaries
1. **Guest code:** fully attacker-controlled, from a model error or prompt injection. This is the primary adversary.
2. **API caller:** holds a valid token and tries to widen policy, exhaust resources, or inject via inputs.
3. **Network attacker:** reaches a listener without a token.
4. **Supply chain:** tampered interpreter assets, crates, or release binaries.
5. **Local user with write access to the cache directory** (see residual risk R3).

## Trust boundaries
| Boundary | Enforcement |
|---|---|
| Guest ↔ host | wasmtime (memory safety, no ambient authority); WASI preopens via cap-std; the interposer (ADR-001: lexical mount-escape checks, catch-all `/`, live `/out` quota, audit); fuel, epoch and outer timeout; linear-memory limiter; 1 MiB wasm stack inside a 4 MiB fiber; capped output streams |
| Caller ↔ server | Bearer tokens (SHA-256 at rest, constant-time compare); loopback-default bind and refusal on public bind without tokens; body limit; strict request schema; named operator policies, tighten-only overrides; input name, count and size validation before disk |
| Guest ↔ network | No sockets in WASI p1. Egress exists only as the host broker's virtual devices (`/dev/sandbox/http`, `/dev/sandbox/tcp/<host>:<port>`), registered per run and only for what the policy grants. The broker checks the allowlist (scheme, host, port, method, normalized path prefix) **before** DNS. Every resolved address is checked against private/loopback/link-local/metadata ranges and the connection is **pinned** to the vetted address. Redirects are followed by the broker, re-checked per hop. The broker owns framing and hop-by-hop headers. Quotas and timeouts apply per run; there is a per-run client and pool. Every request and connection is audited. Guest-side shims make no security decisions. |
| Build ↔ upstream | SHA-256 pins verified at fetch and at build; `Cargo.lock`; cargo-deny/cargo-audit; module-cache sidecar hash; release `SHA256SUMS` + build-provenance attestation |

## Threat register
| ID | Threat | Mitigation | Tests |
|---|---|---|---|
| T1 | Path traversal, absolute/Windows paths, symlinks, hard links, renames out of mounts | cap-std preopens; interposer lexical resolution + catch-all `/`; hard links into `/out` refused; symlinks never collected | E-FS-1, E-FS-1/js, E-FS-2, E-FS-3; `sandboxd-vfs` CPython tests |
| T2 | Reading host env vars and secrets | Guest env is exactly the policy's literal vars | E-ENV |
| T3 | CPU exhaustion (loops, catastrophic regex, huge ranges) | Fuel, epoch deadline, outer timeout covering host calls | E-CPU; runtime AC 2 tests |
| T4 | Memory exhaustion; **host stack overflow from deep recursion** | `ResourceLimiter`; wasm stack 1 MiB with 3 MiB host headroom (**bug found and fixed by the suite**) | E-MEM, E-CRASH; `deep_recursion_is_contained_not_a_host_crash` |
| T5 | Output, artifact and disk floods | Capped streams; live `/out` byte and file quota; collection caps | E-OUT; vfs quota tests |
| T6 | Policy widening, unknown or path-like policy names, request-supplied mounts | Named policies; `tighten()`; no mount field in the API; `policy.denied` audit | E-POL, E-INPUT; policy proptests |
| T7 | Unauthenticated access; token leakage | Bearer auth on `/v1`, `/mcp`, `/metrics`; query-string tokens ignored; tokens never logged | E-AUTH; server AC 8 tests |
| T8 | Tampered interpreter or module cache | Asset pins (fetch and build); `.cwasm` sidecar hash, recompile on mismatch | `sandboxd-assets` tamper check; runtime cache-tamper test |
| T9 | A guest crash taking down the server or other runs | Per-run `Store`; trap classification; spawned task + panic isolation; run dirs removed | E-CRASH (30 concurrent hostile runs) |
| T10 | Process creation, sockets, threads, FFI | Not available under WASI p1; no host functions provide them; network only through the broker (T13–T18) | E-PROC, E-NET-10 |
| T11 | Request-input abuse (names, count, base64, size) | Validation before disk; **1000-file cap (added in U6)**; `input_bytes`; body limit | E-INPUT |
| T12 | Secrets ending up in the audit log | Redactor (9 built-ins + operator patterns); code hash by default; URL query values never logged (`?…[N params]`); OTLP spans carry no code, output, paths or principals | E-AUDIT; audit redaction tests; every E-NET case checks a secret query value never reaches the audit; `sandboxd-server` OTLP test |
| T13 | SSRF to internal services or cloud metadata, including encoded IP literals (decimal, octal, hex, IPv4-mapped IPv6), `localhost`-style names and 6to4/NAT64/Teredo forms | Allowlist first (an IP literal only matches an IP rule). WHATWG canonicalization. Every resolved address is classified, and **any** blocked address rejects the name. Private ranges are blocked unless `allow_private_ips`. Metadata endpoints (169.254.169.254, 100.100.100.200, 168.63.129.16, fd00:ec2::254) also need an **explicit IP rule**. DNS is only queried for allowlisted names. | E-NET-3 (+ JS); `sandboxd-net` ip/target unit + proptests, broker SSRF tests |
| T14 | DNS rebinding (vetted at check time, different at connect time) | One resolution per connection; the HTTP client and TCP connect use **only** the vetted addresses (pinning resolver) | `sandboxd-net` pinning tests; E-NET-3 `dns-localhost` |
| T15 | Redirect to a disallowed target (other host/port/path, metadata, `file:`, https→http downgrade) | Redirects followed by the broker (client redirects off). Every hop is re-checked against allowlist + SSRF; https→http refused even when an http rule exists. Cross-origin redirects drop credentials. At most 5 hops. | E-NET-4; broker redirect tests |
| T16 | Request smuggling, header/CRLF injection, Host spoofing, method injection, malformed device frames | Strict header names/values (no CR/LF/NUL); the broker sets `Host`, `Content-Length`, `Transfer-Encoding`, `Connection` and drops hop-by-hop, Connection-listed and `Proxy-*` headers. Methods validated. Strict length-prefixed frames with `deny_unknown_fields` and size limits. | E-NET-5 (+ JS), E-NET-9 |
| T17 | Exfiltration to **allowed** hosts; slow/hanging servers holding resources | By design the operator trusts allowed hosts; bounded by `max_requests`, request/response/total byte quotas, connect/request timeouts within the run's wall clock; fully audited (host, IP, port, method, path, status, bytes) | E-NET-6; broker quota/timeout tests |
| T18 | Guest use of proxies or the operator's proxy; cross-run state leakage through connection pools | Guest proxy use (`*_PROXY` env, `ProxyHandler`, `set_tunnel`, absolute-form requests) is refused, and a proxy host would also need its own allowlist rule. The operator proxy is configured only in `sandboxd.toml`; system proxies are never used implicitly. A per-run client and pool (no shared cookies/connections). | E-NET-8, E-NET-11 |

## Residual risks (accepted / owned)
| ID | Risk | Owner / plan |
|---|---|---|
| R1 | A bug in wasmtime, wasmtime-wasi or cap-std breaks isolation | Pin and track advisories (cargo-audit in CI); upgrade promptly; the interposer is a second layer for paths |
| R2 | Spectre-class / timing side channels between concurrent runs | Out of scope for this tier; run separate deployments per tenant if needed |
| R3 | A local attacker who can write the cache dir and recompute the sidecar hash could plant a malicious `.cwasm` | The cache dir is user-only (0700 on Unix); operators must not share it. Future: sign cache entries with a per-install key |
| R4 | Read-write operator mounts let guests modify host data (by design) and are not size-limited | Flagged by `policy check` warnings; operator responsibility |
| R5 | Raw TCP content is opaque to the broker | Raw TCP is off by default and per-destination opt-in (`tcp` rules); destination, peer IP and bytes are audited |
| R6 | ~~OTLP export not implemented~~ **Closed in cycle 2 (C2-U4):** optional `otel` feature; spans carry no sensitive data | — |
| R7 | Symlink cases E-FS-2 (host-created links) only run on Unix CI (Windows needs Developer Mode to create symlinks) | Covered on the Linux and macOS runners |
| R8 | With an operator proxy configured, the **proxy** resolves names, so sandboxd cannot pin addresses (DNS rebinding / private targets *behind the proxy*) | The broker still enforces the allowlist and IP-literal checks before sending to the proxy. Operators must configure the proxy to deny private and metadata ranges (docs/NETWORK.md) |
| R9 | Exfiltration to allowed hosts (T17) is possible by design | Allow only hosts you trust with the run's data; keep quotas tight; review `net.request` audit events |
| R10 | Python programs that hide their network imports (e.g. `getattr(__builtins__, …)`) under a policy **without** grants get WASI's generic socket error instead of the "not allowed by policy" message (bootstrap heuristic, NFR-N3) | Error clarity only: without grants there are no network devices |
