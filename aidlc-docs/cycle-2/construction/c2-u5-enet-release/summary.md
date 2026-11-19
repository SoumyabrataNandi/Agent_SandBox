# C2-U5 E-NET + Release — Summary

**Requirements:** NFR-N1 (E-NET, release-blocking), NFR-N2 (local servers only), AC 1–10; threat model T13–T18, R8.

## E-NET escape-suite family (`tests/escape-suite/tests/net.rs`, 11 cases)
A separate hostile world: a broker trusting a runtime-generated test CA, five policies (`netpos`, `netdef` = default SSRF protection, `netproxy`, `netquota`, `nonet`), and **ten in-process servers**. Six of them are **forbidden** destinations that serve the canary and count every connection: a forbidden HTTP server, `/secret` outside the allowed prefix, the loopback targets of `netdef` (HTTP + TCP), a downgrade target, and a forbidden TCP server.

**Invariants checked after every case:**
- no `ESCAPED` line;
- no canary in output, artifacts or audit;
- every forbidden hit counter at **0**;
- a secret query value never in the audit;
- the service still healthy.

**Each refusal must carry the expected broker code**, so a case can't pass by failing for an unrelated reason.

| Case | Covers (NFR-N1 list) | Guest |
|---|---|---|
| E-NET-1 | Non-allowlisted host, port, method, path, scheme; `file:`; userinfo; via `fetch`, urllib, http.client; deny audit events | Py + JS |
| E-NET-2 | URL path traversal: 11 encodings (`..`, `%2e%2e`, `%2F`, `%5c`, `\`, `//`, case, double-encoding) + raw http.client request line | Py |
| E-NET-3 | IP-literal SSRF: loopback, decimal, hex, octal, IPv4-mapped IPv6, `[::1]`, `0.0.0.0`; **metadata** (incl. decimal); **DNS → private** (`localhost`); TCP loopback / DNS → SSRF code | Py + JS |
| E-NET-4 | Redirects to another port/host/path, metadata, `file:`, loops; **https → http downgrade** (even with an http rule) | Py |
| E-NET-5 | CRLF in header names/values, NUL, method injection; Host spoofing, `Content-Length` / `Transfer-Encoding` smuggling, Connection-listed and `Proxy-*` headers (the server sees broker values) | Py + JS |
| E-NET-6 | Quotas (`max_requests`, `max_response_bytes`) → `limit` / `network`; **slowloris** (dripping body) and hanging server → `TIMEOUT` in < 3s | Py |
| E-NET-7 | TCP to an unlisted port/host; device-path tricks (`..`, garbage, unknown family) | Py |
| E-NET-8 | **Guest proxy use:** `HTTP(S)_PROXY` in the policy env, `ProxyHandler`, `set_tunnel`, absolute-form requests | Py |
| E-NET-9 | Hand-written device frames (forbidden URL, unknown JSON field, CRLF, 4 GiB header length, garbage, body-length lie, read before write); **monkey-patching the guest shim changes nothing** | Py |
| E-NET-10 | No grants: every API and the raw devices fail (`NETWORK_DISABLED` / ENOENT) | Py + JS |
| E-NET-11 | 12 concurrent hostile runs across three policies: per-run grants, clients and quotas stay isolated | Py |

The guest output of each case is printed to the test log for review. Example (E-NET-3):
`blocked loopback PermissionError SSRF`, `blocked decimal … SSRF`, `blocked metadata-decimal … SSRF`, `blocked dns-localhost … SSRF`.

The existing `escape-suite` CI job and the release gate (`release.yml` runs the suite against every release build) pick E-NET up automatically, on Linux x64/arm64, macOS and Windows.

## Threat model (`THREAT_MODEL.md`)
- New trust boundary **Guest ↔ network**.
- **T13–T18** with mitigations and test mappings (SSRF incl. encodings and metadata, DNS rebinding/pinning, redirects, smuggling/injection/frames, exfiltration and slow servers, guest proxies and cross-run state). T10 and T12 were extended.
- R5 reworded. **R6 closed** (OTLP shipped in C2-U4).
- New **R8** (re-resolution behind an operator proxy), **R9** (exfiltration to allowed hosts by design), and **R10** (the Python bootstrap heuristic affects error clarity only).

## Docs
- New **`docs/NETWORK.md`**: policy rules and defaults, limits, private/metadata handling, server `[network]` settings, **proxy guidance** (deny private ranges at the proxy; `no_proxy` for internal targets), Python/JS usage, the error-code table, audit fields, and the security model. Defaults and messages were checked against the code.
- README: network row, capabilities, E-NET in the security section. The release archives now include `NETWORK.md`. `docs/MCP.md` gained the `[telemetry]` example (C2-U4).

## Cycle 2 acceptance criteria
| AC | Evidence |
|---|---|
| 1 Allowed GET via urllib + fetch, audited with redacted query | runtime `python_urllib_get_post…`, `javascript_fetch_…`; broker `allowed roundtrip` (`?…[2 params]`); E-NET invariant (query value never audited) |
| 2 Non-allowlisted host/port/method/path → clear error + deny audit, server untouched | E-NET-1 (codes + `net_denials ≥ 9` + forbidden counters 0); runtime denial test |
| 3 127.0.0.1, 169.254.169.254, [::ffff:127.0.0.1], 2130706433, name → 127.0.0.1 refused | E-NET-3 (all of them, Py + JS); broker SSRF test |
| 4 Redirect to a disallowed host refused at the hop, both hops audited | E-NET-4; broker redirect test (hop 0 allow, hop 1 deny) |
| 5 Quotas → `limits_hit` contains `network` | E-NET-6; runtime `quota_exhaustion…`; broker quota tests (incl. `max_total_bytes`) |
| 6 TCP echo via `connect` + `create_connection`, others refused, audited with bytes | runtime `python_socket_create_connection_and_connect`; E-NET-7; broker TCP test |
| 7 HTTPS with `extra_ca_file` ok, without it fails validation | runtime/broker HTTPS tests; broker "without the CA → TLS" |
| 8 `[network] enabled = false` → granting policy refused at load | C2-U1 policy/kill-switch tests |
| 9 `otel`: span + metrics to a stub; default build has no opentelemetry | C2-U4 `otlp_export…` test; CI `otel` job's `cargo tree` check |
| 10 Escape suite incl. E-NET on all runners; cargo-deny + cargo-audit pass | Local: all pass, cargo-deny ok. The CI run on the 4 runners happens after push. |

## Results
All run locally on Windows, using the CI flags (`--locked`, `--test-threads=4`):
- **Escape suite:** 17 cycle-1 cases + **11 E-NET** cases pass.
- **Workspace tests:** all pass.
- **Clippy `-D warnings`:** clean for the default features and with `--features otel`.
- **fmt:** clean.
- **cargo-deny:** advisories, bans, licenses and sources ok.
- **New test-only dependencies:** rcgen, rustls, tokio-rustls, serde and sandboxd-net for the escape suite. All were already in the lockfile.

Remaining for AC 10: confirm the GitHub Actions run, all 4 OS runners plus the new `otel` job and the Node 24 actions, after this push.
