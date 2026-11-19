# Cycle 2 — Requirements Verification Questions

## Starting point
Cycle 1 (Phases 1–3) shipped: CLI, VFS + interposer, HTTP API, MCP, escape suite, and CI on 3 OSes. The pieces cycle 1 left for later:

| Item | What exists already | Cycle-1 reference |
|---|---|---|
| **Phase 4 network broker** | Policy schema `[network]` (http/tcp rules, quotas, `allow_private_ips`) validated but **refused** at load. `/dev/sandbox/*` virtual-device seam, tested end to end with an echo device. `NetworkBroker` trait. `net.request` audit event reserved. | FR-7, ADR-002, U1 Q3, U3 V9 |
| **OTLP exporter** | Config key `telemetry.otlp_endpoint` reserved. Prometheus `/metrics` works. | FR-6.2, U5 Q7, R6 |
| **Phase 5 performance** | `InstancePool` / `SessionStore` seams; `session` policy section refused; perf smoke in CI | FR-8 |

**Most important constraint for networking:** the broker is the place that stops data exfiltration (the original problem statement). Everything below is about making egress *possible, narrow and fully audited*.

Answer after each `[Answer]:` tag, or reply **"accept recommended defaults"**.

---

### Question 1 — Cycle 2 scope
A) **Phase 4 network broker + OTLP exporter.** Phase 5 (performance) next cycle **(Recommended: networking unlocks the most agent use cases, e.g. calling internal APIs, and OTLP is small)**
B) Phase 5 performance only (snapshots, pooling, sessions, Docker benchmarks)
C) Phase 4 + OTLP + Phase 5 (large cycle)
D) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 2 — How guest code makes HTTP requests
The guest has no sockets; requests go through `/dev/sandbox/http` (ADR-002).
A) **Transparent:** provide a small `sandbox_net` module *and* install it as the stdlib `urllib.request` handler (Python), plus a global `fetch()` for JavaScript. Ordinary `urllib.request.urlopen(...)` / `fetch(...)` code just works, subject to the allowlist **(Recommended; agents write standard code)**
B) Explicit only: code must call `sandbox_net.fetch(...)` / `import { fetch } from 'sandbox:net'`
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 3 — Raw TCP (designed in cycle 1, Q15)
A) **Implement it**, as designed: off by default, opt-in per `host:port` in the policy, audited by destination and byte counts (content is opaque) **(Recommended: completes the approved design; database clients need it)**
B) Defer raw TCP; HTTP(S) only this cycle
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 4 — TLS trust for outbound HTTPS (the host does TLS, never the guest)
A) **OS trust store** (Windows cert store / macOS keychain / Linux CA bundle) plus an optional extra CA file in config. Works behind corporate TLS-inspecting proxies **(Recommended for enterprise)**
B) Bundled Mozilla roots only (portable, but fails behind corporate interception)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 5 — Corporate outbound proxy
A) **Support an operator-configured HTTP(S) proxy** in `sandboxd.toml` (with a no-proxy list). Never taken from the guest; the host environment's `HTTPS_PROXY` is honoured only if the config says so **(Recommended)**
B) No proxy support (direct connections only)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 6 — Redirects
A) Follow **up to 5** redirects; **every hop is re-checked** against the allowlist (host, port, method, path prefix) and audited **(Recommended)**
B) Never follow; return the 3xx to the guest
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 7 — Private / internal address protection (SSRF, DNS rebinding)
A) Resolve DNS on the host. **Refuse** loopback, private (RFC 1918 / ULA), link-local and cloud-metadata (169.254.169.254, fd00:ec2::254) addresses unless the policy sets `allow_private_ips = true`. Check **every** resolved address and pin the connection to the checked IP **(Recommended)**
B) Allowlist by hostname only (no IP checks)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 8 — Credential injection (deferred in cycle 1)
Lets the operator attach e.g. `Authorization: Bearer …` to requests for a given host, so the guest code (and the model) never sees the secret.
A) **Defer.** Keep this cycle to allowlisting, quotas and audit **(Recommended; it needs a secrets design, sources and rotation)**
B) Include it: per-rule headers from env vars / files, never visible to the guest, redacted in audit
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 9 — OTLP exporter scope
A) **Metrics + traces** (one span per run with phase timings and outcome) over OTLP/HTTP, behind the `otel` cargo feature (off in default builds), endpoint from config **(Recommended)**
B) Metrics only
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 10 — Request/response bodies in the audit log
A) **Never log bodies.** Log method, scheme, host, resolved IP, port, path (query string redacted), status, byte counts, duration and decision **(Recommended: bodies are where secrets and personal data live)**
B) Log the first N bytes of bodies (redacted)
C) Other (please describe after [Answer]: tag below)

[Answer]: 
