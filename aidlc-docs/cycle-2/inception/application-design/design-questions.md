# Cycle 2 Application Design — Questions

Design: `application-design.md`. Answer after each `[Answer]:` tag, or reply **"accept recommended defaults"**.

### Question 1 — HTTP client stack
A) **reqwest 0.13** (already in our dependency tree via rmcp; OS trust store via rustls-platform-verifier) with a **custom pinning resolver**, redirects disabled and handled by the broker, and one client per run **(Recommended)**
B) hyper + hyper-util + tokio-rustls directly (more control, considerably more code)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 2 — Device wire protocol
A) **Length-prefixed frames:** a JSON header plus a raw body, no base64 **(Recommended; ~33% less data and no copies)**
B) A single JSON document with base64 bodies (simpler to debug)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 3 — Tracebacks with the Python bootstrap
The bootstrap runs `/code/main.py` through `runpy`, which adds bootstrap frames to tracebacks.
A) **Trim** bootstrap/runpy frames with a `sys.excepthook`, so tracebacks look exactly as in cycle 1 (`File "/code/main.py", line N`) **(Recommended; agents read tracebacks)**
B) Leave the extra frames
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 4 — Proxy configured + SSRF
With an operator proxy, the proxy resolves the target itself, so we can't pin the IP.
A) **Allow it**: the broker pre-checks the target's resolved IPs; DNS rebinding through the proxy is recorded as residual risk **R8**, and the docs advise configuring the proxy to deny private ranges **(Recommended; corporate networks need proxies)**
B) When a proxy is configured, require `allow_private_ips = false` *and* refuse any rule whose host resolves to a private range at policy load
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 5 — Connection reuse
A) **Per-run** client and connection pool; nothing is shared between runs **(Recommended: isolation)**
B) A shared pool across runs (faster repeated requests, but runs share TLS sessions and connections)
C) Other (please describe after [Answer]: tag below)

[Answer]: 
