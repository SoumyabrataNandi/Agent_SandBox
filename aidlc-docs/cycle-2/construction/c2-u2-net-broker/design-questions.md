# C2-U2 Broker — Design Questions

Answer after each `[Answer]:` tag, or reply **"accept recommended defaults"**.

### Question 1 — Raw TCP when an operator HTTP proxy is configured
A) **Connect directly**; the proxy applies to HTTP(S) only. Operators who must force everything through a proxy simply don't grant TCP rules **(Recommended; simple and predictable)**
B) Tunnel TCP through the proxy with HTTP `CONNECT`
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 2 — Response headers returned to the guest
A) **All headers** except hop-by-hop ones (`Connection`, `Transfer-Encoding`, `Keep-Alive`, …) **(Recommended; code often needs `Content-Type`, `Location`, rate-limit headers, `Set-Cookie`)**
B) A strict allowlist of response headers
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 3 — Encoded path separators (`%2F`, `%5C`) and backslashes in URLs
A) **Deny.** They can bypass `path_prefix` rules on servers that decode them **(Recommended)**
B) Allow them as opaque characters
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 4 — Redirect method handling
A) **Browser-compatible:** 301/302/303 → `GET` without a body; 307/308 keep the method and body. `Authorization`/`Cookie` are dropped on cross-origin hops **(Recommended)**
B) Always keep the method and body
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 5 — Request frame limits
A) Header JSON ≤ 64 KiB, ≤ 100 headers, each value ≤ 8 KiB; body ≤ the policy's `max_request_bytes` **(Recommended)**
B) Other limits (please describe after [Answer]: tag below)

[Answer]: 

### Question 6 — Redirect from https to http
A) **Refuse the downgrade** even if an `http` rule would match the target **(Recommended)**
B) Allow it when an `http` rule matches
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 7 — IPv6 transition addresses
A) Classify **6to4 (`2002::/16`) and NAT64 (`64:ff9b::/96`) by their embedded IPv4**; **block Teredo (`2001::/32`) entirely**; mapped/compatible forms as their IPv4 **(Recommended)**
B) Treat all of them as public unless they literally match a private range
C) Other (please describe after [Answer]: tag below)

[Answer]: 
