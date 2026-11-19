# C2-U1 Policy, Config & Audit Extensions — Design + Code Summary

Combined gate (light unit, per unit-of-work.md). Implements FR-N11, N3.1, N6 (schema), and the audit parts of FR-N7 and FR-N10.

## Policy (`sandboxd-policy`)
| Change | Detail |
|---|---|
| `Scheme` enum | `https` (default) / `http` on every HTTP rule. `port` defaults to 443 / 80 by scheme. Any other value is an error naming `network.http[i].scheme`. |
| Timeouts | `network.connect_timeout` (default 5 s, range 100 ms..=60 s) and `network.request_timeout` (default 30 s, range 100 ms..=10 min) |
| **`max_requests` default 0 → 100** | Defect avoided: 0 was harmless while grants were refused, but would have silently blocked every request once grants were allowed |
| `ensure_supported` | Accepts network grants. Sessions (Phase 5) are still refused. |
| Kill switch | `LoadOptions.network_enabled` (default `true`). `PolicyDir::load` refuses granting policies when it's `false`: *"network access is disabled on this server ([network] enabled = false)"* |
| Reserved path | `/usr/local/lib/sandboxd` (`HELPER_GUEST_PATH`) for the guest helpers (ADR-C2-3) |
| `explain` / warnings | Rules shown as `https://host:port/prefix [METHODS]` / `tcp://host:port` plus a quota line. Warnings for `allow_private_ips`, unencrypted `http` rules, and TCP content not being inspected. |

## Audit (`sandboxd-audit`), additive (NFR-N6)
- `LimitKind::Network`
- `net.request` gains `scheme`, `hop`, `duration_ms`, `reason`. There are no body or header-value fields by design.
- New `net.connect` event (TCP sessions): host, ip, port, bytes in and out, duration, decision, reason.
- The redactor covers the new free-text fields.

## Server config (`sandboxd-server`)
```toml
[network]
enabled = true                       # kill switch (FR-N11.2)
proxy = "http://proxy.corp:8080"     # operator only; http:// or https:// (FR-N9)
no_proxy = ["internal.corp"]
use_env_proxy = false                # honour HTTPS_PROXY only if true
extra_ca_file = "ca.pem"             # added to the OS trust store (FR-N8)
```
The CLI passes `network.enabled` into `LoadOptions`.

## Tests
- **Policy:** the golden TOML/YAML pair gains a `http` rule and timeouts, and **parity still holds** (cycle-1 AC 9). New tests cover grants being supported and explained, field validation (scheme, timeout ranges, scheme-in-host), and the kill switch (AC 8). Updated: the full golden now expects support; the `/usr/local/lib/sandboxd` mount is rejected; the unknown-key example changed (`scheme` is now a valid key).
- **Audit:** every event kind, including `net.connect`, serializes with the right name.
- **Server:** `[network]` parsing, defaults, and refusal of a non-HTTP proxy scheme.
