# sandboxd threat model

> Skeleton created in U0. Each unit fills in its section during NFR Design. U6 finalizes the
> document and links every threat to an escape-suite test.

## Assets
- Host filesystem outside declared mounts; host environment variables and secrets
- Host network and internal services (Phase 4)
- Host availability: CPU, memory, disk, file descriptors
- Integrity and confidentiality of other concurrent runs
- Integrity of the audit log
- API tokens

## Adversaries
1. **Guest code**: fully attacker-controlled (model error or prompt injection). Primary adversary.
2. **API caller**: a holder of a valid token who tries to widen policy or exhaust resources.
3. **Network attacker**: someone reaching a non-loopback listener without a token.
4. **Supply chain**: tampered interpreter assets or crates.

## Trust boundaries
| Boundary | Enforced by |
|---|---|
| Guest ↔ host | wasmtime (memory safety, no ambient authority), WASI preopens via cap-std, FS interposer (ADR-001), fuel/epoch/memory limits |
| Caller ↔ server | Bearer auth, loopback-default bind, request size limits, named operator policies only (agents cannot widen) |
| Build ↔ upstream | SHA-256 pins (`assets/manifest.toml`, verified twice), cargo-deny/audit, `Cargo.lock` |

## Threat register
| ID | Threat | Mitigation | Test (U6) | Unit |
|---|---|---|---|---|
| T1 | Path traversal / absolute path / symlink escape | cap-std preopens + interposer canonicalization | escape::fs_* | U3 |
| T2 | Env var / secret read | Env built only from the policy allowlist | escape::env_* | U4 |
| T3 | CPU exhaustion (infinite loop) | Fuel + epoch deadline | escape::cpu_* | U4 |
| T4 | Memory bomb | ResourceLimiter cap | escape::mem_* | U4 |
| T5 | Output / artifact flood | Byte and count caps | escape::output_* | U3/U4 |
| T6 | Policy widening via API/CLI | Named policies, `tighten()` only | escape::policy_* | U1/U5 |
| T7 | Unauthenticated network access to API | Loopback default, refuse non-loopback without tokens | escape::auth_* | U5 |
| T8 | Tampered interpreter binary | SHA-256 pin at fetch and build; cache hash check before deserialize | unit tests | U0/U4 |
| T9 | Host panic from guest input crashing server | Per-run Store isolation, panic=unwind, catch at RunService | escape::crash_* | U4/U5 |
| T10 | Data exfiltration over network (Phase 4) | No sockets; brokered allowlist; raw TCP is opt-in and audited (content opaque) | Phase 4 | — |
