# sandboxd threat model

Finalized in U6 (2026-11-18). Every threat maps to tests in `tests/escape-suite` (release-blocking on
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
| T10 | Process creation, sockets, threads, FFI | Not available under WASI p1; no host functions provide them | E-PROC |
| T11 | Request-input abuse (names, count, base64, size) | Validation before disk; **1000-file cap (added in U6)**; `input_bytes`; body limit | E-INPUT |
| T12 | Secrets ending up in the audit log | Redactor (9 built-ins + operator patterns); code hash by default | E-AUDIT; audit redaction tests |

## Residual risks (accepted / owned)
| ID | Risk | Owner / plan |
|---|---|---|
| R1 | A bug in wasmtime, wasmtime-wasi or cap-std breaks isolation | Pin and track advisories (cargo-audit in CI); upgrade promptly; the interposer is a second layer for paths |
| R2 | Spectre-class / timing side channels between concurrent runs | Out of scope for this tier; run separate deployments per tenant if needed |
| R3 | A local attacker who can write the cache dir and recompute the sidecar hash could plant a malicious `.cwasm` | The cache dir is user-only (0700 on Unix); operators must not share it. Future: sign cache entries with a per-install key |
| R4 | Read-write operator mounts let guests modify host data (by design) and are not size-limited | Flagged by `policy check` warnings; operator responsibility |
| R5 | Network egress (Phase 4): raw TCP content is opaque to the broker | Raw TCP is off by default and per-destination opt-in; only destination and bytes are audited |
| R6 | OTLP export not implemented (only Prometheus `/metrics`) | Next cycle |
| R7 | Symlink cases E-FS-2 (host-created links) only run on Unix CI (Windows needs Developer Mode to create symlinks) | Covered on the Linux and macOS runners |
