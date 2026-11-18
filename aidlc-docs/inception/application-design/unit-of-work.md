# Units of Work — sandboxd

**Approved changes applied:** the VFS unit is now built before the runtime. Units are renumbered to match the build order.

| Unit | Crate(s) | Components | Requirements covered | Key deliverables | Size |
|---|---|---|---|---|---|
| **U0 Bootstrap** | workspace root, `assets/`, CI skeleton | — | NFR-1, NFR-4 (tooling), NFR-7, NFR-8 | Rust toolchain installed on Windows; Cargo workspace; `assets/manifest.toml` (pinned CPython + QuickJS + stdlib SHA-256); `build.rs` that fetches, verifies and embeds them; GitHub Actions 3-OS matrix (fmt, clippy, test); `cargo deny` + `cargo audit`; LICENSE (Apache-2.0) + third-party notices; `THREAT_MODEL.md` skeleton | S |
| **U1 Policy** | `sandboxd-policy` | C1 | FR-4, FR-2 (limit model), FR-7/8 (schema only) | Schema v1, TOML + YAML loaders, strict validation, unit parsing, `tighten()`, built-in `default`, `explain()`, TOML↔YAML golden parity tests | M |
| **U2 Audit** | `sandboxd-audit` | C2 | FR-6 | `AuditEvent`, `JsonlSink` (bounded, non-blocking), `Redactor`, optional `OtelSink` (feature) | S–M |
| **U3 VFS** | `sandboxd-vfs` | C3 | FR-3, FR-6.1 (fs events), ADR-001/002 | **ADR-001 spike first (2 days, go/no-go)**; `RunFs`; mount table and path canonicalization; two-layer linker interposer; `VirtualFdTable` (empty device set); `ArtifactCollector`; stdlib cache provisioning | **L, highest risk** |
| **U4 Runtime** | `sandboxd-runtime` | C4 | FR-1, FR-2, FR-8 seams | Async engine + epoch ticker; `ModuleCache` (AOT, hash-verified); `CPython` + `QuickJs` interpreters; fuel/epoch/memory/output limits; trap classification; `NativeExtGuard`; `Sandbox::execute`; naive `InstancePool`; `FallbackBackend`/`SessionStore`/`NetworkBroker` traits | L |
| **U5 Server + CLI** | `sandboxd-server`, `sandboxd` | C5, C6 | FR-5, FR-2.5, NFR-6 | `RunService` (admission, streaming); axum HTTP + SSE; `rmcp` MCP over stdio and Streamable HTTP; bearer auth + bind-safety check; CLI commands; config file; `/metrics` | L |
| **U6 Escape suite + release** | `tests/escape-suite`, CI | C7 | NFR-4, NFR-1, AC 1–10 | Adversarial cases (traversal, symlink, env, loops, memory bombs, recursion, output floods, artifact bombs, socket/subprocess, policy widening, auth bypass); release-blocking CI gate on 3 OSes; performance smoke check against NFR-3; release workflow that builds the binaries; threat model finalized | M |

Each unit goes through Functional Design → NFR Requirements → NFR Design → Infrastructure Design (light) → Code Generation. Depth is scaled per unit: U0 and U2 use minimal design stages, and U3 and U4 get the full treatment.
