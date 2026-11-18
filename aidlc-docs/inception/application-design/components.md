# Components — sandboxd

Cargo workspace (Q6=A). Each crate is a trust boundary with its own tests.

```
sandboxd/
├─ crates/
│  ├─ sandboxd-policy/     C1  Policy model, loaders, validation, tighten-only overrides
│  ├─ sandboxd-audit/      C2  Audit event schema, sinks (JSONL, OTLP), redaction
│  ├─ sandboxd-vfs/        C3  Run filesystem layout, FS interposer, virtual-fd table, artifacts
│  ├─ sandboxd-runtime/    C4  wasmtime engine, interpreters, limits, compile cache, run execution
│  ├─ sandboxd-server/     C5  RunService, HTTP API (axum), MCP server (rmcp), auth, admission control
│  └─ sandboxd/            C6  Binary: CLI (clap), config loading, wiring
├─ guest/                      Guest-side helpers embedded in the binary (sandbox_net.py, sandbox_net.js; Phase 4)
├─ assets/                     Pinned interpreter manifests (URL + SHA-256), fetched by build.rs
└─ tests/escape-suite/     C7  Adversarial release-blocking tests (U6)
```

## C1 — sandboxd-policy
**Responsibility:** Turns operator policy files (TOML **or** YAML) into one validated, immutable `Policy` (schema v1).
- Loads the policy directory at startup. Hot reload is out of scope.
- Rejects unknown keys and invalid units (`"2s"`, `"128mb"`).
- `Policy::tighten(&Overrides)` lets CLI flags lower limits. It can never raise a limit or add a mount or host.
- Has schema sections for phases 4–5 (`network`, `session`). They validate now but aren't enforced yet.
- Built-in `default` policy: no mounts except `/out`, no env vars, no network.

## C2 — sandboxd-audit
**Responsibility:** One typed `AuditEvent` enum and a fan-out `AuditSink`.
- `JsonlSink` writes to a file or stdout, with a non-blocking buffered writer and a bounded channel. If the channel is full, it increments a dropped-event counter, which is itself audited.
- `OtelSink` exports traces and metrics over OTLP. It's behind a cargo feature and off by default.
- `Redactor` masks token-, secret- and credential-like patterns. Code is logged as a SHA-256 unless `audit.log_code = true`.

## C3 — sandboxd-vfs
**Responsibility:** Everything the guest can see as a filesystem.
- `RunFs`: per-run temp root with `in/` (inputs, read-only), `out/` (rw, size-capped), and the policy mounts. Deleted on drop.
- **`FsInterposer`** (ADR-001): wraps the WASI p1 path and fd calls. It resolves every guest path against a virtual mount table, applies deny rules (traversal, symlink escape, mode), emits `fs.open` audit events, and delegates allowed calls to wasmtime-wasi.
- **`VirtualFdTable`** (ADR-002): a reserved fd range for host-implemented devices. The Phase 4 network devices plug in here.
- `ArtifactCollector`: after the run, walks `out/`, enforces count and byte caps, hashes files, and returns `Artifact`s.
- Python stdlib provisioning (Q3=A): extracts the embedded stdlib archive into `<cache>/stdlib/<sha>/` once, verifies it, and mounts it read-only at `/usr/local/lib/python3.13`.

## C4 — sandboxd-runtime
**Responsibility:** Runs the guest safely.
- `Engine`: a single shared wasmtime `Engine` with async support, fuel consumption, epoch interruption and pooling allocator off for now. An epoch ticker task advances the epoch every 10 ms.
- `Interpreter` implementations: `CPython` and `QuickJs`. Each knows its module bytes, argv/env layout and how to place user code in the guest filesystem.
- `ModuleCache`: on first use, AOT-compiles the embedded `.wasm` into `<cache>/modules/<wasm-sha>-<wasmtime-ver>-<target>.cwasm`. It verifies a hash before deserializing and keeps an `InstancePre` in memory.
- `Limits`: maps the policy to fuel, an epoch deadline, a `ResourceLimiterAsync` (memory and tables), and output caps (bounded stdout/stderr pipes).
- `NativeExtGuard`: scans the code before running it and inspects the `ModuleNotFoundError` after, returning `UNSUPPORTED_NATIVE_EXTENSION`.
- Trait seams with no implementation in this cycle: `InstancePool` (naive implementation shipped), `FallbackBackend`, `SessionStore`, `NetworkBroker`.

## C5 — sandboxd-server
**Responsibility:** The front door. Every interface goes through `RunService`.
- `RunService`: admission control (a semaphore plus a bounded queue with timeout, FR-2.5), policy lookup, a `RunRequest` → `Sandbox::execute` call, and event streaming.
- `http`: axum routes `/v1/runs` (JSON or SSE), `/v1/policies`, `/healthz`, `/metrics`, plus bearer auth middleware and body-size limits.
- `mcp`: an `rmcp` server with the tools `run_code` and `list_policies`. Transports are stdio and Streamable HTTP, the latter mounted on the same axum router at `/mcp`. Output streams as progress notifications.
- `auth`: constant-time token compare. Startup refuses to bind to a non-loopback address when no tokens are configured.

## C6 — sandboxd (binary)
`run`, `serve`, `mcp`, `policy check|list`, `cache warm|clear`, `version`. Loads `sandboxd.toml` config (policy dir, cache dir, listen address, tokens via env, audit sink, concurrency).

## C7 — escape-suite (tests)
Black-box tests against the binary and `RunService`. Each case states the attack, the expected denial and the expected audit event. The suite is release-blocking on all three operating systems.
