# Architecture Decision Records — sandboxd

## ADR-001 — Filesystem interposer over wasmtime-wasi p1 (Q1=B)
**Status:** Accepted, subject to a time-boxed spike in U3. **Spike 2026-11-18: GO** with the *trait-wrapper* variant (see `construction/u3-vfs/adr001-spike-report.md`), awaiting user confirmation.
**Context:** FR-6.1 needs a per-open `fs.open` allow/deny audit. wasmtime-wasi p1 preopens map directly to host dirs and have no hook. A naive `func_wrap` override is reported to break the runtime.
**Decision:** Build the linker in two layers:
1. Register the real wasmtime-wasi p1 implementation (`add_to_linker_async`) into an *inner* linker and capture the `Func`s for the path- and fd-taking imports.
2. Define the *outer* `wasi_snapshot_preview1` imports ourselves. Each wrapper reads arguments from guest memory, consults `FsInterposer` and the `VirtualFdTable`, emits audit events, and then either returns an errno (`EACCES`/`ENOENT`/`ENOTCAPABLE`) or delegates through `inner.call_async(&mut caller, …)`. Imports that aren't wrapped are passed through unchanged.

**Wrapped calls:** `path_open`, `path_filestat_get`, `path_filestat_set_times`, `path_create_directory`, `path_remove_directory`, `path_unlink_file`, `path_rename`, `path_link`, `path_symlink`, `path_readlink`, `fd_close`, and the `fd_read`/`fd_write`/`fd_seek`/`fd_fdstat_get` calls when the fd is virtual. `environ_get`/`environ_sizes_get` aren't wrapped, because the env is built from the policy.
**Defence in depth:** the interposer is an *additional* layer. wasmtime-wasi's own preopen sandboxing (`cap-std`) remains the primary enforcement, so an interposer bug can't widen access beyond the preopens.
**Fallback:** if the spike shows delegation is unworkable, use Q1=A (mount-level audit plus an `/out` diff) and record FR-6.1 as a known gap.
**Spike exit criteria:** Python `open()`, `os.listdir()` and `pathlib` all work through the wrappers. A denied path produces an audit event. Overhead is under 5% on a stdlib import benchmark.

## ADR-002 — Network bridge via virtual device files (Q2=A)
**Status:** Accepted for design. Implementation in Phase 4.
**Decision:** Virtual fds come from a reserved range (≥ `0x4000_0000`) and are managed by the `VirtualFdTable` in the outer linker layer (ADR-001). They never reach wasmtime-wasi.
- `/dev/sandbox/http`: open → write a JSON request → the first read triggers `NetworkBroker::http`, which checks the allowlist, resolves DNS on the host, checks the IP is not private or loopback unless allowed, enforces quotas, and logs the request → read returns the JSON response (body base64 or streamed).
- `/dev/sandbox/tcp/<host>:<port>`: open → `NetworkBroker::tcp_connect` (allowlist, off by default) → read and write map to a host socket, with byte quotas, and an audit event records destination and byte counts.
- Guest helpers `sandbox_net.py` (provides `fetch()` plus a small `urllib`-like API) and `sandbox_net.js` are embedded and mounted read-only. They're the only supported way to reach the network.

**Consequence:** this works with the unmodified prebuilt CPython and QuickJS. Stock `requests`/`socket` won't work, and that's documented.

## ADR-003 — Async wasmtime on tokio (Q4=A)
**Decision:** `Config::async_support(true)`, `consume_fuel(true)`, `epoch_interruption(true)`, with a 10 ms ticker. All host functions are async.
**Consequence:** many concurrent runs per core, which sets up Phase 5 pooling. The cost is some async complexity in the interposer.

## ADR-004 — Interpreter sourcing (requirements §7 item 2, Q3=A, Q5 from requirements)
**Decision:**
- CPython **3.15.2** `wasm32-wasip1` from the prebuilt cpython-wasi-build release zip (`python.wasm` + `lib/python3.15`), pinned by SHA-256 in `assets/manifest.toml`.
- QuickJS from the quickjs-ng release asset `qjs-wasi.wasm`, also pinned by SHA-256.
- *(Amended at U0 gate)* `scripts/fetch-assets.py` downloads and verifies the assets. `build.rs` makes no network calls: it re-verifies and embeds them as-is, with no zstd (the zip is already compressed). Offline builds use a `SANDBOXD_ASSETS_DIR` override. The stdlib is extracted from the embedded zip into a hash-verified cache and mounted read-only.

## ADR-005 — MCP via `rmcp` (Q5=A), workspace layout (Q6=A)
**Decision:** Use the official Rust MCP SDK for stdio and Streamable HTTP. Use the multi-crate workspace described in `components.md`.
