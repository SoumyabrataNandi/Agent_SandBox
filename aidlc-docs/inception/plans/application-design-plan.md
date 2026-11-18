# Application Design Plan — sandboxd

## Plan (checklist)
- [x] Resolve the design decisions below (Questions 1–6)
- [x] `application-design/components.md`: components, responsibilities, interfaces
- [x] `application-design/component-methods.md`: key traits and method signatures (`Interpreter`, `Sandbox`, `PolicyStore`, `Vfs`, `FsInterposer`, `AuditSink`, `InstancePool`, `NetworkBroker`, `FallbackBackend`, `SessionStore`)
- [x] `application-design/services.md`: orchestration (RunService), the request lifecycle, and concurrency/queueing
- [x] `application-design/component-dependency.md`: dependency graph, data flow and the crate map
- [x] Record the two open items from requirements §7 as Architecture Decision Records (ADRs)

## Facts gathered (to inform the answers)
- **QuickJS:** quickjs-ng GitHub releases ship WASI build artifacts (`qjs-wasi.wasm`) and a separate reactor variant. We can pin a release asset by SHA-256, with no custom build needed. That resolves requirements §7 item 2, unless Question 2 picks custom builds.
- **CPython:** 3.13 is the first release with WASI as a tier-2 platform (`wasm32-wasip1`). Prebuilt builds come from brettcannon/cpython-wasi-build. The interpreter needs its **stdlib directory** present in the guest filesystem at runtime.
- **wasmtime-wasi (p1):** preopens map to *real host directories*. There's no built-in hook to observe or deny an individual `path_open`. Interposing means wrapping the generated `WasiSnapshotPreview1` implementation, and community reports say naive `func_wrap` shadowing breaks things. This matters for FR-6.1 (`fs.open` audit events) and for the network bridge.

---

## Questions

### Question 1 — Filesystem interception (drives FR-3 + FR-6.1 `fs.open` audit)
A) **No interception.** Use per-run temp dirs + wasmtime-wasi preopens. Audit at mount level only (what was granted, and what appeared in `/out`). Opens the guest attempts are not logged. Simplest and most robust, but FR-6.1 is only partly met.
B) **Interposer layer.** Wrap wasmtime-wasi's preview1 implementation, intercept the path-taking calls (`path_open`, `path_filestat_get`, `path_unlink_file`, etc.) to audit and deny, then delegate to the real implementation. Starts with a time-boxed spike in U4; if the spike fails, fall back to A and record a gap ADR **(Recommended)**
C) **Our own preview1 filesystem** (fully in-memory VFS, own implementation of the ~45 p1 calls). Maximum control, but the largest security-critical surface to own.
D) Other (please describe after [Answer]: tag below)

[Answer]: B

### Question 2 — Guest↔host bridge for the network broker (Phase 4; the seam is designed now)
A) **Virtual device files** through the Q1 interposer. The guest opens `/dev/sandbox/http`, writes a JSON request and reads the response, or opens `/dev/sandbox/tcp/<host>:<port>` as a byte stream. We inject a small pure-Python `sandbox_net` module and a JS `sandbox_net.js` helper. This works with the **unmodified prebuilt interpreters** **(Recommended; depends on Q1=B or C)**
B) **Custom interpreter builds** with a host import module (`sandbox.http_request`, etc.). The cleanest ABI, but it means building CPython and QuickJS from source in CI on all three OSes.
C) **WASI 0.2 / `wasi:http` components.** Standards-aligned, but the CPython component story isn't mature, and raw TCP would need `wasi:sockets`.
D) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 3 — Python stdlib packaging (affects NFR-2 single binary)
A) Embed the stdlib as a compressed archive in the binary. On first use, extract it to a hash-verified cache dir and mount it read-only at `/usr/local/lib/python3.13` **(Recommended; works the same on all OSes)**
B) Embed it as `python313.zip` and use zipimport directly (smaller, but slower first imports, and it depends on the build's zlib support)
C) Ship the stdlib as a separate file next to the binary
D) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 4 — Execution model
A) **Async wasmtime on tokio.** Epoch interruption yields back to the scheduler, so many concurrent runs can share a small thread pool. This sets up Phase 5 ("thousands of sandboxes") **(Recommended)**
B) **Sync wasmtime** on `spawn_blocking` threads, one OS thread per active run. Simpler, but caps concurrency at around the thread count.
C) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 5 — MCP implementation
A) Use the official Rust MCP SDK (`rmcp`) for stdio and Streamable HTTP **(Recommended)**
B) Hand-write the JSON-RPC/MCP layer
C) Other (please describe after [Answer]: tag below)

[Answer]: A

### Question 6 — Code organization
A) A Cargo workspace with one crate per unit (`sandboxd-policy`, `-audit`, `-runtime`, `-vfs`, `-server`, plus the `sandboxd` bin and the `escape-suite` test crate) **(Recommended; clear trust boundaries, units can be tested independently)**
B) A single crate with modules
C) Other (please describe after [Answer]: tag below)

[Answer]: A
