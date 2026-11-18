# sandboxd

**Run untrusted, agent-generated code in a WebAssembly sandbox: fast, self-hosted, deny-by-default.**

Agents write code and run it. That code is untrusted by definition. `sandboxd` is a single Rust
binary that runs Python (CPython WASI) and JavaScript (QuickJS) inside wasmtime. It grants nothing
the operator's policy doesn't allow, enforces CPU, wall-clock, memory and output limits, and audits
every capability use. Agents reach it over a CLI, an HTTP API, or as an MCP `run_code` tool.

> Most agent code doesn't need a VM. Stop paying for one.

**Status:** early development (U0 bootstrap). See `aidlc-docs/` for requirements and design.

## Scope
- ✅ Logic, string processing, JSON, light data work in pure Python + stdlib, and JavaScript
- ❌ NumPy/pandas and other native extensions. These return a clear `UNSUPPORTED_NATIVE_EXTENSION`; a container/microVM fallback is a planned extension point.
- ❌ Full Linux environments (`apt install`). Use a VM for those.

## Build
See [docs/DEV_SETUP.md](docs/DEV_SETUP.md). In short:
```bash
python scripts/fetch-assets.py
cargo run -p sandboxd -- version
```

## License
Apache-2.0. Embedded interpreters keep their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
