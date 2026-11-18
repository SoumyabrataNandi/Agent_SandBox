# U0 Bootstrap — Code Generation Plan

Design stages for U0 are minimal by plan: no business logic, infrastructure only.

## Decisions taken in this unit (flagged at the U0 gate)
1. **CPython 3.15.2 instead of 3.13.** As of 2026-11-18, the latest stable CPython with an official WASI build (brettcannon/cpython-wasi-build) is 3.15.2 (`wasi_sdk-33`, `wasm32-wasip1`). The 3.14.x releases ship no assets, and 3.16 is alpha. This affects FR-1.2 and ADR-004.
2. **Assets are fetched by a script, not by `build.rs`.** `scripts/fetch-assets.py` downloads into `assets/vendor/` and verifies SHA-256 against `assets/manifest.toml`. `build.rs` makes no network calls: it only verifies and embeds. This keeps builds offline and reproducible. It refines ADR-004.
3. **No zstd.** The CPython zip is already deflate-compressed and QuickJS is only 1.5 MB, so both are embedded as-is. One fewer C dependency.
4. A small `sandboxd-assets` crate owns the embedded bytes and their pins. The VFS and runtime crates depend on it.

## Steps
- [x] Workspace `Cargo.toml`, `rust-toolchain.toml` (pinned 1.100.0), `.gitignore`
- [x] Crate skeletons: policy, audit, vfs, runtime, server, assets, sandboxd bin
- [x] `assets/manifest.toml` with pinned CPython 3.15.2 + QuickJS-ng v0.18.0
- [x] `scripts/fetch-assets.py` (stdlib only, verify-then-move)
- [x] `sandboxd-assets/build.rs` (hash verify + `include_bytes!` codegen)
- [x] `sandboxd version` prints the version and asset pins
- [x] CI: 3-OS matrix (fmt, clippy -D warnings, test), cargo-deny, cargo-audit
- [x] `deny.toml`, LICENSE (Apache-2.0), NOTICE, THIRD_PARTY_NOTICES.md, THREAT_MODEL.md skeleton, README, docs/DEV_SETUP.md
- [x] Local build verification — all green (see code-summary.md)
