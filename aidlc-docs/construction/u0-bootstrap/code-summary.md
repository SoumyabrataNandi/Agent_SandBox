# U0 Bootstrap — Code Summary & Build/Test Results

**Date:** 2026-11-18 · **Host:** Windows 11, Rust 1.100.0 (D:\dev), portable MSVC 14.52 (D:\dev\msvc)

## Files
| Path | Purpose |
|---|---|
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.gitignore` | Workspace (edition 2024, resolver 3), pinned toolchain, shared lints (`unsafe_code = deny`, `clippy::unwrap_used`, `dbg_macro`), release profile |
| `crates/sandboxd-assets/` | `build.rs` verifies SHA-256 → generates `include_bytes!` consts; `PYTHON`, `JAVASCRIPT`, `ALL` |
| `crates/sandboxd-{policy,audit,vfs,runtime,server}/` | Documented skeletons. Inter-crate deps are added in their own units |
| `crates/sandboxd/` | Binary; `sandboxd version` |
| `assets/manifest.toml` | CPython 3.15.2 WASI zip + QuickJS-ng 0.18.0 `qjs-wasi.wasm`, pinned |
| `scripts/fetch-assets.py` | Download → verify → atomic move; `--check` mode |
| `scripts/dev-env.ps1` | Loads the no-admin Windows dev env (Rust on D:, portable MSVC) |
| `.github/workflows/ci.yml` | ubuntu x64/arm64, macOS, Windows: fmt, clippy -D warnings, test, smoke; cargo-deny + cargo-audit |
| `deny.toml` | License allowlist, advisories, sources |
| `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, `THREAT_MODEL.md`, `README.md`, `docs/DEV_SETUP.md` | Legal, threat-model skeleton (T1–T10), docs |

## Results (local, Windows)
| Check | Result |
|---|---|
| `fetch-assets.py --check` | ✅ both assets verified |
| `cargo fmt --check` | ✅ |
| `cargo clippy --workspace --all-targets --locked -D warnings` | ✅ |
| `cargo test --workspace --locked` | ✅ 2 passed (assets: pinned + magic bytes `PK\x03\x04` / `\0asm`) |
| `sandboxd version` | ✅ prints both pins |
| Release build | ✅ `sandboxd.exe` 16.5 MB (interpreters embedded) |
| Tamper test (1 byte appended to qjs-wasi.wasm) | ✅ build refused: "SHA-256 mismatch … Refusing to embed" |

## Not yet verified
- CI on Linux/macOS: the repo is not on GitHub yet.
- `cargo deny` / `cargo audit` locally (not installed; they run in CI).
