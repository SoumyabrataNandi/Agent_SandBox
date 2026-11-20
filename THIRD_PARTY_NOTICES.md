# Third-party notices

`sandboxd` binaries embed the following guest interpreters, pinned in `assets/manifest.toml`.

| Component | Version | License | Source |
|---|---|---|---|
| CPython (WASI build, incl. standard library) | 3.15.2 | PSF-2.0 (Python Software Foundation License) | https://github.com/brettcannon/cpython-wasi-build/releases/tag/v3.15.2 |
| QuickJS-ng (`qjs-wasi.wasm`) | 0.18.0 | MIT | https://github.com/quickjs-ng/quickjs/releases/tag/v0.18.0 |
| CPython reactor for snapshots (`sandboxd-python.wasm`, built in CI from `interpreters/`) | 3.15.2 | PSF-2.0 | https://www.python.org/ftp/python/3.15.2/Python-3.15.2.tgz |
| QuickJS-ng reactor for snapshots (`sandboxd-qjs.wasm`, built in CI from `interpreters/`) | 0.18.0 | MIT | https://github.com/quickjs-ng/quickjs/archive/refs/tags/v0.18.0.tar.gz |
| wasi-libc (from wasi-sdk 33, linked into both reactors) | wasi-sdk 33 | Apache-2.0 WITH LLVM-exception, Apache-2.0, MIT (per file; see its `LICENSE*` files) | https://github.com/WebAssembly/wasi-sdk/releases/tag/wasi-sdk-33 |

The reactors are built from the sources and toolchain pinned by SHA-256 in `interpreters/sources.toml`
and published as GitHub releases (`interp-<hash>`) with build-provenance attestations; the binary
embeds them as pinned in `assets/manifest.toml`. At start-up they are pre-initialised with
`wasmtime-wizer` into snapshots.

The full CPython license text ships inside the embedded archive (`LICENSE`). Release packaging (U6)
copies both upstream license texts into the distribution next to the binary.

Rust crate dependencies and their licenses are listed by `cargo deny list` and are restricted by `deny.toml`.
