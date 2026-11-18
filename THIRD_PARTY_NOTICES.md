# Third-party notices

`sandboxd` binaries embed the following guest interpreters, pinned in `assets/manifest.toml`.

| Component | Version | License | Source |
|---|---|---|---|
| CPython (WASI build, incl. standard library) | 3.15.2 | PSF-2.0 (Python Software Foundation License) | https://github.com/brettcannon/cpython-wasi-build/releases/tag/v3.15.2 |
| QuickJS-ng (`qjs-wasi.wasm`) | 0.18.0 | MIT | https://github.com/quickjs-ng/quickjs/releases/tag/v0.18.0 |

The full CPython license text ships inside the embedded archive (`LICENSE`). Release packaging (U6)
copies both upstream license texts into the distribution next to the binary.

Rust crate dependencies and their licenses are listed by `cargo deny list` and are restricted by `deny.toml`.
