//! Embedded guest interpreters, verified against `assets/manifest.toml` at build time.
//!
//! * [`PYTHON`] is the CPython WASI release zip (`python.wasm` + `lib/python3.x/**` + `LICENSE`).
//!   It is unpacked into the hash-keyed cache by `sandboxd-vfs` (ADR-004).
//! * [`JAVASCRIPT`] is the QuickJS-ng `qjs-wasi.wasm` module.
//! * [`PYTHON_SNAPSHOT`] / [`JAVASCRIPT_SNAPSHOT`] are sandboxd's own builds of the same versions as
//!   WASI reactors with `wizer-initialize` / `sandboxd-run` entry points (cycle 3, ADR-C3-1),
//!   pre-initialised into snapshots at start-up by `sandboxd-runtime`.

#![forbid(unsafe_code)]

/// One pinned, embedded asset.
#[derive(Debug, Clone, Copy)]
pub struct Asset {
    /// Manifest key (`python`, `javascript`, `python_snapshot`, `javascript_snapshot`).
    pub name: &'static str,
    /// Upstream version string.
    pub version: &'static str,
    /// Upstream download URL.
    pub url: &'static str,
    /// Lower-case hex SHA-256 of [`Asset::bytes`], checked at build time.
    pub sha256: &'static str,
    /// SPDX license identifier of the upstream artifact.
    pub license: &'static str,
    /// The raw file contents.
    pub bytes: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/assets.rs"));

/// All embedded assets, for `sandboxd version` and cache provisioning.
pub const ALL: [Asset; 4] = [PYTHON, JAVASCRIPT, PYTHON_SNAPSHOT, JAVASCRIPT_SNAPSHOT];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assets_are_non_empty_and_pinned() {
        for a in ALL {
            assert!(!a.bytes.is_empty(), "{} is empty", a.name);
            assert_eq!(a.sha256.len(), 64, "{} sha256 is not 64 hex chars", a.name);
        }
    }

    #[test]
    fn python_is_a_zip_and_quickjs_is_wasm() {
        assert_eq!(&PYTHON.bytes[..4], b"PK\x03\x04");
        assert_eq!(&JAVASCRIPT.bytes[..4], b"\0asm");
    }
}
