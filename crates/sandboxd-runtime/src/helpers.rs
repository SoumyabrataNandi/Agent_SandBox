//! Embedded guest helpers (C2-U3): the Python/JS bootstraps and `sandbox_net`.
//!
//! They are compiled into the binary, extracted once to `cache_dir/helpers/<sha256>/` (temp dir +
//! atomic rename + marker, like the stdlib, ADR-004) and mounted read-only at
//! [`sandboxd_policy::HELPER_GUEST_PATH`]. Any change to a helper changes the hash, so a stale copy
//! is never used; a corrupted copy is detected and rebuilt. The Python helpers are then compiled
//! to `__pycache__` inside the sandbox (see `cache::ensure_helper_bytecode`) so that no run
//! compiles the bootstrap from source (NFR-N3).

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

use crate::error::RuntimeError;

const MARKER: &str = ".complete";

/// The helper files: (file name, contents).
pub(crate) const FILES: &[(&str, &str)] = &[
    (
        "sandboxd_boot.py",
        include_str!("../guest/sandboxd_boot.py"),
    ),
    ("sandbox_net.py", include_str!("../guest/sandbox_net.py")),
    ("boot.js", include_str!("../guest/boot.js")),
    (
        "sandboxd_session.py",
        include_str!("../guest/sandboxd_session.py"),
    ),
    ("session.mjs", include_str!("../guest/session.mjs")),
    ("fetch.js", include_str!("../guest/fetch.js")),
];

/// `python -c` launcher: imports the (precompiled) bootstrap from the helper mount and runs it.
/// The helper dir is first on `sys.path` only for that import, so it doesn't scan the stdlib's
/// zip/dir finders (a cost a plain `print(1)` never paid); `main()` appends it for `sandbox_net`.
pub(crate) const PYTHON_LAUNCHER: &str = "import sys;sys.path.insert(0,'/usr/local/lib/sandboxd');import sandboxd_boot;del sys.path[0];sandboxd_boot.main()";
/// `python -c` launcher for a session on the upstream interpreter (C3-U4): the session loop,
/// with the same lazy network patcher as the bootstrap.
pub(crate) const PYTHON_SESSION_LAUNCHER: &str = "import sys;sys.path.append('/usr/local/lib/sandboxd');import sandboxd_session;sandboxd_session.main()";
/// Guest path of the JavaScript session loop (C3-U4).
pub(crate) const JS_SESSION: &str = "/usr/local/lib/sandboxd/session.mjs";

/// Whether a Python run needs the bootstrap (NFR-N3 vs. N2.3).
///
/// The bootstrap's first `compile()` makes CPython build its AST types (~22 M fuel), a cost a
/// plain script launch never pays. So it is used only when the policy grants network access or
/// the program text mentions a networking module, which is when its clear "not allowed by policy"
/// errors matter. Everything else launches exactly as in cycle 1. This is not a security
/// boundary: without grants there are no network devices whichever launch line is used.
pub(crate) fn python_needs_bootstrap(policy_grants_network: bool, code: &str) -> bool {
    const HINTS: &[&str] = &[
        "socket",
        "urllib",
        "http",
        "sandbox_net",
        "asyncio",
        "smtplib",
        "ftplib",
        "imaplib",
        "poplib",
        "nntplib",
        "xmlrpc",
        "__import__",
        "importlib",
    ];
    policy_grants_network || HINTS.iter().any(|h| code.contains(h))
}

/// Guest path of the JavaScript bootstrap (a `qjs -I` include).
pub(crate) const JS_BOOT: &str = "/usr/local/lib/sandboxd/boot.js";

/// SHA-256 over every helper's name and contents (the cache key).
pub fn helpers_sha256() -> String {
    let mut h = Sha256::new();
    for (name, body) in FILES {
        h.update(name.as_bytes());
        h.update([0]);
        h.update((body.len() as u64).to_le_bytes());
        h.update(body.as_bytes());
    }
    hex::encode(h.finalize())
}

fn io(what: &str, path: &Path, e: std::io::Error) -> RuntimeError {
    RuntimeError::Io(format!("{what} {}: {e}", path.display()))
}

fn intact(dir: &Path, sha: &str) -> bool {
    std::fs::read_to_string(dir.join(MARKER)).is_ok_and(|m| m == sha)
        && FILES
            .iter()
            .all(|(name, body)| std::fs::read(dir.join(name)).is_ok_and(|b| b == body.as_bytes()))
}

/// Host directory holding the helpers, extracting (or repairing) it if needed.
pub fn ensure_helpers(cache_dir: &Path) -> Result<PathBuf, RuntimeError> {
    let sha = helpers_sha256();
    let root = cache_dir.join("helpers");
    let final_dir = root.join(&sha);
    if intact(&final_dir, &sha) {
        return Ok(final_dir);
    }
    std::fs::create_dir_all(&root).map_err(|e| io("create helper cache", &root, e))?;
    if final_dir.exists() {
        std::fs::remove_dir_all(&final_dir)
            .map_err(|e| io("remove stale helpers", &final_dir, e))?;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let tmp = root.join(format!(".tmp-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|e| io("create temp helper dir", &tmp, e))?;
    for (name, body) in FILES {
        let p = tmp.join(name);
        std::fs::write(&p, body).map_err(|e| io("write helper", &p, e))?;
    }
    std::fs::write(tmp.join(MARKER), &sha).map_err(|e| io("write helper marker", &tmp, e))?;
    match std::fs::rename(&tmp, &final_dir) {
        Ok(()) => Ok(final_dir),
        Err(_) if intact(&final_dir, &sha) => {
            // Another process won the race; use theirs.
            let _ = std::fs::remove_dir_all(&tmp);
            Ok(final_dir)
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(io("install helpers", &final_dir, e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_paths_are_under_the_reserved_helper_path() {
        let (dir, file) = JS_BOOT.rsplit_once('/').expect("path");
        assert_eq!(dir, sandboxd_policy::HELPER_GUEST_PATH);
        assert!(FILES.iter().any(|(n, _)| *n == file), "{file} is embedded");
        assert!(PYTHON_LAUNCHER.contains(&format!("'{}'", sandboxd_policy::HELPER_GUEST_PATH)));
        assert!(FILES.iter().any(|(n, _)| *n == "sandboxd_boot.py"));
        assert!(FILES.iter().any(|(n, _)| *n == "fetch.js"));
        let (dir, file) = JS_SESSION.rsplit_once('/').expect("path");
        assert_eq!(dir, sandboxd_policy::HELPER_GUEST_PATH);
        assert!(FILES.iter().any(|(n, _)| *n == file));
        assert!(FILES.iter().any(|(n, _)| *n == "sandboxd_session.py"));
        assert!(
            PYTHON_SESSION_LAUNCHER.contains(&format!("'{}'", sandboxd_policy::HELPER_GUEST_PATH))
        );
    }

    #[test]
    fn extract_reuse_and_repair() {
        let dir =
            std::env::temp_dir().join(format!("sandboxd-helpers-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = ensure_helpers(&dir).expect("extract");
        assert!(a.ends_with(helpers_sha256()));
        for (name, body) in FILES {
            assert_eq!(std::fs::read_to_string(a.join(name)).expect("read"), *body);
        }
        // Reuse.
        assert_eq!(ensure_helpers(&dir).expect("cached"), a);
        // Tampered/corrupted file Ã¢â€ â€™ rebuilt.
        std::fs::write(a.join("sandbox_net.py"), "raise SystemExit").expect("tamper");
        let b = ensure_helpers(&dir).expect("repair");
        assert_eq!(
            std::fs::read_to_string(b.join("sandbox_net.py")).expect("read"),
            FILES[1].1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn python_bootstrap_only_when_networking_is_possible() {
        assert!(!python_needs_bootstrap(
            false,
            "print(1)
import json, re"
        ));
        assert!(python_needs_bootstrap(true, "print(1)"));
        for code in [
            "import urllib.request",
            "from http import client",
            "import socket",
            "import sandbox_net",
            "m = __import__('sock' + 'et')",
            "import importlib; importlib.import_module('x')",
            "print('see https://example.com')",
        ] {
            assert!(python_needs_bootstrap(false, code), "{code}");
        }
    }

    #[test]
    fn helper_sources_use_lf_line_endings() {
        // .gitattributes pins eol=lf, so the cache key is the same on every OS.
        for (name, body) in FILES {
            assert!(!body.contains('\r'), "{name} has CR characters");
        }
    }
}
