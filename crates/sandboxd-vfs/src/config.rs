//! Host locations (U3 design Q6).

use std::path::PathBuf;

/// Where sandboxd keeps its cache (stdlib, compiled modules) and per-run work dirs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfsConfig {
    /// Long-lived, hash-keyed artifacts (extracted stdlib; compiled modules in U4).
    pub cache_dir: PathBuf,
    /// Per-run temp roots and the shared empty catch-all root.
    pub work_dir: PathBuf,
}

impl VfsConfig {
    /// OS-conventional defaults: `%LOCALAPPDATA%\sandboxd`, `~/Library/Caches/sandboxd`,
    /// `$XDG_CACHE_HOME/sandboxd` or `~/.cache/sandboxd`; falls back to the temp dir.
    pub fn default_locations() -> Self {
        let base = os_cache_base()
            .unwrap_or_else(std::env::temp_dir)
            .join("sandboxd");
        Self {
            cache_dir: base.join("cache"),
            work_dir: base.join("work"),
        }
    }

    /// Both under one directory (tests, portable installs).
    pub fn under(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            cache_dir: root.join("cache"),
            work_dir: root.join("work"),
        }
    }
}

fn os_cache_base() -> Option<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(windows) {
        env("LOCALAPPDATA")
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|h| h.join("Library/Caches"))
    } else {
        env("XDG_CACHE_HOME").or_else(|| env("HOME").map(|h| h.join(".cache")))
    }
}
