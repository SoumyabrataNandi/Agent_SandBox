//! Execution engine for sandboxd (component C4, unit U4).
//!
//! [`Sandbox`] owns one wasmtime `Engine` (fuel + epoch interruption), the prepared CPython and
//! QuickJS interpreters (loaded from a verified on-disk cache) and an epoch ticker.
//! [`Sandbox::execute`] runs one [`RunRequest`] under a [`sandboxd_policy::Policy`] and always
//! returns a [`RunResult`], streaming [`RunEvent`]s if asked.
//!
//! The only `unsafe` in the workspace outside dependencies is `Module::deserialize_file` in
//! `cache.rs`, guarded by a SHA-256 sidecar check (U4 design Q1).
//!
//! Design: `aidlc-docs/construction/u4-runtime/design.md`.

#![deny(unsafe_code)]

mod cache;
mod error;
mod helpers;
mod native;
mod sandbox;
mod seams;
mod snapshot;
mod stream;
mod types;

pub use error::RuntimeError;
pub use helpers::{ensure_helpers, helpers_sha256};
pub use native::{NATIVE_PACKAGES, detect as detect_native_extension};
pub use sandbox::{
    EPOCH_TICK, PoolStatus, PoolingMode, RuntimeConfig, Sandbox, SnapshotMode, WarmupReport,
};
pub use seams::{FallbackBackend, SeamFuture, SessionStore};
pub use types::{Language, RunError, RunEvent, RunRequest, RunResult, SessionId, Timings};

pub use sandboxd_audit::{LimitKind, Outcome, RunId};
pub use sandboxd_vfs::{Artifact, InputFile};
