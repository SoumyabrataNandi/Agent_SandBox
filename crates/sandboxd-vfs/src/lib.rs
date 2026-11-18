//! Guest filesystem for sandboxd (component C3, unit U3).
//!
//! * [`RunFs`]: per-run layout (catch-all `/`, stdlib, `/in`, `/out`, policy mounts), input
//!   materialization, artifact collection, cleanup on drop.
//! * [`Interposer`]: wraps wasmtime-wasi's `WasiP1Ctx` (ADR-001, trait-wrapper variant) to
//!   resolve, deny and audit path operations and enforce the live `/out` quota.
//! * [`VirtualFdTable`]: `/dev/sandbox` device seam for the Phase 4 network broker (ADR-002).
//! * [`ensure_stdlib`]: hash-keyed, atomically extracted CPython stdlib cache (ADR-004).
//!
//! Install the interposer with
//! `wasmtime_wasi::p1::wasi_snapshot_preview1::add_to_linker(&mut linker, |s| &mut s.interposer)`.
//!
//! Design: `aidlc-docs/construction/u3-vfs/design.md`.

#![forbid(unsafe_code)]

mod config;
mod error;
mod interposer;
mod paths;
mod runfs;
mod stdlib;
mod vfd;

pub use config::VfsConfig;
pub use error::VfsError;
pub use interposer::{FIRST_PREOPEN_FD, Interposer, InterposerReport, MountInfo, MountKind};
pub use paths::{resolve, validate_input_name};
pub use runfs::{Artifact, Collected, InputFile, RunFs};
pub use stdlib::{STDLIB_GUEST, ensure_stdlib};
pub use vfd::{DeviceFactory, DeviceFuture, VFD_BASE, VirtualDevice, VirtualFdTable};
