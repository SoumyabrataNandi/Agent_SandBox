//! Operator policy model for sandboxd (component C1, unit U1).
//!
//! Policies are written in TOML or YAML, parsed into one serde shape (so the two formats are
//! equivalent by construction), and validated into an immutable [`Policy`]. Agents select a
//! policy by name only. The only runtime adjustment is [`Policy::tighten`], which can lower
//! limits but never raise them.
//!
//! Design: `aidlc-docs/construction/u1-policy/design.md`.

#![forbid(unsafe_code)]

mod dir;
mod error;
mod model;
mod raw;
mod units;

pub use dir::{PolicyDir, PolicySummary};
pub use error::{PolicyError, PolicyErrors};
pub use model::{
    AuditPolicy, CODE_GUEST_PATH, DEVICE_GUEST_PATH, Filesystem, Format, HttpRule, Limits,
    LoadOptions, MAX_POLICY_FILE_BYTES, Mount, MountMode, NetworkPolicy, Overrides, Policy,
    PolicySpec, RESERVED_ENV, SCHEMA_VERSION, STDLIB_GUEST_PATH, SessionPolicy, TcpRule,
};
pub use units::{ByteSize, fmt_duration, fmt_fuel, parse_bytes, parse_duration, parse_fuel};
