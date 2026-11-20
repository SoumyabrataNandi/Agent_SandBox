//! Audit events and sinks for sandboxd (component C2, unit U2).
//!
//! * [`AuditEvent`] / [`EventKind`]: the versioned JSON Lines schema.
//! * [`AuditSink`]: non-blocking destination with a health flag. The server fails closed
//!   (rejects new runs) while the audit log can't be written.
//! * [`JsonlSink`]: bounded queue + writer thread, batch flush, drop counting.
//! * [`Redactor`]: secret masking applied to every free-text field before it is written.
//!
//! Metrics and OTLP export live in `sandboxd-server` (U5) per the U2 design Q4.

#![forbid(unsafe_code)]

mod event;
mod redact;
mod sink;

pub use event::{
    AssetPin, AuditEvent, Decision, EventKind, FileDigest, FsOp, LimitKind, MAX_CODE_BYTES,
    MAX_FIELD_BYTES, Outcome, RunId, SCHEMA_VERSION, rfc3339_millis, sha256_hex, token_principal,
};
pub use redact::{PatternError, Redactor};
#[cfg(any(test, feature = "testing"))]
pub use sink::MemorySink;
pub use sink::{AuditSink, FanoutSink, JsonlOptions, JsonlSink, NullSink};
