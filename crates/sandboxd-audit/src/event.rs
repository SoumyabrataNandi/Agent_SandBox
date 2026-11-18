//! Audit event model (design: aidlc-docs/construction/u2-audit/design.md §1).

use std::{fmt, time::SystemTime};

use serde::{Serialize, Serializer};

use crate::redact::Redactor;

/// Schema version written as `"v"` on every line.
pub const SCHEMA_VERSION: u32 = 1;

/// Time-ordered run identifier (UUID v7), so audit lines sort naturally by run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct RunId(uuid::Uuid);

impl RunId {
    /// A fresh, time-ordered id.
    pub fn new() -> Self {
        Self(uuid::Uuid::now_v7())
    }
    /// Wrap an existing UUID (tests, replay).
    pub fn from_uuid(u: uuid::Uuid) -> Self {
        Self(u)
    }
    /// The underlying UUID.
    pub fn as_uuid(&self) -> uuid::Uuid {
        self.0
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Which limit a run hit. Shared with the runtime and the API result type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    /// Fuel (instruction budget) exhausted.
    Cpu,
    /// Wall-clock deadline passed.
    WallClock,
    /// Linear-memory growth denied.
    Memory,
    /// Stdout byte cap reached.
    Stdout,
    /// Stderr byte cap reached.
    Stderr,
    /// Artifact count or total bytes exceeded.
    Artifacts,
    /// Request input files exceeded the policy's `input_bytes`.
    Inputs,
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Guest exited with status 0.
    Ok,
    /// Guest exited with a non-zero status.
    Exit,
    /// Terminated because a limit was hit.
    Limit,
    /// Guest trapped (crash inside the sandbox).
    Trap,
    /// Host-side error before or during the run.
    Error,
}

/// Filesystem operation observed by the interposer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FsOp {
    Open,
    Stat,
    SetTimes,
    Mkdir,
    Rmdir,
    Unlink,
    Rename,
    Link,
    Symlink,
    Readlink,
    Readdir,
}

/// Allow / deny decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
}

/// Name, size and digest of a file crossing the sandbox boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileDigest {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

/// One pinned asset, reported at server start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssetPin {
    pub name: String,
    pub version: String,
    pub sha256: String,
}

/// Event-specific payload. Serialized with `"event": "<name>"` and its fields flattened.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event")]
pub enum EventKind {
    #[serde(rename = "run.start")]
    RunStart {
        lang: String,
        code_sha256: String,
        code_bytes: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
        inputs: Vec<FileDigest>,
    },
    #[serde(rename = "run.end")]
    RunEnd {
        outcome: Outcome,
        exit_code: Option<i32>,
        duration_ms: u64,
        fuel_used: Option<u64>,
        peak_memory: Option<u64>,
        limits_hit: Vec<LimitKind>,
        stdout_bytes: u64,
        stderr_bytes: u64,
        artifacts: Vec<FileDigest>,
    },
    #[serde(rename = "fs.access")]
    FsAccess {
        op: FsOp,
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        mode: Option<String>,
        decision: Decision,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    #[serde(rename = "env.read")]
    EnvRead { key: String, decision: Decision },
    #[serde(rename = "limit.hit")]
    LimitHit {
        kind: LimitKind,
        limit: u64,
        observed: u64,
    },
    #[serde(rename = "policy.denied")]
    PolicyDenied {
        what: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        requested: Option<String>,
    },
    /// Reserved for the Phase 4 network broker.
    #[serde(rename = "net.request")]
    NetRequest {
        proto: String,
        host: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        ip: Option<String>,
        port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        method: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<u16>,
        bytes_out: u64,
        bytes_in: u64,
        decision: Decision,
    },
    #[serde(rename = "audit.dropped")]
    Dropped { count: u64 },
    #[serde(rename = "server.start")]
    ServerStart {
        version: String,
        asset_pins: Vec<AssetPin>,
        policies: Vec<String>,
    },
    #[serde(rename = "server.stop")]
    ServerStop,
}

/// Max bytes kept for ordinary free-text fields (rule A4).
pub const MAX_FIELD_BYTES: usize = 4 * 1024;
/// Max bytes kept for the optional `code` field (rule A4).
pub const MAX_CODE_BYTES: usize = 64 * 1024;

impl EventKind {
    /// Apply redaction and truncation to every free-text field (rules A3, A4).
    pub(crate) fn sanitize(&mut self, r: &Redactor) {
        let field = |s: &mut String| {
            *s = truncate(r.redact(s).into_owned(), MAX_FIELD_BYTES);
        };
        let opt = |s: &mut Option<String>| {
            if let Some(v) = s {
                *v = truncate(r.redact(v).into_owned(), MAX_FIELD_BYTES);
            }
        };
        match self {
            EventKind::RunStart { code, inputs, .. } => {
                if let Some(c) = code {
                    *c = truncate(r.redact(c).into_owned(), MAX_CODE_BYTES);
                }
                for i in inputs {
                    field(&mut i.name);
                }
            }
            EventKind::RunEnd { artifacts, .. } => {
                for a in artifacts {
                    field(&mut a.name);
                }
            }
            EventKind::FsAccess {
                path, mode, reason, ..
            } => {
                field(path);
                opt(mode);
                opt(reason);
            }
            EventKind::EnvRead { key, .. } => field(key),
            EventKind::PolicyDenied { what, requested } => {
                field(what);
                opt(requested);
            }
            EventKind::NetRequest {
                host, path, method, ..
            } => {
                field(host);
                opt(path);
                opt(method);
            }
            EventKind::LimitHit { .. }
            | EventKind::Dropped { .. }
            | EventKind::ServerStart { .. }
            | EventKind::ServerStop => {}
        }
    }
}

/// Truncate to at most `max` bytes on a char boundary, appending a marker.
pub(crate) fn truncate(mut s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let dropped = s.len() - cut;
    s.truncate(cut);
    s.push_str(&format!("…[truncated {dropped} bytes]"));
    s
}

/// One audit record: envelope + payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuditEvent {
    #[serde(serialize_with = "ser_ts")]
    pub ts: SystemTime,
    #[serde(rename = "v")]
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    #[serde(flatten)]
    pub kind: EventKind,
}

fn ser_ts<S: Serializer>(ts: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(&humantime::format_rfc3339_millis(*ts))
}

impl AuditEvent {
    /// New event stamped with the current time.
    pub fn new(kind: EventKind) -> Self {
        Self {
            ts: SystemTime::now(),
            version: SCHEMA_VERSION,
            run_id: None,
            policy: None,
            principal: None,
            kind,
        }
    }
    /// Attach the run id.
    pub fn run(mut self, id: RunId) -> Self {
        self.run_id = Some(id);
        self
    }
    /// Attach the policy name.
    pub fn policy(mut self, name: impl Into<String>) -> Self {
        self.policy = Some(name.into());
        self
    }
    /// Attach the caller identity (token *name* or `token:<hash prefix>`, never the token).
    pub fn principal(mut self, p: impl Into<String>) -> Self {
        self.principal = Some(p.into());
        self
    }
    /// Override the timestamp (tests, replay).
    pub fn at(mut self, ts: SystemTime) -> Self {
        self.ts = ts;
        self
    }
    /// Serialize to one JSON line (no trailing newline) after redaction.
    pub fn to_json_line(&self, r: &Redactor) -> String {
        let mut ev = self.clone();
        ev.kind.sanitize(r);
        if let Some(p) = &mut ev.policy {
            *p = truncate(std::mem::take(p), MAX_FIELD_BYTES);
        }
        if let Some(p) = &mut ev.principal {
            *p = truncate(r.redact(p).into_owned(), MAX_FIELD_BYTES);
        }
        // Serialization of these plain data types cannot fail.
        serde_json::to_string(&ev).unwrap_or_else(|e| {
            format!(
                r#"{{"event":"audit.serialize_error","error":{:?}}}"#,
                e.to_string()
            )
        })
    }
}

/// Lower-case hex SHA-256, used for `code_sha256` and file digests.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Stable, non-reversible principal label for an unnamed bearer token (rule A5).
pub fn token_principal(token: &str) -> String {
    format!("token:{}", &sha256_hex(token.as_bytes())[..12])
}
