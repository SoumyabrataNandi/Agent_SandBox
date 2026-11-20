//! Request / result / event types (U4 design §1).

use std::fmt;

use bytes::Bytes;
use sandboxd_audit::{LimitKind, Outcome, RunId};
use sandboxd_policy::Overrides;
use sandboxd_vfs::{Artifact, InputFile};

/// Guest language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    /// CPython 3.15 (WASI).
    Python,
    /// QuickJS-ng (ES module).
    JavaScript,
}

impl Language {
    /// Lower-case name used in audit events and APIs.
    pub fn as_str(self) -> &'static str {
        match self {
            Language::Python => "python",
            Language::JavaScript => "javascript",
        }
    }
    /// Parse `python`/`py`/`javascript`/`js`.
    pub fn parse(s: &str) -> Option<Language> {
        match s.to_ascii_lowercase().as_str() {
            "python" | "py" | "python3" => Some(Language::Python),
            "javascript" | "js" | "node" | "mjs" => Some(Language::JavaScript),
            _ => None,
        }
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A persistent session id (`ses_<uuid>`, cycle 3 C3-U4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

/// One code execution request.
#[derive(Debug, Clone)]
pub struct RunRequest {
    pub language: Language,
    pub code: String,
    pub files: Vec<InputFile>,
    pub args: Vec<String>,
    pub stdin: Option<Vec<u8>>,
    /// Limit-only overrides; can only tighten the policy.
    pub overrides: Overrides,
    /// Must be `None`: session calls use [`crate::Session::call`].
    pub session: Option<SessionId>,
}

impl RunRequest {
    /// Minimal request: language + code, everything else default.
    pub fn new(language: Language, code: impl Into<String>) -> Self {
        Self {
            language,
            code: code.into(),
            files: Vec::new(),
            args: Vec::new(),
            stdin: None,
            overrides: Overrides::default(),
            session: None,
        }
    }
}

/// Why a run did not produce a normal result. The run's output is still returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// Code imported a package that needs native extensions (FR-1.5).
    UnsupportedNativeExtension { module: String },
    /// The request itself is invalid (size, names, inputs).
    InvalidRequest(String),
    /// An override would widen the policy.
    PolicyViolation(String),
    /// The guest crashed (wasm trap). Message is sanitized.
    Trap(String),
    /// Host-side failure (never the guest's fault).
    Internal(String),
    /// Feature reserved for a later phase.
    NotImplemented(&'static str),
}

impl RunError {
    /// Stable machine-readable code for APIs.
    pub fn code(&self) -> &'static str {
        match self {
            RunError::UnsupportedNativeExtension { .. } => "UNSUPPORTED_NATIVE_EXTENSION",
            RunError::InvalidRequest(_) => "INVALID_REQUEST",
            RunError::PolicyViolation(_) => "POLICY_VIOLATION",
            RunError::Trap(_) => "TRAP",
            RunError::Internal(_) => "INTERNAL",
            RunError::NotImplemented(_) => "NOT_IMPLEMENTED",
        }
    }
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::UnsupportedNativeExtension { module } => write!(
                f,
                "module {module:?} needs native extensions, which this WebAssembly sandbox does not support"
            ),
            RunError::InvalidRequest(m)
            | RunError::PolicyViolation(m)
            | RunError::Trap(m)
            | RunError::Internal(m) => f.write_str(m),
            RunError::NotImplemented(what) => {
                write!(f, "{what} is not implemented in this version")
            }
        }
    }
}

/// Phase timings in milliseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timings {
    /// Time waiting for admission (set by the server).
    pub queued_ms: u64,
    pub setup_ms: u64,
    pub run_ms: u64,
    pub collect_ms: u64,
    pub total_ms: u64,
}

/// Everything about a finished run.
#[derive(Debug, Clone)]
pub struct RunResult {
    pub run_id: RunId,
    pub language: Language,
    pub policy: String,
    pub outcome: Outcome,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub artifacts: Vec<Artifact>,
    pub limits_hit: Vec<LimitKind>,
    pub error: Option<RunError>,
    pub fuel_used: u64,
    pub peak_memory: u64,
    /// HTTP requests + TCP connections made through the network broker (0 without grants).
    pub net_requests: u32,
    pub timings: Timings,
}

/// Streamed while a run executes; `Finished` is always last.
#[derive(Debug, Clone)]
pub enum RunEvent {
    Stdout(Bytes),
    Stderr(Bytes),
    LimitHit(LimitKind),
    Finished(Box<RunResult>),
}
