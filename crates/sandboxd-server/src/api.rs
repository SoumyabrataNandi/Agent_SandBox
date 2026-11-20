//! Wire types shared by HTTP and MCP (U5 design §2, §3).

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use sandboxd_policy::{Overrides, parse_bytes, parse_duration, parse_fuel};
use sandboxd_runtime::{
    CallRequest, InputFile, Language, RunError, RunRequest, RunResult, SessionOptions,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Guest language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiLanguage {
    /// CPython 3.15 with the standard library only (no pip, no native extensions).
    #[serde(alias = "py")]
    Python,
    /// QuickJS (ES2023 module). `qjs:std` / `qjs:os` are importable. No Node.js APIs.
    #[serde(alias = "js")]
    Javascript,
}

impl From<ApiLanguage> for Language {
    fn from(l: ApiLanguage) -> Self {
        match l {
            ApiLanguage::Python => Language::Python,
            ApiLanguage::Javascript => Language::JavaScript,
        }
    }
}

/// How `content` is encoded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiEncoding {
    #[default]
    Utf8,
    Base64,
}

/// An input file, exposed read-only to the code under `/in/<name>`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiFile {
    /// Relative path such as `data.csv` or `raw/2025/jan.json` (letters, digits, `._-`, up to 4 levels).
    pub name: String,
    /// File content (UTF-8 text unless `encoding` is `base64`).
    pub content: String,
    #[serde(default)]
    pub encoding: ApiEncoding,
}

/// Optional limits. They can only make the selected policy stricter, never looser.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiLimits {
    /// e.g. "2s", "500ms".
    pub wall_clock: Option<String>,
    /// Instruction budget, e.g. "5G".
    pub fuel: Option<String>,
    /// e.g. "128MiB".
    pub memory: Option<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
}

/// A code execution request.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiRunRequest {
    pub language: ApiLanguage,
    /// The program. Python runs as `/code/main.py`; JavaScript as the ES module `/code/main.mjs`.
    pub code: String,
    /// Named operator policy (see `list_policies`). Defaults to `default`.
    #[serde(default)]
    pub policy: Option<String>,
    /// Input files, available read-only under `/in`.
    #[serde(default)]
    pub files: Vec<ApiFile>,
    /// Command-line arguments (`sys.argv[1:]` / `scriptArgs`).
    #[serde(default)]
    pub args: Vec<String>,
    /// Text supplied on standard input.
    #[serde(default)]
    pub stdin: Option<String>,
    #[serde(default)]
    pub limits: Option<ApiLimits>,
    /// Run in this persistent session (from `session_create`) instead of a fresh sandbox:
    /// variables, imports and files under /work carry over between calls. `language` must match
    /// the session's; `policy` is the session's.
    #[serde(default)]
    pub session_id: Option<String>,
}

fn decode_files(files: Vec<ApiFile>) -> Result<Vec<InputFile>, String> {
    let mut out = Vec::with_capacity(files.len());
    for f in files {
        let bytes = match f.encoding {
            ApiEncoding::Utf8 => f.content.into_bytes(),
            ApiEncoding::Base64 => B64
                .decode(f.content.as_bytes())
                .map_err(|e| format!("file {:?}: invalid base64: {e}", f.name))?,
        };
        out.push(InputFile {
            name: f.name,
            bytes,
        });
    }
    Ok(out)
}

impl ApiLimits {
    /// Parse into policy overrides. Errors are client errors (400).
    pub fn into_overrides(self) -> Result<Overrides, String> {
        let d = |v: &Option<String>, f: &str| -> Result<_, String> {
            v.as_deref()
                .map(parse_duration)
                .transpose()
                .map_err(|e| format!("limits.{f}: {e}"))
        };
        let b = |v: &Option<String>, f: &str| -> Result<_, String> {
            v.as_deref()
                .map(parse_bytes)
                .transpose()
                .map_err(|e| format!("limits.{f}: {e}"))
        };
        Ok(Overrides {
            wall_clock: d(&self.wall_clock, "wall_clock")?,
            fuel: self
                .fuel
                .as_deref()
                .map(parse_fuel)
                .transpose()
                .map_err(|e| format!("limits.fuel: {e}"))?,
            memory: b(&self.memory, "memory")?,
            stdout: b(&self.stdout, "stdout")?,
            stderr: b(&self.stderr, "stderr")?,
            ..Overrides::default()
        })
    }
}

/// Create a persistent session (`POST /v1/sessions`, MCP `session_create`).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiSessionCreate {
    pub language: ApiLanguage,
    /// Named operator policy; it must enable sessions. Defaults to `default`.
    #[serde(default)]
    pub policy: Option<String>,
    /// Files available read-only under /in for the whole session.
    #[serde(default)]
    pub files: Vec<ApiFile>,
    /// Limits for the whole session (can only tighten the policy).
    #[serde(default)]
    pub limits: Option<ApiLimits>,
}

impl ApiSessionCreate {
    /// Policy name, defaulting to `default`.
    pub fn policy_name(&self) -> &str {
        self.policy
            .as_deref()
            .filter(|p| !p.is_empty())
            .unwrap_or("default")
    }

    /// Decode into runtime options.
    pub fn into_options(self) -> Result<SessionOptions, String> {
        Ok(SessionOptions {
            language: self.language.into(),
            files: decode_files(self.files)?,
            overrides: self
                .limits
                .map(ApiLimits::into_overrides)
                .transpose()?
                .unwrap_or_default(),
        })
    }
}

/// One call in a session (`POST /v1/sessions/{id}/runs`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiSessionRun {
    /// The cell. Python runs in the session's `__main__`; JavaScript runs as a global script
    /// with top-level await (use `await import(...)`, not `import`).
    pub code: String,
    /// More input files under /in (new names only).
    #[serde(default)]
    pub files: Vec<ApiFile>,
    /// `sys.argv[1:]` / `scriptArgs` for this call.
    #[serde(default)]
    pub args: Vec<String>,
    /// Not supported in sessions; send data as a file.
    #[serde(default)]
    pub stdin: Option<String>,
    /// Only `wall_clock` and `fuel` (tighter than the session's) for one call.
    #[serde(default)]
    pub limits: Option<ApiLimits>,
}

impl ApiSessionRun {
    /// Decode into a runtime call.
    pub fn into_call(self) -> Result<CallRequest, String> {
        Ok(CallRequest {
            code: self.code,
            args: self.args,
            stdin: self.stdin.map(String::into_bytes),
            files: decode_files(self.files)?,
            overrides: self
                .limits
                .map(ApiLimits::into_overrides)
                .transpose()?
                .unwrap_or_default(),
        })
    }
}

/// A session's state.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiSession {
    pub session_id: String,
    pub language: String,
    pub policy: String,
    /// `snapshot` or `upstream`.
    pub interpreter: String,
    /// `active`, `busy` or `ended`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_reason: Option<String>,
    pub calls: u64,
    pub max_calls: u32,
    pub created_at: String,
    /// When the session ends regardless of use (`max_lifetime`).
    pub expires_at: String,
    /// Ends after this many seconds without a call.
    pub idle_timeout_s: u64,
}

impl ApiRunRequest {
    /// Policy name, defaulting to `default`.
    pub fn policy_name(&self) -> &str {
        self.policy
            .as_deref()
            .filter(|p| !p.is_empty())
            .unwrap_or("default")
    }

    /// Decode into a runtime request. Errors are client errors (400).
    pub fn into_run_request(self) -> Result<RunRequest, String> {
        if self.session_id.is_some() {
            return Err("session calls go through the session API".into());
        }
        Ok(RunRequest {
            language: self.language.into(),
            code: self.code,
            files: decode_files(self.files)?,
            args: self.args,
            stdin: self.stdin.map(String::into_bytes),
            overrides: self
                .limits
                .map(ApiLimits::into_overrides)
                .transpose()?
                .unwrap_or_default(),
            session: None,
        })
    }

    /// `Ok(self)` for a plain run; `Err((id, language, policy, call))` for a session call.
    #[allow(
        clippy::result_large_err,
        reason = "not an error: the two shapes of run_code"
    )]
    pub fn into_session_call_or_run(
        mut self,
    ) -> Result<Self, (String, ApiLanguage, Option<String>, ApiSessionRun)> {
        match self.session_id.take() {
            None => Ok(self),
            Some(id) => Err((
                id,
                self.language,
                self.policy,
                ApiSessionRun {
                    code: self.code,
                    files: self.files,
                    args: self.args,
                    stdin: self.stdin,
                    limits: self.limits,
                },
            )),
        }
    }

    /// Split a `run_code` request that has a `session_id` into (id, language, policy, call).
    pub fn into_session_call(self) -> Option<(String, ApiLanguage, Option<String>, ApiSessionRun)> {
        let id = self.session_id?;
        Some((
            id,
            self.language,
            self.policy,
            ApiSessionRun {
                code: self.code,
                files: self.files,
                args: self.args,
                stdin: self.stdin,
                limits: self.limits,
            },
        ))
    }
}

/// A collected `/out` file.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiArtifact {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub content_base64: String,
}

/// Error detail inside a result or an error response.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

/// Timings in milliseconds.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiTimings {
    pub queued_ms: u64,
    pub setup_ms: u64,
    pub run_ms: u64,
    pub collect_ms: u64,
    pub total_ms: u64,
}

/// The result of a run. A guest failure is reported here, not as an HTTP error.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiRunResult {
    pub run_id: String,
    pub language: String,
    pub policy: String,
    /// ok | exit | limit | trap | error
    pub outcome: String,
    pub exit_code: Option<i32>,
    pub stdout: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_base64: Option<String>,
    pub stderr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_base64: Option<String>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub artifacts: Vec<ApiArtifact>,
    pub limits_hit: Vec<String>,
    pub error: Option<ApiError>,
    pub fuel_used: u64,
    pub peak_memory: u64,
    pub timings: ApiTimings,
    /// Set for session calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Set when this call ended its session (`limit`, `exited`, `max_calls`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ended: Option<String>,
}

fn text_and_b64(b: &[u8]) -> (String, Option<String>) {
    match std::str::from_utf8(b) {
        Ok(s) => (s.to_string(), None),
        Err(_) => (String::from_utf8_lossy(b).into_owned(), Some(B64.encode(b))),
    }
}

fn snake<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// Map a runtime error to the wire.
pub fn api_error(e: &RunError) -> ApiError {
    ApiError {
        code: e.code().into(),
        message: e.to_string(),
    }
}

impl From<&RunResult> for ApiRunResult {
    fn from(r: &RunResult) -> Self {
        let (stdout, stdout_base64) = text_and_b64(&r.stdout);
        let (stderr, stderr_base64) = text_and_b64(&r.stderr);
        ApiRunResult {
            run_id: r.run_id.to_string(),
            language: r.language.as_str().into(),
            policy: r.policy.clone(),
            outcome: snake(&r.outcome),
            exit_code: r.exit_code,
            stdout,
            stdout_base64,
            stderr,
            stderr_base64,
            stdout_truncated: r.stdout_truncated,
            stderr_truncated: r.stderr_truncated,
            artifacts: r
                .artifacts
                .iter()
                .map(|a| ApiArtifact {
                    name: a.name.clone(),
                    size: a.bytes.len() as u64,
                    sha256: a.sha256.clone(),
                    content_base64: B64.encode(&a.bytes),
                })
                .collect(),
            limits_hit: r.limits_hit.iter().map(snake).collect(),
            error: r.error.as_ref().map(api_error),
            fuel_used: r.fuel_used,
            peak_memory: r.peak_memory,
            timings: ApiTimings {
                queued_ms: r.timings.queued_ms,
                setup_ms: r.timings.setup_ms,
                run_ms: r.timings.run_ms,
                collect_ms: r.timings.collect_ms,
                total_ms: r.timings.total_ms,
            },
            session_id: None,
            session_ended: None,
        }
    }
}

/// `GET /v1/policies` row (no host paths).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiPolicy {
    pub name: String,
    pub description: String,
    pub overrides_builtin: bool,
    pub wall_clock: String,
    pub memory: String,
    pub mounts: Vec<String>,
}
