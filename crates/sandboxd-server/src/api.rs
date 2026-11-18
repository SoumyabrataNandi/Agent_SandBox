//! Wire types shared by HTTP and MCP (U5 design §2, §3).

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use sandboxd_policy::{Overrides, parse_bytes, parse_duration, parse_fuel};
use sandboxd_runtime::{InputFile, Language, RunError, RunRequest, RunResult};
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
        let mut files = Vec::with_capacity(self.files.len());
        for f in self.files {
            let bytes = match f.encoding {
                ApiEncoding::Utf8 => f.content.into_bytes(),
                ApiEncoding::Base64 => B64
                    .decode(f.content.as_bytes())
                    .map_err(|e| format!("file {:?}: invalid base64: {e}", f.name))?,
            };
            files.push(InputFile {
                name: f.name,
                bytes,
            });
        }
        let mut o = Overrides::default();
        if let Some(l) = self.limits {
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
            o.wall_clock = d(&l.wall_clock, "wall_clock")?;
            o.fuel = l
                .fuel
                .as_deref()
                .map(parse_fuel)
                .transpose()
                .map_err(|e| format!("limits.fuel: {e}"))?;
            o.memory = b(&l.memory, "memory")?;
            o.stdout = b(&l.stdout, "stdout")?;
            o.stderr = b(&l.stderr, "stderr")?;
        }
        Ok(RunRequest {
            language: self.language.into(),
            code: self.code,
            files,
            args: self.args,
            stdin: self.stdin.map(String::into_bytes),
            overrides: o,
            session: None,
        })
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
