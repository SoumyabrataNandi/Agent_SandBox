//! `sandboxd.toml` (U5 design §5, Q4).

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use sandboxd_policy::{parse_bytes, parse_duration};
use serde::Deserialize;

use crate::service::AdmissionConfig;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    policy_dir: Option<PathBuf>,
    cache_dir: Option<PathBuf>,
    work_dir: Option<PathBuf>,
    #[serde(default)]
    server: RawServer,
    #[serde(default)]
    auth: RawAuth,
    #[serde(default)]
    audit: RawAudit,
    #[serde(default)]
    telemetry: RawTelemetry,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    listen: Option<String>,
    max_concurrent: Option<usize>,
    queue_depth: Option<usize>,
    queue_timeout: Option<String>,
    max_request_bytes: Option<String>,
    metrics_public: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuth {
    #[serde(default)]
    tokens: Vec<RawToken>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToken {
    name: String,
    sha256: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAudit {
    sink: Option<String>,
    path: Option<PathBuf>,
    #[serde(default)]
    redact: Vec<RawRedact>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRedact {
    name: String,
    regex: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTelemetry {
    otlp_endpoint: Option<String>,
}

/// Where audit events go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditDest {
    Stdout,
    File(Option<PathBuf>),
    None,
}

/// Validated server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub policy_dir: Option<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub work_dir: Option<PathBuf>,
    pub listen: SocketAddr,
    pub admission: AdmissionConfig,
    pub max_request_bytes: usize,
    pub metrics_public: bool,
    /// `(name, sha256-hex)`.
    pub tokens: Vec<(String, String)>,
    /// `None` → mode default (Q9).
    pub audit: Option<AuditDest>,
    pub redact: Vec<(String, String)>,
    pub otlp_endpoint: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            policy_dir: None,
            cache_dir: None,
            work_dir: None,
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            admission: AdmissionConfig::default(),
            max_request_bytes: 64 << 20,
            metrics_public: false,
            tokens: Vec::new(),
            audit: None,
            redact: Vec::new(),
            otlp_endpoint: None,
        }
    }
}

impl ServerConfig {
    /// Parse TOML. Relative paths are resolved against `base` (the config file's directory).
    pub fn from_toml(src: &str, base: &std::path::Path) -> Result<Self, String> {
        let raw: Raw = toml::from_str(src).map_err(|e| e.to_string())?;
        let mut c = ServerConfig::default();
        let abs = |p: PathBuf| if p.is_absolute() { p } else { base.join(p) };
        c.policy_dir = raw.policy_dir.map(abs);
        c.cache_dir = raw.cache_dir.map(abs);
        c.work_dir = raw.work_dir.map(abs);
        if let Some(l) = raw.server.listen {
            c.listen = l.parse().map_err(|e| format!("server.listen {l:?}: {e}"))?;
        }
        if let Some(n) = raw.server.max_concurrent.filter(|n| *n > 0) {
            c.admission.max_concurrent = n;
        }
        if let Some(n) = raw.server.queue_depth {
            c.admission.queue_depth = n;
        }
        if let Some(t) = raw.server.queue_timeout {
            c.admission.queue_timeout =
                parse_duration(&t).map_err(|e| format!("server.queue_timeout: {e}"))?;
        }
        if let Some(b) = raw.server.max_request_bytes {
            c.max_request_bytes = usize::try_from(
                parse_bytes(&b)
                    .map_err(|e| format!("server.max_request_bytes: {e}"))?
                    .bytes(),
            )
            .unwrap_or(usize::MAX);
        }
        c.metrics_public = raw.server.metrics_public.unwrap_or(false);
        c.tokens = raw
            .auth
            .tokens
            .into_iter()
            .map(|t| (t.name, t.sha256))
            .collect();
        c.audit = match raw.audit.sink.as_deref() {
            None => raw.audit.path.map(|p| AuditDest::File(Some(abs(p)))),
            Some("stdout") => Some(AuditDest::Stdout),
            Some("none") => Some(AuditDest::None),
            Some("file") => Some(AuditDest::File(raw.audit.path.map(abs))),
            Some(other) => return Err(format!("audit.sink {other:?}: use file, stdout or none")),
        };
        c.redact = raw
            .audit
            .redact
            .into_iter()
            .map(|r| (r.name, r.regex))
            .collect();
        c.otlp_endpoint = raw.telemetry.otlp_endpoint.filter(|e| !e.is_empty());
        Ok(c)
    }

    /// Bind-safety rule (FR-5.4, AC 8): refuse non-loopback without tokens.
    pub fn check_bind_safety(&self, have_tokens: bool) -> Result<(), String> {
        if !self.listen.ip().is_loopback() && !have_tokens {
            return Err(format!(
                "refusing to listen on {} without auth tokens; configure [auth] tokens or SANDBOXD_TOKEN, or bind to 127.0.0.1",
                self.listen
            ));
        }
        Ok(())
    }
}

/// Parse a duration (re-export convenience for the CLI).
pub fn duration(s: &str) -> Result<Duration, String> {
    parse_duration(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_checks_bind_safety() {
        let c = ServerConfig::from_toml(
            "policy_dir = \"policies\"\n[server]\nlisten = \"0.0.0.0:9000\"\nqueue_timeout = \"3s\"\nmax_request_bytes = \"1MiB\"\n[auth]\ntokens = [{ name = \"ci\", sha256 = \"00\" }]\n[audit]\nsink = \"stdout\"\n",
            std::path::Path::new("/etc/sandboxd"),
        )
        .expect("parse");
        assert!(
            c.policy_dir
                .as_deref()
                .is_some_and(|p| p.ends_with("policies"))
        );
        assert_eq!(c.admission.queue_timeout, Duration::from_secs(3));
        assert_eq!(c.max_request_bytes, 1 << 20);
        assert_eq!(c.audit, Some(AuditDest::Stdout));
        assert!(c.check_bind_safety(false).is_err());
        assert!(c.check_bind_safety(true).is_ok());
        assert!(ServerConfig::default().check_bind_safety(false).is_ok());
        assert!(ServerConfig::from_toml("bogus = 1", std::path::Path::new(".")).is_err());
    }
}
