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
    #[serde(default)]
    runtime: RawRuntime,
    #[serde(default)]
    network: RawNetworkCfg,
    #[serde(default)]
    packages: RawPackages,
}

/// `[packages]` (cycle 5, FR-PK1): the operator's wheelhouse.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackages {
    dir: Option<PathBuf>,
    #[serde(default)]
    sha256: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNetworkCfg {
    enabled: Option<bool>,
    proxy: Option<String>,
    #[serde(default)]
    no_proxy: Vec<String>,
    use_env_proxy: Option<bool>,
    extra_ca_file: Option<PathBuf>,
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
struct RawRuntime {
    pooling: Option<String>,
    snapshots: Option<String>,
    max_sessions: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTelemetry {
    otlp_endpoint: Option<String>,
    otlp_interval: Option<String>,
}

/// Where audit events go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditDest {
    Stdout,
    File(Option<PathBuf>),
    None,
}

/// Server-wide network settings (cycle 2, FR-N8/N9/N11.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    /// Kill switch: when `false`, policies that grant egress are refused at load.
    pub enabled: bool,
    /// Operator proxy (`http://host:port` or `https://…`), never taken from the guest.
    pub proxy: Option<String>,
    pub no_proxy: Vec<String>,
    /// Use the process environment's `HTTPS_PROXY`/`NO_PROXY` (off by default).
    pub use_env_proxy: bool,
    /// Extra PEM CA bundle, added to the OS trust store.
    pub extra_ca_file: Option<PathBuf>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxy: None,
            no_proxy: Vec::new(),
            use_env_proxy: false,
            extra_ca_file: None,
        }
    }
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
    /// OTLP/HTTP base URL (`otel` feature), e.g. `http://collector:4318`.
    pub otlp_endpoint: Option<String>,
    /// Metric export interval (default 30s).
    pub otlp_interval: std::time::Duration,
    pub network: NetworkConfig,
    /// `[runtime] pooling` (cycle 3, FR-P1).
    pub pooling: sandboxd_runtime::PoolingMode,
    /// `[runtime] snapshots` (cycle 3, FR-S1).
    pub snapshots: sandboxd_runtime::SnapshotMode,
    /// `[packages]` (cycle 5, FR-PK1): pure-Python wheels for Python runs.
    pub packages: Option<sandboxd_runtime::PackageConfig>,
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
            otlp_interval: crate::otel::DEFAULT_EXPORT_INTERVAL,
            network: NetworkConfig::default(),
            pooling: sandboxd_runtime::PoolingMode::Auto,
            snapshots: sandboxd_runtime::SnapshotMode::Auto,
            packages: None,
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
        if let Some(p) = &raw.runtime.pooling {
            c.pooling = sandboxd_runtime::PoolingMode::parse(p)
                .ok_or_else(|| format!("runtime.pooling {p:?}: use auto, on or off"))?;
        }
        if let Some(v) = &raw.runtime.snapshots {
            c.snapshots = sandboxd_runtime::SnapshotMode::parse(v)
                .ok_or_else(|| format!("runtime.snapshots {v:?}: use auto, on or off"))?;
        }
        c.packages = match raw.packages.dir {
            Some(dir) => {
                for (file, sha) in &raw.packages.sha256 {
                    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Err(format!(
                            "packages.sha256.{file:?}: expected 64 hex characters"
                        ));
                    }
                }
                Some(sandboxd_runtime::PackageConfig {
                    dir: abs(dir),
                    sha256: raw.packages.sha256,
                })
            }
            None if !raw.packages.sha256.is_empty() => {
                return Err("packages.sha256 needs packages.dir".into());
            }
            None => None,
        };
        if let Some(n) = raw.runtime.max_sessions {
            if n > 10_000 {
                return Err(format!("runtime.max_sessions {n}: at most 10000"));
            }
            c.admission.max_sessions = n;
        }
        c.otlp_endpoint = raw.telemetry.otlp_endpoint.filter(|e| !e.is_empty());
        if let Some(e) = &c.otlp_endpoint {
            let ok = (e.starts_with("http://") || e.starts_with("https://"))
                && !e.contains(char::is_whitespace);
            if !ok {
                return Err(format!(
                    "telemetry.otlp_endpoint {e:?}: must be an http:// or https:// URL (OTLP/HTTP, e.g. http://collector:4318)"
                ));
            }
        }
        if let Some(i) = &raw.telemetry.otlp_interval {
            let d = sandboxd_policy::parse_duration(i)
                .map_err(|e| format!("telemetry.otlp_interval: {e}"))?;
            if !(std::time::Duration::from_secs(1)..=std::time::Duration::from_secs(3600))
                .contains(&d)
            {
                return Err(format!(
                    "telemetry.otlp_interval {i:?}: must be between 1s and 1h"
                ));
            }
            c.otlp_interval = d;
        }
        let n = raw.network;
        if let Some(p) = &n.proxy {
            let ok = (p.starts_with("http://") || p.starts_with("https://"))
                && !p.contains(char::is_whitespace);
            if !ok {
                return Err(format!(
                    "network.proxy {p:?}: must be an http:// or https:// URL"
                ));
            }
        }
        c.network = NetworkConfig {
            enabled: n.enabled.unwrap_or(true),
            proxy: n.proxy,
            no_proxy: n.no_proxy,
            use_env_proxy: n.use_env_proxy.unwrap_or(false),
            extra_ca_file: n.extra_ca_file.map(abs),
        };
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
        let n = ServerConfig::from_toml(
            "[network]
enabled = false
proxy = \"http://proxy.corp:8080\"
no_proxy = [\"internal.corp\"]
extra_ca_file = \"ca.pem\"
",
            std::path::Path::new("/etc/sandboxd"),
        )
        .expect("network config");
        assert!(!n.network.enabled && n.network.proxy.is_some() && !n.network.use_env_proxy);
        assert!(
            n.network
                .extra_ca_file
                .as_deref()
                .is_some_and(|p| p.ends_with("ca.pem"))
        );
        assert!(
            ServerConfig::from_toml(
                "[network]
proxy = \"socks5://x\"
",
                std::path::Path::new(".")
            )
            .is_err()
        );
        assert!(ServerConfig::default().network.enabled);
    }

    #[test]
    fn runtime_pooling_mode() {
        let p = std::path::Path::new(".");
        assert_eq!(
            ServerConfig::default().pooling,
            sandboxd_runtime::PoolingMode::Auto
        );
        for (v, want) in [
            ("auto", sandboxd_runtime::PoolingMode::Auto),
            ("on", sandboxd_runtime::PoolingMode::On),
            ("off", sandboxd_runtime::PoolingMode::Off),
        ] {
            let c = ServerConfig::from_toml(&format!("[runtime]\npooling = \"{v}\"\n"), p)
                .expect("pooling");
            assert_eq!(c.pooling, want);
        }
        assert!(ServerConfig::from_toml("[runtime]\npooling = \"maybe\"\n", p).is_err());
        assert_eq!(
            ServerConfig::default().snapshots,
            sandboxd_runtime::SnapshotMode::Auto
        );
        let c = ServerConfig::from_toml("[runtime]\nsnapshots = \"off\"\n", p).expect("snapshots");
        assert_eq!(c.snapshots, sandboxd_runtime::SnapshotMode::Off);
        // [packages] (cycle 5)
        assert_eq!(ServerConfig::default().packages, None);
        let c = ServerConfig::from_toml("[packages]\ndir = \"wheels\"\n", p).expect("packages");
        assert_eq!(c.packages.map(|k| k.dir), Some(p.join("wheels")));
        let lock = format!(
            "[packages]\ndir = \"w\"\nsha256 = {{ \"a-1-py3-none-any.whl\" = \"{}\" }}\n",
            "ab".repeat(32)
        );
        assert!(ServerConfig::from_toml(&lock, p).is_ok());
        assert!(
            ServerConfig::from_toml(
                "[packages]\ndir = \"w\"\nsha256 = { \"x.whl\" = \"zz\" }\n",
                p
            )
            .is_err()
        );
        assert!(
            ServerConfig::from_toml("[packages]\nsha256 = { \"x.whl\" = \"zz\" }\n", p).is_err()
        );
        assert!(ServerConfig::from_toml("[packages]\nfolder = \"w\"\n", p).is_err());
        assert!(ServerConfig::from_toml("[runtime]\nsnapshots = \"sometimes\"\n", p).is_err());
        assert_eq!(ServerConfig::default().admission.max_sessions, 16);
        let c = ServerConfig::from_toml("[runtime]\nmax_sessions = 0\n", p).expect("sessions");
        assert_eq!(c.admission.max_sessions, 0);
        assert!(ServerConfig::from_toml("[runtime]\nmax_sessions = 20000\n", p).is_err());
        assert!(ServerConfig::from_toml("[runtime]\nbogus = 1\n", p).is_err());
    }

    #[test]
    fn telemetry_endpoint_and_interval() {
        let p = std::path::Path::new(".");
        let c = ServerConfig::from_toml(
            "[telemetry]\notlp_endpoint = \"http://collector:4318\"\notlp_interval = \"10s\"\n",
            p,
        )
        .expect("telemetry");
        assert_eq!(c.otlp_endpoint.as_deref(), Some("http://collector:4318"));
        assert_eq!(c.otlp_interval, Duration::from_secs(10));
        let d = ServerConfig::default();
        assert_eq!(
            (d.otlp_endpoint, d.otlp_interval),
            (None, crate::otel::DEFAULT_EXPORT_INTERVAL)
        );
        // An empty endpoint means "off".
        let off = ServerConfig::from_toml("[telemetry]\notlp_endpoint = \"\"\n", p).expect("empty");
        assert!(off.otlp_endpoint.is_none());
        for bad in [
            "[telemetry]\notlp_endpoint = \"collector:4317\"\n",
            "[telemetry]\notlp_endpoint = \"grpc://collector:4317\"\n",
            "[telemetry]\notlp_interval = \"100ms\"\n",
            "[telemetry]\notlp_interval = \"2h\"\n",
            "[telemetry]\nbogus = 1\n",
        ] {
            assert!(ServerConfig::from_toml(bad, p).is_err(), "{bad}");
        }
    }
}
