//! Validated policy model (design §1–§3).

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use crate::{
    error::{PolicyError, PolicyErrors},
    raw::{Quantity, RawMode, RawPolicy},
    units::{ByteSize, fmt_duration, fmt_fuel, parse_bytes, parse_duration, parse_fuel},
};

/// Only accepted schema version.
pub const SCHEMA_VERSION: u32 = 1;
/// Max policy file size, for TOML and YAML alike (rule R12).
pub const MAX_POLICY_FILE_BYTES: usize = 1024 * 1024;
/// Guest path where the CPython stdlib is mounted. Must match `sandboxd-vfs` (ADR-004).
pub const STDLIB_GUEST_PATH: &str = "/usr/local/lib/python3.15";
/// Guest path reserved for virtual devices (ADR-002).
pub const DEVICE_GUEST_PATH: &str = "/dev/sandbox";
/// Guest path where the runtime places the submitted program (read-only; U4 design Q4).
pub const CODE_GUEST_PATH: &str = "/code";
/// Env keys the runtime controls; policies cannot set them.
pub const RESERVED_ENV: &[&str] = &[
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "PYTHONUSERBASE",
];

/// Resource limits (all enforced by the runtime in U4; `input_bytes` by the server in U5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub wall_clock: Duration,
    pub fuel: u64,
    pub memory: ByteSize,
    pub stdout: ByteSize,
    pub stderr: ByteSize,
    pub artifact_count: u32,
    pub artifact_bytes: ByteSize,
    pub input_bytes: ByteSize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            wall_clock: Duration::from_secs(5),
            // ≈ 4 s of CPU (calibrated in U4: ~4.7G fuel/s), so wall_clock (5 s) is the binding limit.
            fuel: 20_000_000_000,
            memory: ByteSize::mib(256),
            stdout: ByteSize::mib(1),
            stderr: ByteSize::kib(256),
            artifact_count: 16,
            artifact_bytes: ByteSize::mib(16),
            input_bytes: ByteSize::mib(16),
        }
    }
}

/// Inclusive ranges (rule R3).
mod range {
    use super::*;
    pub const WALL_CLOCK: (Duration, Duration) =
        (Duration::from_millis(10), Duration::from_secs(3600));
    pub const FUEL: (u64, u64) = (1_000_000, 1_000_000_000_000);
    pub const MEMORY: (ByteSize, ByteSize) = (ByteSize::mib(1), ByteSize::gib(4));
    pub const STDIO: (ByteSize, ByteSize) = (ByteSize(0), ByteSize::mib(64));
    pub const ARTIFACT_COUNT: (u32, u32) = (0, 1000);
    pub const ARTIFACT_BYTES: (ByteSize, ByteSize) = (ByteSize(0), ByteSize::gib(1));
    pub const INPUT_BYTES: (ByteSize, ByteSize) = (ByteSize(0), ByteSize::gib(1));
    pub const IDLE_TTL: (Duration, Duration) =
        (Duration::from_secs(1), Duration::from_secs(86_400));
}

/// Read-only or read-write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MountMode {
    ReadOnly,
    ReadWrite,
}
impl MountMode {
    /// `"ro"` / `"rw"`.
    pub fn as_str(self) -> &'static str {
        match self {
            MountMode::ReadOnly => "ro",
            MountMode::ReadWrite => "rw",
        }
    }
}

/// A host directory exposed to the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// Normalized absolute guest path.
    pub guest: String,
    /// Canonicalized host directory.
    pub host: PathBuf,
    pub mode: MountMode,
}

/// Guest paths for request inputs (always ro) and outputs (always rw).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filesystem {
    pub inputs: String,
    pub outputs: String,
    pub mounts: Vec<Mount>,
}

/// HTTP egress rule (Phase 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRule {
    pub host: String,
    pub port: u16,
    pub methods: Vec<String>,
    pub path_prefix: String,
}

/// Raw TCP egress rule (Phase 4; opt-in per destination).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRule {
    pub host: String,
    pub port: u16,
}

/// Network section (validated now, enforced in Phase 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub allow_private_ips: bool,
    pub max_requests: u32,
    pub max_request_bytes: ByteSize,
    pub max_response_bytes: ByteSize,
    pub max_total_bytes: ByteSize,
    pub http: Vec<HttpRule>,
    pub tcp: Vec<TcpRule>,
}
impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            allow_private_ips: false,
            max_requests: 0,
            max_request_bytes: ByteSize::mib(1),
            max_response_bytes: ByteSize::mib(10),
            max_total_bytes: ByteSize::mib(50),
            http: Vec::new(),
            tcp: Vec::new(),
        }
    }
}
impl NetworkPolicy {
    /// `true` if this section grants any egress.
    pub fn grants_anything(&self) -> bool {
        !self.http.is_empty() || !self.tcp.is_empty()
    }
}

/// Session section (validated now, enforced in Phase 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPolicy {
    pub enabled: bool,
    pub idle_ttl: Duration,
    pub max_sessions: u32,
}
impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            idle_ttl: Duration::from_secs(300),
            max_sessions: 100,
        }
    }
}

/// Audit section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuditPolicy {
    pub log_code: bool,
}

/// Everything except where it came from. Equality of specs is what TOML/YAML parity means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySpec {
    pub name: String,
    pub description: String,
    pub limits: Limits,
    pub filesystem: Filesystem,
    pub env: BTreeMap<String, String>,
    pub network: NetworkPolicy,
    pub session: SessionPolicy,
    pub audit: AuditPolicy,
}

/// A validated, immutable policy.
#[derive(Debug, Clone)]
pub struct Policy {
    spec: PolicySpec,
    origin: String,
}

impl PartialEq for Policy {
    fn eq(&self, other: &Self) -> bool {
        self.spec == other.spec
    }
}
impl Eq for Policy {}

/// Limit-only overrides from the CLI or API. They can only tighten (rule R8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Overrides {
    pub wall_clock: Option<Duration>,
    pub fuel: Option<u64>,
    pub memory: Option<ByteSize>,
    pub stdout: Option<ByteSize>,
    pub stderr: Option<ByteSize>,
    pub artifact_count: Option<u32>,
    pub artifact_bytes: Option<ByteSize>,
    pub input_bytes: Option<ByteSize>,
}
impl Overrides {
    /// `true` if nothing is overridden.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Host-side context for validation.
#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    /// Host directories that mounts must not be inside, or contain (cache, audit log dir, policy dir; rule R6).
    pub forbidden_host_roots: Vec<PathBuf>,
}

/// Source format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Toml,
    Yaml,
}

impl Policy {
    /// Parse and validate TOML. `origin` is used in error messages (usually the file path).
    pub fn from_toml(src: &str, origin: &str) -> Result<Policy, PolicyErrors> {
        Self::parse(src, origin, Format::Toml, &LoadOptions::default())
    }

    /// Parse and validate YAML.
    pub fn from_yaml(src: &str, origin: &str) -> Result<Policy, PolicyErrors> {
        Self::parse(src, origin, Format::Yaml, &LoadOptions::default())
    }

    /// Parse and validate with explicit options.
    pub fn parse(
        src: &str,
        origin: &str,
        format: Format,
        opts: &LoadOptions,
    ) -> Result<Policy, PolicyErrors> {
        if src.len() > MAX_POLICY_FILE_BYTES {
            return Err(PolicyError::Parse {
                origin: origin.into(),
                msg: format!(
                    "file is larger than {}",
                    ByteSize(MAX_POLICY_FILE_BYTES as u64)
                ),
            }
            .into());
        }
        let raw: RawPolicy = match format {
            Format::Toml => toml::from_str(src).map_err(|e| PolicyError::Parse {
                origin: origin.into(),
                msg: e.to_string().trim_end().to_string(),
            })?,
            Format::Yaml => {
                serde_saphyr::from_str_with_options(src, yaml_options()).map_err(|e| {
                    PolicyError::Parse {
                        origin: origin.into(),
                        msg: e.to_string().trim_end().to_string(),
                    }
                })?
            }
        };
        validate(raw, origin, opts)
    }

    /// Load one file; the format comes from the extension (`.toml`, `.yaml`, `.yml`).
    /// The `name` field must equal the file stem (rule R7).
    pub fn from_path(path: &Path, opts: &LoadOptions) -> Result<Policy, PolicyErrors> {
        let origin = path.display().to_string();
        let format = match path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
        {
            Some(e) if e == "toml" => Format::Toml,
            Some(e) if e == "yaml" || e == "yml" => Format::Yaml,
            _ => {
                return Err(PolicyError::Io {
                    origin,
                    msg: "unsupported extension (use .toml, .yaml or .yml)".into(),
                }
                .into());
            }
        };
        let meta = std::fs::metadata(path).map_err(|e| PolicyError::Io {
            origin: origin.clone(),
            msg: e.to_string(),
        })?;
        if meta.len() > MAX_POLICY_FILE_BYTES as u64 {
            return Err(PolicyError::Parse {
                origin,
                msg: format!(
                    "file is larger than {}",
                    ByteSize(MAX_POLICY_FILE_BYTES as u64)
                ),
            }
            .into());
        }
        let src = std::fs::read_to_string(path).map_err(|e| PolicyError::Io {
            origin: origin.clone(),
            msg: e.to_string(),
        })?;
        let p = Self::parse(&src, &origin, format, opts)?;
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if p.spec.name != stem {
            return Err(PolicyError::Invalid {
                origin,
                path: "name".into(),
                msg: format!("{:?} must equal the file name {stem:?}", p.spec.name),
            }
            .into());
        }
        Ok(p)
    }

    /// The built-in `default` policy: default limits, `/in` + `/out`, nothing else.
    pub fn builtin_default() -> Policy {
        Policy {
            spec: PolicySpec {
                name: "default".into(),
                description:
                    "Built-in: default limits, /in (ro) and /out (rw) only, no env, no network"
                        .into(),
                limits: Limits::default(),
                filesystem: Filesystem {
                    inputs: "/in".into(),
                    outputs: "/out".into(),
                    mounts: Vec::new(),
                },
                env: BTreeMap::new(),
                network: NetworkPolicy::default(),
                session: SessionPolicy::default(),
                audit: AuditPolicy::default(),
            },
            origin: "<built-in>".into(),
        }
    }

    /// Refuse policies that grant capabilities this version can't enforce (Q3 = A).
    /// `PolicyDir::load` calls this; `policy check` reports it alongside validation.
    pub fn ensure_supported(&self) -> Result<(), PolicyErrors> {
        let mut errs = Vec::new();
        if self.spec.network.grants_anything() {
            errs.push(PolicyError::Unsupported {
                origin: self.origin.clone(),
                feature: "network.http / network.tcp grant egress, which requires the network broker (not in this version)".into(),
            });
        }
        if self.spec.session.enabled {
            errs.push(PolicyError::Unsupported {
                origin: self.origin.clone(),
                feature:
                    "session.enabled = true requires persistent sessions (not in this version)"
                        .into(),
            });
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(PolicyErrors(errs))
        }
    }

    /// Lower limits per `o`. Any value above the policy's is an error, never a clamp (rule R8).
    pub fn tighten(&self, o: &Overrides) -> Result<Policy, PolicyError> {
        fn pick<T: PartialOrd + Copy>(
            field: &'static str,
            cur: T,
            req: Option<T>,
            (lo, _): (T, T),
            show: impl Fn(T) -> String,
        ) -> Result<T, PolicyError> {
            match req {
                None => Ok(cur),
                Some(r) if r > cur => Err(PolicyError::WouldWiden {
                    field,
                    policy: show(cur),
                    requested: show(r),
                }),
                Some(r) if r < lo => Err(PolicyError::Invalid {
                    origin: "override".into(),
                    path: field.into(),
                    msg: format!("{} is below the minimum {}", show(r), show(lo)),
                }),
                Some(r) => Ok(r),
            }
        }
        let l = &self.spec.limits;
        let bs = |b: ByteSize| b.to_string();
        let new = Limits {
            wall_clock: pick(
                "limits.wall_clock",
                l.wall_clock,
                o.wall_clock,
                range::WALL_CLOCK,
                fmt_duration,
            )?,
            fuel: pick("limits.fuel", l.fuel, o.fuel, range::FUEL, fmt_fuel)?,
            memory: pick("limits.memory", l.memory, o.memory, range::MEMORY, bs)?,
            stdout: pick("limits.stdout", l.stdout, o.stdout, range::STDIO, bs)?,
            stderr: pick("limits.stderr", l.stderr, o.stderr, range::STDIO, bs)?,
            artifact_count: pick(
                "limits.artifact_count",
                l.artifact_count,
                o.artifact_count,
                range::ARTIFACT_COUNT,
                |v| v.to_string(),
            )?,
            artifact_bytes: pick(
                "limits.artifact_bytes",
                l.artifact_bytes,
                o.artifact_bytes,
                range::ARTIFACT_BYTES,
                bs,
            )?,
            input_bytes: pick(
                "limits.input_bytes",
                l.input_bytes,
                o.input_bytes,
                range::INPUT_BYTES,
                bs,
            )?,
        };
        let mut p = self.clone();
        p.spec.limits = new;
        Ok(p)
    }

    /// Human-readable effective policy with warnings (rule R10).
    pub fn explain(&self) -> String {
        let s = &self.spec;
        let l = &s.limits;
        let mut o = String::new();
        let _ = writeln!(o, "policy {:?}  ({})", s.name, self.origin);
        if !s.description.is_empty() {
            let _ = writeln!(o, "  {}", s.description);
        }
        let _ = writeln!(o, "\nlimits");
        let _ = writeln!(o, "  wall_clock      {}", fmt_duration(l.wall_clock));
        let _ = writeln!(o, "  fuel            {}", fmt_fuel(l.fuel));
        let _ = writeln!(o, "  memory          {}", l.memory);
        let _ = writeln!(o, "  stdout/stderr   {} / {}", l.stdout, l.stderr);
        let _ = writeln!(
            o,
            "  artifacts       {} files, {} total",
            l.artifact_count, l.artifact_bytes
        );
        let _ = writeln!(o, "  inputs          {} total", l.input_bytes);
        let _ = writeln!(o, "\nfilesystem");
        let _ = writeln!(o, "  {:<24} ro  (request inputs)", s.filesystem.inputs);
        let _ = writeln!(
            o,
            "  {:<24} rw  (returned as artifacts)",
            s.filesystem.outputs
        );
        for m in &s.filesystem.mounts {
            let _ = writeln!(
                o,
                "  {:<24} {}  ← {}",
                m.guest,
                m.mode.as_str(),
                m.host.display()
            );
        }
        let _ = writeln!(o, "\nenv");
        if s.env.is_empty() {
            let _ = writeln!(o, "  (none)");
        }
        for k in s.env.keys() {
            let _ = writeln!(o, "  {k}");
        }
        let _ = writeln!(o, "\nnetwork");
        if !s.network.grants_anything() {
            let _ = writeln!(o, "  (none)");
        }
        for r in &s.network.http {
            let _ = writeln!(
                o,
                "  http {}:{} {} {}",
                r.host,
                r.port,
                r.methods.join(","),
                r.path_prefix
            );
        }
        for r in &s.network.tcp {
            let _ = writeln!(o, "  tcp  {}:{}", r.host, r.port);
        }
        let _ = writeln!(
            o,
            "\nsession   {}",
            if s.session.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        let _ = writeln!(o, "audit     log_code = {}", s.audit.log_code);

        let warnings = self.warnings();
        if !warnings.is_empty() {
            let _ = writeln!(o, "\nwarnings");
            for w in warnings {
                let _ = writeln!(o, "  ! {w}");
            }
        }
        o
    }

    /// Non-fatal concerns an operator should see.
    pub fn warnings(&self) -> Vec<String> {
        let s = &self.spec;
        let mut w = Vec::new();
        for m in s
            .filesystem
            .mounts
            .iter()
            .filter(|m| m.mode == MountMode::ReadWrite)
        {
            w.push(format!(
                "{} is a read-write host mount: guest code can modify {}",
                m.guest,
                m.host.display()
            ));
        }
        if s.audit.log_code {
            w.push(
                "audit.log_code = true: submitted code is written to the audit log (redacted)"
                    .into(),
            );
        }
        if s.limits.memory > ByteSize::gib(1) {
            w.push(format!(
                "memory limit {} is high for a sandbox tier",
                s.limits.memory
            ));
        }
        if s.network.grants_anything() {
            w.push("network rules require the network broker (Phase 4) and are refused by this version".into());
        }
        if s.session.enabled {
            w.push("sessions require Phase 5 and are refused by this version".into());
        }
        w
    }

    /// Where it was loaded from (`<built-in>` for the default).
    pub fn origin(&self) -> &str {
        &self.origin
    }
    /// Full validated content.
    pub fn spec(&self) -> &PolicySpec {
        &self.spec
    }
    /// Policy name.
    pub fn name(&self) -> &str {
        &self.spec.name
    }
    /// Resource limits.
    pub fn limits(&self) -> &Limits {
        &self.spec.limits
    }
    /// Filesystem layout.
    pub fn filesystem(&self) -> &Filesystem {
        &self.spec.filesystem
    }
    /// Literal env vars for the guest.
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.spec.env
    }
    /// Network section.
    pub fn network(&self) -> &NetworkPolicy {
        &self.spec.network
    }
    /// Session section.
    pub fn session(&self) -> &SessionPolicy {
        &self.spec.session
    }
    /// Audit section.
    pub fn audit(&self) -> &AuditPolicy {
        &self.spec.audit
    }
}

/// Hardened YAML options (rule R12).
fn yaml_options() -> serde_saphyr::Options {
    let mut budget = serde_saphyr::Budget::default();
    budget.max_reader_input_bytes = Some(MAX_POLICY_FILE_BYTES);
    budget.max_aliases = 0;
    budget.max_anchors = 0;
    budget.max_depth = 16;
    budget.max_documents = 1;
    budget.max_nodes = 20_000;
    budget.max_total_scalar_bytes = MAX_POLICY_FILE_BYTES;
    budget.max_merge_keys = 0;
    let mut o = serde_saphyr::Options::default();
    o.budget = Some(budget);
    o.duplicate_keys = serde_saphyr::DuplicateKeyPolicy::Error;
    o.merge_keys = serde_saphyr::MergeKeyPolicy::AsOrdinary;
    o.reject_unsupported_tags = true;
    o
}

/// Collects every issue instead of stopping at the first (rule R9).
struct V<'a> {
    origin: &'a str,
    errs: Vec<PolicyError>,
}

impl V<'_> {
    fn err(&mut self, path: impl Into<String>, msg: impl Into<String>) {
        self.errs.push(PolicyError::Invalid {
            origin: self.origin.into(),
            path: path.into(),
            msg: msg.into(),
        });
    }

    fn ranged<T: PartialOrd + Copy>(
        &mut self,
        path: &str,
        v: T,
        (lo, hi): (T, T),
        show: impl Fn(T) -> String,
    ) -> T {
        if v < lo || v > hi {
            self.err(
                path,
                format!(
                    "{} is outside the allowed range {} ..= {}",
                    show(v),
                    show(lo),
                    show(hi)
                ),
            );
        }
        v
    }

    fn bytes(
        &mut self,
        path: &str,
        q: Option<&Quantity>,
        default: ByteSize,
        r: (ByteSize, ByteSize),
    ) -> ByteSize {
        match q.map(|q| parse_bytes(&q.0)) {
            None => default,
            Some(Ok(b)) => self.ranged(path, b, r, |b| b.to_string()),
            Some(Err(e)) => {
                self.err(path, e);
                default
            }
        }
    }

    fn duration(
        &mut self,
        path: &str,
        q: Option<&Quantity>,
        default: Duration,
        r: (Duration, Duration),
    ) -> Duration {
        match q.map(|q| parse_duration(&q.0)) {
            None => default,
            Some(Ok(d)) => self.ranged(path, d, r, fmt_duration),
            Some(Err(e)) => {
                self.err(path, e);
                default
            }
        }
    }

    /// Normalize and check an absolute guest path. Returns the normalized form.
    fn guest_path(&mut self, path: &str, p: &str) -> Option<String> {
        let bad = |m: &str| Some(m.to_string());
        let problem = if !p.starts_with('/') {
            bad("must be an absolute guest path starting with '/'")
        } else if p.len() > 256 {
            bad("is longer than 256 bytes")
        } else if p.contains('\\') || p.contains('\0') || p.chars().any(char::is_control) {
            bad("must not contain backslashes or control characters")
        } else if p.split('/').any(|c| c == "." || c == "..") {
            bad("must not contain '.' or '..' components")
        } else if p.contains("//") {
            bad("must not contain empty components ('//')")
        } else {
            None
        };
        if let Some(m) = problem {
            self.err(path, format!("{p:?} {m}"));
            return None;
        }
        let n = p.trim_end_matches('/');
        Some(if n.is_empty() { "/".into() } else { n.into() })
    }
}

/// `a` equals `b` or one contains the other (path-component aware).
fn overlaps(a: &str, b: &str) -> bool {
    let within = |x: &str, y: &str| y == "/" || x == y || x.starts_with(&format!("{y}/"));
    within(a, b) || within(b, a)
}

fn validate(raw: RawPolicy, origin: &str, opts: &LoadOptions) -> Result<Policy, PolicyErrors> {
    let mut v = V {
        origin,
        errs: Vec::new(),
    };

    if raw.version != SCHEMA_VERSION {
        v.err(
            "version",
            format!(
                "unsupported schema version {} (this build supports {SCHEMA_VERSION})",
                raw.version
            ),
        );
    }
    let name_ok = !raw.name.is_empty()
        && raw.name.len() <= 63
        && raw
            .name
            .starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && raw
            .name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if !name_ok {
        v.err(
            "name",
            format!("{:?} must match [a-z0-9][a-z0-9_-]{{0,62}}", raw.name),
        );
    }
    let description = raw.description.unwrap_or_default();
    if description.len() > 1024 {
        v.err("description", "is longer than 1024 bytes");
    }

    // limits
    let rl = raw.limits.unwrap_or_default();
    let d = Limits::default();
    let fuel = match rl.fuel.as_ref().map(|q| parse_fuel(&q.0)) {
        None => d.fuel,
        Some(Ok(f)) => v.ranged("limits.fuel", f, range::FUEL, fmt_fuel),
        Some(Err(e)) => {
            v.err("limits.fuel", e);
            d.fuel
        }
    };
    let limits = Limits {
        wall_clock: v.duration(
            "limits.wall_clock",
            rl.wall_clock.as_ref(),
            d.wall_clock,
            range::WALL_CLOCK,
        ),
        fuel,
        memory: v.bytes("limits.memory", rl.memory.as_ref(), d.memory, range::MEMORY),
        stdout: v.bytes("limits.stdout", rl.stdout.as_ref(), d.stdout, range::STDIO),
        stderr: v.bytes("limits.stderr", rl.stderr.as_ref(), d.stderr, range::STDIO),
        artifact_count: rl
            .artifact_count
            .map(|c| {
                v.ranged("limits.artifact_count", c, range::ARTIFACT_COUNT, |c| {
                    c.to_string()
                })
            })
            .unwrap_or(d.artifact_count),
        artifact_bytes: v.bytes(
            "limits.artifact_bytes",
            rl.artifact_bytes.as_ref(),
            d.artifact_bytes,
            range::ARTIFACT_BYTES,
        ),
        input_bytes: v.bytes(
            "limits.input_bytes",
            rl.input_bytes.as_ref(),
            d.input_bytes,
            range::INPUT_BYTES,
        ),
    };

    // filesystem
    let rf = raw.filesystem.unwrap_or_default();
    let inputs = v
        .guest_path("filesystem.inputs", rf.inputs.as_deref().unwrap_or("/in"))
        .unwrap_or_else(|| "/in".into());
    let outputs = v
        .guest_path(
            "filesystem.outputs",
            rf.outputs.as_deref().unwrap_or("/out"),
        )
        .unwrap_or_else(|| "/out".into());
    let mut taken: Vec<(String, String)> = vec![
        (STDLIB_GUEST_PATH.into(), "the Python stdlib".into()),
        (DEVICE_GUEST_PATH.into(), "sandbox devices".into()),
        (CODE_GUEST_PATH.into(), "the submitted program".into()),
    ];
    for (p, label, field) in [
        (&inputs, "filesystem.inputs", "filesystem.inputs"),
        (&outputs, "filesystem.outputs", "filesystem.outputs"),
    ] {
        if p == "/" {
            v.err(field, "cannot be '/'");
        } else if let Some((t, what)) = taken.iter().find(|(t, _)| overlaps(p, t)) {
            v.err(field, format!("{p:?} overlaps {t:?} ({what})"));
        }
        taken.push((p.clone(), label.into()));
    }
    let forbidden: Vec<PathBuf> = opts
        .forbidden_host_roots
        .iter()
        .map(|r| std::fs::canonicalize(r).unwrap_or_else(|_| r.clone()))
        .collect();
    let mut mounts = Vec::new();
    for (i, m) in rf.mount.unwrap_or_default().into_iter().enumerate() {
        let path = format!("filesystem.mount[{i}]");
        let Some(guest) = v.guest_path(&format!("{path}.guest"), &m.guest) else {
            continue;
        };
        if guest == "/" {
            v.err(format!("{path}.guest"), "cannot mount over '/'");
            continue;
        }
        if let Some((t, what)) = taken.iter().find(|(t, _)| overlaps(&guest, t)) {
            v.err(
                format!("{path}.guest"),
                format!("{guest:?} overlaps {t:?} ({what}); mounts may not nest or repeat"),
            );
            continue;
        }
        let host_raw = Path::new(&m.host);
        if !host_raw.is_absolute()
            || host_raw
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            v.err(
                format!("{path}.host"),
                format!("{:?} must be an absolute path without '..'", m.host),
            );
            continue;
        }
        let host = match std::fs::canonicalize(host_raw) {
            Ok(h) if h.is_dir() => h,
            Ok(_) => {
                v.err(
                    format!("{path}.host"),
                    format!("{:?} is not a directory", m.host),
                );
                continue;
            }
            Err(e) => {
                v.err(format!("{path}.host"), format!("{:?}: {e}", m.host));
                continue;
            }
        };
        if let Some(f) = forbidden
            .iter()
            .find(|f| host.starts_with(f) || f.starts_with(&host))
        {
            v.err(
                format!("{path}.host"),
                format!(
                    "{:?} overlaps a sandboxd-internal directory ({})",
                    m.host,
                    f.display()
                ),
            );
            continue;
        }
        taken.push((guest.clone(), path.clone()));
        mounts.push(Mount {
            guest,
            host,
            mode: match m.mode {
                RawMode::Ro => MountMode::ReadOnly,
                RawMode::Rw => MountMode::ReadWrite,
            },
        });
    }
    if mounts.len() > 32 {
        v.err("filesystem.mount", "at most 32 mounts");
    }

    // env
    let env = raw.env.unwrap_or_default();
    if env.len() > 64 {
        v.err("env", "at most 64 variables");
    }
    for (k, val) in &env {
        let key_ok = k.starts_with(|c: char| c.is_ascii_uppercase() || c == '_')
            && k.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            && k.len() <= 128;
        if !key_ok {
            v.err(
                format!("env.{k}"),
                "key must match [A-Z_][A-Z0-9_]* (max 128)",
            );
        } else if RESERVED_ENV.contains(&k.as_str()) || k.starts_with("SANDBOXD_") {
            v.err(
                format!("env.{k}"),
                "is controlled by the sandbox runtime and cannot be set by a policy",
            );
        }
        // Never echo the value (it may be sensitive).
        if val.len() > 4096 {
            v.err(format!("env.{k}"), "value is longer than 4096 bytes");
        }
        if val.contains('\0') {
            v.err(format!("env.{k}"), "value contains a NUL byte");
        }
    }

    // network (validated now, refused by ensure_supported until Phase 4)
    let rn = raw.network.unwrap_or_default();
    let nd = NetworkPolicy::default();
    let net_cap = (ByteSize(0), ByteSize::gib(1));
    let mut network = NetworkPolicy {
        allow_private_ips: rn.allow_private_ips.unwrap_or(false),
        max_requests: rn.max_requests.unwrap_or(nd.max_requests),
        max_request_bytes: v.bytes(
            "network.max_request_bytes",
            rn.max_request_bytes.as_ref(),
            nd.max_request_bytes,
            net_cap,
        ),
        max_response_bytes: v.bytes(
            "network.max_response_bytes",
            rn.max_response_bytes.as_ref(),
            nd.max_response_bytes,
            net_cap,
        ),
        max_total_bytes: v.bytes(
            "network.max_total_bytes",
            rn.max_total_bytes.as_ref(),
            nd.max_total_bytes,
            net_cap,
        ),
        http: Vec::new(),
        tcp: Vec::new(),
    };
    for (i, r) in rn.http.unwrap_or_default().into_iter().enumerate() {
        let path = format!("network.http[{i}]");
        let host = r.host.to_ascii_lowercase();
        if !valid_host(&host) {
            v.err(
                format!("{path}.host"),
                format!(
                    "{:?} must be a hostname or IP literal (no scheme, port or path)",
                    r.host
                ),
            );
        }
        let port = r.port.unwrap_or(443);
        if port == 0 {
            v.err(format!("{path}.port"), "must be 1..=65535");
        }
        let mut methods: Vec<String> = r
            .methods
            .unwrap_or_else(|| vec!["GET".into()])
            .iter()
            .map(|m| m.to_ascii_uppercase())
            .collect();
        methods.sort();
        methods.dedup();
        for m in &methods {
            if !["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].contains(&m.as_str()) {
                v.err(
                    format!("{path}.methods"),
                    format!("unsupported method {m:?}"),
                );
            }
        }
        let path_prefix = r.path_prefix.unwrap_or_else(|| "/".into());
        if !path_prefix.starts_with('/') || path_prefix.contains("..") {
            v.err(
                format!("{path}.path_prefix"),
                "must start with '/' and not contain '..'",
            );
        }
        network.http.push(HttpRule {
            host,
            port,
            methods,
            path_prefix,
        });
    }
    for (i, r) in rn.tcp.unwrap_or_default().into_iter().enumerate() {
        let path = format!("network.tcp[{i}]");
        let host = r.host.to_ascii_lowercase();
        if !valid_host(&host) {
            v.err(
                format!("{path}.host"),
                format!("{:?} must be a hostname or IP literal", r.host),
            );
        }
        if r.port == 0 {
            v.err(format!("{path}.port"), "must be 1..=65535");
        }
        network.tcp.push(TcpRule { host, port: r.port });
    }

    // session (validated now, refused by ensure_supported until Phase 5)
    let rs = raw.session.unwrap_or_default();
    let sd = SessionPolicy::default();
    let session = SessionPolicy {
        enabled: rs.enabled.unwrap_or(false),
        idle_ttl: v.duration(
            "session.idle_ttl",
            rs.idle_ttl.as_ref(),
            sd.idle_ttl,
            range::IDLE_TTL,
        ),
        max_sessions: rs
            .max_sessions
            .map(|n| v.ranged("session.max_sessions", n, (1, 10_000), |n| n.to_string()))
            .unwrap_or(sd.max_sessions),
    };

    let audit = AuditPolicy {
        log_code: raw.audit.unwrap_or_default().log_code.unwrap_or(false),
    };

    if !v.errs.is_empty() {
        return Err(PolicyErrors(v.errs));
    }
    Ok(Policy {
        spec: PolicySpec {
            name: raw.name,
            description,
            limits,
            filesystem: Filesystem {
                inputs,
                outputs,
                mounts,
            },
            env,
            network,
            session,
            audit,
        },
        origin: origin.into(),
    })
}

/// Hostname (`a.b-c.example`) or IPv4/IPv6 literal. No wildcards, schemes, ports or paths.
fn valid_host(h: &str) -> bool {
    if h.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}
