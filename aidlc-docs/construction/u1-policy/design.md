# U1 Policy — Functional, NFR & Infrastructure Design

Depth is scaled to the unit: functional design is complete, and the NFR/infra sections are brief. Open choices are in `../u1-u2-design-questions.md`.

## 1. Schema v1 (TOML shown; YAML is the same structure)

```toml
version = 1                       # required; only 1 accepted
name = "data-analysis"            # required; must equal the file stem; [a-z0-9][a-z0-9_-]{0,62}
description = "Pandas-free CSV crunching with a read-only dataset"

[limits]                          # every field optional; defaults shown
wall_clock      = "5s"            # 10ms ..= 1h
fuel            = "20G"           # instruction budget; 1M ..= 1T; ×1000 suffixes. Default raised from 2G in U4 (≈4 s CPU)
memory          = "256MiB"        # 1MiB ..= 4GiB (wasm32 ceiling)
stdout          = "1MiB"          # 0 ..= 64MiB
stderr          = "256KiB"        # 0 ..= 64MiB
artifact_count  = 16              # 0 ..= 1000
artifact_bytes  = "16MiB"         # 0 ..= 1GiB, total of /out
input_bytes     = "16MiB"         # total of request-supplied files; 0 ..= 1GiB

[filesystem]
inputs  = "/in"                   # request-supplied files, always read-only
outputs = "/out"                  # always read-write, size-capped, returned as artifacts

[[filesystem.mount]]
guest = "/data"                   # absolute, normalized, no "..", not reserved, not nested
host  = "/srv/datasets"           # must exist + be a directory at load; canonicalized
mode  = "ro"                      # "ro" | "rw"

[env]                             # literal values only; key ~ [A-Z_][A-Z0-9_]*; max 64 vars, 4KiB each
TZ = "UTC"

[network]                         # Phase 4. Parsed and validated now (see Q3 for load behaviour)
allow_private_ips = false
max_requests = 0
http = [ { host = "api.internal.company.com", port = 443, methods = ["GET"], path_prefix = "/v1/" } ]
tcp  = [ { host = "db.internal", port = 5432 } ]

[session]                         # Phase 5. Same treatment as [network]
enabled  = false
idle_ttl = "5m"

[audit]
log_code = false                  # true → full code (redacted, truncated to 64KiB) in run.start
```

**Built-in `default` policy:** all limit defaults, `/in` + `/out` only, no mounts, no env vars, no network, no session. An operator file named `default.*` replaces it, and `policy list` marks it as `(overrides built-in)`.

## 2. Business rules
| ID | Rule |
|---|---|
| R1 | Unknown keys at any depth → error (`deny_unknown_fields`), with the key path in the message. |
| R2 | Units are case-insensitive. Bytes: `B, K/KB/KiB, M/MB/MiB, G/GB/GiB` (see Q2). Durations: `ms, s, m, h`, decimals allowed (`1.5s`). Bare integers are bytes, or fuel units for `fuel`. |
| R3 | Out-of-range values → error that states the allowed range. No silent clamping anywhere. |
| R4 | Reserved guest paths that can't be mounted over: `/in`, `/out` (or their configured values), `/usr/local/lib/python3.15`, `/dev/sandbox`, `/`. |
| R5 | Mounts can't nest, duplicate, or overlap reserved paths. `inputs` ≠ `outputs`. |
| R6 | `host` paths are canonicalized at load. A host path inside the sandboxd cache or audit log directory → error. |
| R7 | `name` must equal the file stem. Two files with the same stem (e.g. `a.toml` + `a.yaml`) → error. |
| R8 | **Tighten-only overrides:** every override must be ≤ the policy value. A larger value → `PolicyError::WouldWiden { field, policy, requested }`. Overrides can't add mounts, env vars or hosts; there are no fields for that. |
| R9 | Loading is all-or-nothing. If any file in the policy directory is invalid, startup fails and lists every error, not just the first. |
| R10 | `explain()` prints the effective policy with resolved values, plus warnings: rw host mounts, `log_code=true`, memory > 1GiB, and Phase 4/5 sections. |
| R11 | TOML and YAML parse into the same `RawPolicy` serde struct and then the same validation. Parity holds by construction and is proven by golden tests. |
| R12 | YAML safety: limits on aliases, anchors and recursion depth; a 1MiB maximum file size (also applied to TOML); no YAML tags. A duplicate key → error. |

## 3. Types (public API)
```rust
pub struct Policy { /* private fields, validated */ }        // Clone, Debug, PartialEq, Serialize (for explain / golden)
impl Policy {
    pub fn from_toml(src: &str, origin: &str) -> Result<Policy, PolicyErrors>;
    pub fn from_yaml(src: &str, origin: &str) -> Result<Policy, PolicyErrors>;
    pub fn from_path(path: &Path) -> Result<Policy, PolicyErrors>;     // by extension
    pub fn builtin_default() -> Policy;
    pub fn tighten(&self, o: &Overrides) -> Result<Policy, PolicyError>;
    pub fn explain(&self) -> String;
    pub fn name(&self) -> &str; pub fn limits(&self) -> &Limits; pub fn mounts(&self) -> &[Mount];
    pub fn env(&self) -> &BTreeMap<String,String>; pub fn network(&self) -> &NetworkPolicy; /* … */
}
pub struct Limits { pub wall_clock: Duration, pub fuel: u64, pub memory: ByteSize, pub stdout: ByteSize, pub stderr: ByteSize,
                    pub artifact_count: u32, pub artifact_bytes: ByteSize, pub input_bytes: ByteSize }
pub struct Overrides { pub wall_clock: Option<Duration>, pub fuel: Option<u64>, pub memory: Option<ByteSize>, /* … limits only */ }
pub struct PolicyDir { /* name → Arc<Policy> */ }
impl PolicyDir { pub fn load(dir: Option<&Path>) -> Result<PolicyDir, PolicyErrors>; pub fn get(&self, name:&str) -> Result<Arc<Policy>, PolicyError>; pub fn list(&self) -> Vec<PolicySummary>; }
pub enum PolicyError { Parse{origin, path, msg}, Invalid{origin, path, msg}, WouldWiden{field, policy, requested}, NotFound(String), Unsupported{origin, feature}, Io{..} }
```
`ByteSize` and `parse_duration` are small in-crate parsers with no humantime dependency, so the units in R2 are exact and documented.

## 4. NFR (scaled)
- **Security:** `#![forbid(unsafe_code)]`. Size and alias limits (R12). Errors never echo `env` values, only keys. Loading never follows a symlink that leaves the policy directory.
- **Performance:** loading is startup-only. `get()` is an `Arc` clone and lock-free.
- **Testing:** unit tests per rule (R1–R12); a TOML↔YAML golden corpus (`tests/golden/*.{toml,yaml}` → identical `Policy`); property tests (proptest) for unit parsers and for `tighten()`, which must never widen.

## 5. Infrastructure
No infrastructure. New dependencies: `serde`, `toml` (1.x), the YAML crate (Q1), `serde_path_to_error`, and `proptest` (dev only).
