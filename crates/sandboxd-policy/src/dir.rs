//! Policy directory loading (rules R7, R9; Q3 support gate).

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{
    error::{PolicyError, PolicyErrors},
    model::{LoadOptions, Policy},
};

/// Summary row for `policy list` / `GET /v1/policies` / MCP `list_policies`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySummary {
    pub name: String,
    pub description: String,
    pub origin: String,
    /// `true` if an operator file replaced the built-in `default`.
    pub overrides_builtin: bool,
}

/// All policies the server can serve. Immutable after load; `get` is an `Arc` clone.
#[derive(Debug, Clone)]
pub struct PolicyDir {
    policies: BTreeMap<String, Arc<Policy>>,
    default_overridden: bool,
}

impl PolicyDir {
    /// Only the built-in `default` policy.
    pub fn builtin_only() -> Self {
        let mut policies = BTreeMap::new();
        policies.insert("default".to_string(), Arc::new(Policy::builtin_default()));
        Self {
            policies,
            default_overridden: false,
        }
    }

    /// Load every `*.toml`, `*.yaml`, `*.yml` in `dir` (non-recursive, hidden files skipped).
    /// All-or-nothing: any invalid or unsupported policy fails the whole load, listing every error.
    /// `dir` itself is added to the forbidden mount roots.
    pub fn load(dir: &Path, opts: &LoadOptions) -> Result<Self, PolicyErrors> {
        let origin = dir.display().to_string();
        let canon_dir = std::fs::canonicalize(dir).map_err(|e| PolicyError::Io {
            origin: origin.clone(),
            msg: e.to_string(),
        })?;
        let mut opts = opts.clone();
        opts.forbidden_host_roots.push(canon_dir.clone());

        let mut files: Vec<PathBuf> = Vec::new();
        let entries = std::fs::read_dir(&canon_dir).map_err(|e| PolicyError::Io {
            origin: origin.clone(),
            msg: e.to_string(),
        })?;
        let mut errs = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    errs.push(PolicyError::Io {
                        origin: origin.clone(),
                        msg: e.to_string(),
                    });
                    continue;
                }
            };
            let path = entry.path();
            let fname = entry.file_name().to_string_lossy().into_owned();
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase);
            if fname.starts_with('.') || !matches!(ext.as_deref(), Some("toml" | "yaml" | "yml")) {
                continue;
            }
            // A symlinked policy must still resolve inside the policy directory.
            match std::fs::canonicalize(&path) {
                Ok(real) if real.starts_with(&canon_dir) && real.is_file() => files.push(path),
                Ok(_) => errs.push(PolicyError::Io {
                    origin: path.display().to_string(),
                    msg: "resolves outside the policy directory or is not a regular file".into(),
                }),
                Err(e) => errs.push(PolicyError::Io {
                    origin: path.display().to_string(),
                    msg: e.to_string(),
                }),
            }
        }
        files.sort();

        let mut by_name: BTreeMap<String, Arc<Policy>> = BTreeMap::new();
        for f in &files {
            match Policy::from_path(f, &opts) {
                Ok(p) => {
                    if let Err(e) = p.ensure_supported() {
                        errs.extend(e.0);
                        continue;
                    }
                    if !opts.network_enabled && p.network().grants_anything() {
                        errs.push(PolicyError::Unsupported {
                            origin: p.origin().to_string(),
                            feature: "this policy grants network egress, but network access is disabled on this server ([network] enabled = false)".into(),
                        });
                        continue;
                    }
                    if let Some(prev) = by_name.get(p.name()) {
                        errs.push(PolicyError::Invalid {
                            origin: f.display().to_string(),
                            path: "name".into(),
                            msg: format!(
                                "duplicate policy name {:?} (also defined in {})",
                                p.name(),
                                prev.origin()
                            ),
                        });
                        continue;
                    }
                    by_name.insert(p.name().to_string(), Arc::new(p));
                }
                Err(e) => errs.extend(e.0),
            }
        }
        if !errs.is_empty() {
            return Err(PolicyErrors(errs));
        }
        let default_overridden = by_name.contains_key("default");
        by_name
            .entry("default".to_string())
            .or_insert_with(|| Arc::new(Policy::builtin_default()));
        Ok(Self {
            policies: by_name,
            default_overridden,
        })
    }

    /// Look up by name. Unknown names are an error, never a fallback.
    pub fn get(&self, name: &str) -> Result<Arc<Policy>, PolicyError> {
        self.policies
            .get(name)
            .cloned()
            .ok_or_else(|| PolicyError::NotFound(name.to_string()))
    }

    /// Summaries, sorted by name.
    pub fn list(&self) -> Vec<PolicySummary> {
        self.policies
            .values()
            .map(|p| PolicySummary {
                name: p.name().to_string(),
                description: p.spec().description.clone(),
                origin: p.origin().to_string(),
                overrides_builtin: p.name() == "default" && self.default_overridden,
            })
            .collect()
    }

    /// Number of policies (including `default`).
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Always `false`: `default` is always present.
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}
