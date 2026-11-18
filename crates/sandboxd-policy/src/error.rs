//! Policy errors. Messages name the origin file and field path, and never include env values.

use std::fmt;

/// One problem with a policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// Syntax / type error from the TOML or YAML parser (includes line and column).
    #[error("{origin}: {msg}")]
    Parse { origin: String, msg: String },
    /// A value that parsed but violates a rule.
    #[error("{origin}: {path}: {msg}")]
    Invalid {
        origin: String,
        path: String,
        msg: String,
    },
    /// An override tried to raise a limit above the policy (rule R8).
    #[error("override would widen {field}: policy allows {policy}, requested {requested}")]
    WouldWiden {
        field: &'static str,
        policy: String,
        requested: String,
    },
    /// Unknown policy name. There is never a fallback to another policy.
    #[error("policy {0:?} not found")]
    NotFound(String),
    /// The policy grants a capability this version cannot enforce (U1 design Q3).
    #[error("{origin}: {feature}")]
    Unsupported { origin: String, feature: String },
    /// Filesystem problem while loading.
    #[error("{origin}: {msg}")]
    Io { origin: String, msg: String },
}

/// Every problem found (loading reports all of them, not just the first: rule R9).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyErrors(pub Vec<PolicyError>);

impl PolicyErrors {
    /// The individual errors.
    pub fn iter(&self) -> impl Iterator<Item = &PolicyError> {
        self.0.iter()
    }
    /// Number of errors.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// `true` if there are no errors.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for PolicyErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.as_slice() {
            [one] => write!(f, "{one}"),
            many => {
                write!(f, "{} policy errors:", many.len())?;
                for e in many {
                    write!(f, "\n  - {e}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for PolicyErrors {}

impl From<PolicyError> for PolicyErrors {
    fn from(e: PolicyError) -> Self {
        Self(vec![e])
    }
}
