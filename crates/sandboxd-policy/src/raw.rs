//! Serde shape shared by TOML and YAML (rule R11: parity by construction).
//! Every struct denies unknown fields (rule R1). Values with units are kept as [`Quantity`]
//! strings and parsed during validation, so errors can name the exact field.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Deserializer, de};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawPolicy {
    pub version: u32,
    pub name: String,
    pub description: Option<String>,
    pub limits: Option<RawLimits>,
    pub filesystem: Option<RawFilesystem>,
    pub env: Option<BTreeMap<String, String>>,
    pub network: Option<RawNetwork>,
    pub session: Option<RawSession>,
    pub audit: Option<RawAudit>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLimits {
    pub wall_clock: Option<Quantity>,
    pub fuel: Option<Quantity>,
    pub memory: Option<Quantity>,
    pub stdout: Option<Quantity>,
    pub stderr: Option<Quantity>,
    pub artifact_count: Option<u32>,
    pub artifact_bytes: Option<Quantity>,
    pub input_bytes: Option<Quantity>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawFilesystem {
    pub inputs: Option<String>,
    pub outputs: Option<String>,
    pub mount: Option<Vec<RawMount>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawMount {
    pub guest: String,
    pub host: String,
    pub mode: RawMode,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RawMode {
    Ro,
    Rw,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawNetwork {
    pub allow_private_ips: Option<bool>,
    pub max_requests: Option<u32>,
    pub max_request_bytes: Option<Quantity>,
    pub max_response_bytes: Option<Quantity>,
    pub max_total_bytes: Option<Quantity>,
    pub connect_timeout: Option<Quantity>,
    pub request_timeout: Option<Quantity>,
    pub http: Option<Vec<RawHttpRule>>,
    pub tcp: Option<Vec<RawTcpRule>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawHttpRule {
    pub scheme: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub methods: Option<Vec<String>>,
    pub path_prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawTcpRule {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawSession {
    pub enabled: Option<bool>,
    pub idle_ttl: Option<Quantity>,
    pub max_lifetime: Option<Quantity>,
    pub max_calls: Option<u32>,
    pub max_sessions: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawAudit {
    pub log_code: Option<bool>,
}

/// A number or a string with a unit, kept verbatim until validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Quantity(pub String);

impl<'de> Deserialize<'de> for Quantity {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl de::Visitor<'_> for V {
            type Value = Quantity;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a number or a string with a unit, e.g. \"2s\" or \"128MiB\"")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Quantity, E> {
                Ok(Quantity(v.to_string()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Quantity, E> {
                if v < 0 {
                    return Err(E::custom(format!("{v} must not be negative")));
                }
                Ok(Quantity(v.to_string()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Quantity, E> {
                if !(v.is_finite() && v >= 0.0) {
                    return Err(E::custom(format!("{v} must be a non-negative number")));
                }
                Ok(Quantity(v.to_string()))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Quantity, E> {
                Ok(Quantity(v.to_string()))
            }
        }
        d.deserialize_any(V)
    }
}
