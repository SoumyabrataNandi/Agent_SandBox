//! Bearer-token auth (U5 design §4, Q5).

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Who made a request. Recorded as `principal` in every audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal(pub String);

impl Principal {
    /// For local transports without auth (stdio MCP, CLI).
    pub fn local(kind: &str) -> Self {
        Principal(kind.to_string())
    }
}

/// A configured token: a name and the SHA-256 of the secret (no plaintext at rest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEntry {
    pub name: String,
    pub sha256: [u8; 32],
}

/// All accepted tokens.
#[derive(Debug, Clone, Default)]
pub struct TokenSet {
    entries: Vec<TokenEntry>,
}

/// SHA-256 of a token, hex-encoded (what goes in `sandboxd.toml`).
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A fresh random token (244 bits from two UUIDv4s) with a recognizable prefix.
pub fn generate_token() -> String {
    format!(
        "sbx_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

impl TokenSet {
    /// Build from `(name, sha256-hex)` pairs and an optional plaintext env token.
    pub fn new(hashed: &[(String, String)], env_token: Option<&str>) -> Result<Self, String> {
        let mut entries = Vec::new();
        for (name, hex_hash) in hashed {
            let raw = hex::decode(hex_hash.trim())
                .map_err(|_| format!("auth token {name:?}: sha256 is not hex"))?;
            let sha256: [u8; 32] = raw
                .try_into()
                .map_err(|_| format!("auth token {name:?}: sha256 must be 32 bytes"))?;
            if name.is_empty() {
                return Err("auth token name must not be empty".into());
            }
            entries.push(TokenEntry {
                name: name.clone(),
                sha256,
            });
        }
        if let Some(t) = env_token.filter(|t| !t.is_empty()) {
            if t.len() < 16 {
                return Err("SANDBOXD_TOKEN must be at least 16 characters".into());
            }
            let digest: [u8; 32] = Sha256::digest(t.as_bytes()).into();
            entries.push(TokenEntry {
                name: sandboxd_audit::token_principal(t),
                sha256: digest,
            });
        }
        Ok(Self { entries })
    }

    /// `true` if no token is configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check a presented token. Compares against every entry in constant time.
    pub fn verify(&self, presented: &str) -> Option<Principal> {
        let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        let mut found: Option<&TokenEntry> = None;
        for e in &self.entries {
            if bool::from(e.sha256.ct_eq(&digest)) {
                found = Some(e);
            }
        }
        found.map(|e| Principal(e.name.clone()))
    }

    /// Extract `Bearer <token>` from an `Authorization` header value.
    pub fn bearer(header: &str) -> Option<&str> {
        let (scheme, rest) = header.split_once(' ')?;
        scheme
            .eq_ignore_ascii_case("bearer")
            .then(|| rest.trim())
            .filter(|t| !t.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_tokens() {
        let t = generate_token();
        assert!(t.starts_with("sbx_") && t.len() == 68);
        let set = TokenSet::new(
            &[("ci".into(), hash_token(&t))],
            Some("env-token-0123456789"),
        )
        .expect("set");
        assert_eq!(set.verify(&t), Some(Principal("ci".into())));
        assert!(
            set.verify("env-token-0123456789")
                .is_some_and(|p| p.0.starts_with("token:"))
        );
        assert_eq!(set.verify("wrong"), None);
        assert!(TokenSet::new(&[("x".into(), "zz".into())], None).is_err());
        assert!(TokenSet::new(&[], Some("short")).is_err());
        assert_eq!(TokenSet::bearer("Bearer abc"), Some("abc"));
        assert_eq!(TokenSet::bearer("bearer  abc "), Some("abc"));
        assert_eq!(TokenSet::bearer("Basic abc"), None);
        assert_eq!(TokenSet::bearer("Bearer "), None);
    }
}
