//! Secret redaction for free-text audit fields (rule A3).

use std::borrow::Cow;

use regex::Regex;

/// One redaction rule: matches are replaced using `template` (regex replacement syntax).
#[derive(Debug, Clone)]
struct Rule {
    re: Regex,
    template: String,
}

/// Replaces secret-looking substrings with `[REDACTED:<kind>]`.
#[derive(Debug, Clone)]
pub struct Redactor {
    rules: Vec<Rule>,
}

/// Error for an invalid operator-supplied pattern.
#[derive(Debug)]
pub struct PatternError {
    /// Operator-chosen pattern name.
    pub name: String,
    /// Regex compile error.
    pub error: regex::Error,
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid redaction pattern {:?}: {}",
            self.name, self.error
        )
    }
}
impl std::error::Error for PatternError {}

/// (kind, regex, replacement template). Order matters: specific before generic.
const BUILTIN: &[(&str, &str, &str)] = &[
    (
        "pem",
        r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED:pem]",
    ),
    (
        "bearer",
        r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*",
        "Bearer [REDACTED:bearer]",
    ),
    (
        "anthropic",
        r"\bsk-ant-[A-Za-z0-9_\-]{10,}",
        "[REDACTED:anthropic]",
    ),
    ("api_key", r"\bsk-[A-Za-z0-9_\-]{16,}", "[REDACTED:api_key]"),
    (
        "github",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
        "[REDACTED:github]",
    ),
    ("aws", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "[REDACTED:aws]"),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}",
        "[REDACTED:jwt]",
    ),
    (
        "slack",
        r"\bxox[abposr]-[A-Za-z0-9-]{10,}",
        "[REDACTED:slack]",
    ),
    (
        "kv",
        r#"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)(\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;&]+)"#,
        "${1}${2}[REDACTED:kv]",
    ),
];

impl Redactor {
    /// Built-in patterns only.
    pub fn new() -> Self {
        let rules = BUILTIN
            .iter()
            .map(|(_, re, t)| Rule {
                // Built-in patterns are constants covered by tests.
                re: Regex::new(re).unwrap_or_else(|e| panic!("builtin redaction regex: {e}")),
                template: (*t).to_string(),
            })
            .collect();
        Self { rules }
    }

    /// No redaction at all (tests only; never used by the server).
    pub fn disabled() -> Self {
        Self { rules: Vec::new() }
    }

    /// Built-ins plus operator patterns `(name, regex)`; each match → `[REDACTED:<name>]`.
    pub fn with_extra<'a>(
        extra: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, PatternError> {
        let mut r = Self::new();
        for (name, pat) in extra {
            let re = Regex::new(pat).map_err(|error| PatternError {
                name: name.to_string(),
                error,
            })?;
            r.rules.push(Rule {
                re,
                template: format!("[REDACTED:{}]", name.replace('$', "")),
            });
        }
        Ok(r)
    }

    /// Redact `s`; borrows when nothing matched.
    pub fn redact<'s>(&self, s: &'s str) -> Cow<'s, str> {
        let mut out: Cow<'s, str> = Cow::Borrowed(s);
        for rule in &self.rules {
            if rule.re.is_match(&out) {
                out = Cow::Owned(
                    rule.re
                        .replace_all(&out, rule.template.as_str())
                        .into_owned(),
                );
            }
        }
        out
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> String {
        Redactor::new().redact(s).into_owned()
    }

    #[test]
    fn redacts_known_secret_shapes() {
        // All fake, shaped like real credentials.
        let cases = [
            (
                "Authorization: Bearer abc.DEF-123_xyz==",
                "[REDACTED:bearer]",
            ),
            (
                "key sk-ant-api03-AAAAAAAAAAAAAAAAAAAA",
                "[REDACTED:anthropic]",
            ),
            ("OPENAI sk-proj-ABCDEFGHIJKLMNOPQRST", "[REDACTED:api_key]"),
            ("ghp_0123456789abcdefghijABCDEFGHIJ", "[REDACTED:github]"),
            (
                "github_pat_11ABCDEFG0123456789_abcdefghijk",
                "[REDACTED:github]",
            ),
            ("id AKIAIOSFODNN7EXAMPLE end", "[REDACTED:aws]"),
            (
                "t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
                "[REDACTED:jwt]",
            ),
            ("xoxb-1234567890-abcdefghij", "[REDACTED:slack]"),
            ("password=hunter2", "password=[REDACTED:kv]"),
            ("api_key: \"s3cr3t value\"", "api_key: [REDACTED:kv]"),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
                "[REDACTED:pem]",
            ),
        ];
        for (input, expect) in cases {
            let out = r(input);
            assert!(
                out.contains(expect),
                "{input:?} → {out:?}, expected {expect:?}"
            );
        }
        assert!(!r("ghp_0123456789abcdefghijABCDEFGHIJ").contains("0123456789"));
        assert!(!r("password=hunter2").contains("hunter2"));
    }

    #[test]
    fn leaves_ordinary_text_alone() {
        for s in [
            "/data/input.csv",
            "open denied: outside mounts",
            "skeleton key",
            "tokenizer",
        ] {
            assert!(matches!(Redactor::new().redact(s), Cow::Borrowed(_)), "{s}");
        }
    }

    #[test]
    fn operator_patterns() {
        let red = Redactor::with_extra([("employee_id", r"\bEMP-\d{6}\b")]).expect("valid");
        assert_eq!(
            red.redact("user EMP-123456 ran"),
            "user [REDACTED:employee_id] ran"
        );
        assert!(Redactor::with_extra([("bad", "(")]).is_err());
    }
}
