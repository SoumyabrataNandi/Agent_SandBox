//! Pure path logic: lexical resolution (V1) and input-name validation (I1).

/// Lexically resolve `rel` against `base` (an fd's guest path) inside the mount rooted at `mount`.
///
/// Returns the normalized absolute guest path, or `Err` if `..` climbs above the mount root.
/// No filesystem access: symlinks are left to cap-std, which is the primary enforcement.
pub fn resolve(mount: &str, base: &str, rel: &str) -> Result<String, String> {
    let mut parts: Vec<&str> = base.split('/').filter(|s| !s.is_empty()).collect();
    let floor = mount.split('/').filter(|s| !s.is_empty()).count();
    if rel.starts_with('/') {
        // p1 paths are always relative to a dirfd; an absolute one cannot be honoured.
        return Err(format!(
            "absolute path {rel:?} given relative to a directory"
        ));
    }
    for c in rel.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                if parts.len() <= floor {
                    return Err(format!("{rel:?} escapes mount {mount}"));
                }
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}

/// `true` if `path` is `root` or inside it (component-aware).
pub fn within(path: &str, root: &str) -> bool {
    root == "/" || path == root || path.starts_with(&format!("{root}/"))
}

const WINDOWS_RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Validate a request input name (rule I1): `/`-separated, ≤ 4 levels, safe on every OS.
pub fn validate_input_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 512 {
        return Err(format!("input name {name:?} must be 1..=512 bytes"));
    }
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() > 4 {
        return Err(format!(
            "input name {name:?} is nested deeper than 4 levels"
        ));
    }
    for p in parts {
        if p.is_empty() || p == "." || p == ".." {
            return Err(format!(
                "input name {name:?} has an empty, '.' or '..' component"
            ));
        }
        if p.len() > 128
            || !p
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(format!(
                "input name {name:?}: each component must match [A-Za-z0-9._-]{{1,128}}"
            ));
        }
        let stem = p.split('.').next().unwrap_or(p).to_ascii_lowercase();
        if WINDOWS_RESERVED.contains(&stem.as_str()) || p.ends_with('.') {
            return Err(format!("input name {name:?} uses a reserved name"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_normalizes_and_detects_escape() {
        assert_eq!(
            resolve("/data", "/data", "a/./b/../c.txt"),
            Ok("/data/a/c.txt".into())
        );
        assert_eq!(resolve("/data", "/data/sub", ".."), Ok("/data".into()));
        assert!(resolve("/data", "/data", "..").is_err());
        assert!(resolve("/data", "/data/sub", "../../x").is_err());
        assert!(resolve("/data", "/data", "/etc/passwd").is_err());
        assert_eq!(resolve("/", "/", "etc/passwd"), Ok("/etc/passwd".into()));
        assert!(resolve("/", "/", "../etc").is_err());
        assert_eq!(resolve("/", "/", ""), Ok("/".into()));
    }

    #[test]
    fn within_is_component_aware() {
        assert!(within("/out/a", "/out"));
        assert!(within("/out", "/out"));
        assert!(!within("/output", "/out"));
        assert!(within("/anything", "/"));
    }

    #[test]
    fn input_names() {
        for ok in ["a.csv", "data/2025/sales.csv", "x_y-z.1", "a/b/c/d.txt"] {
            assert!(validate_input_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "/abs",
            "a//b",
            "../x",
            "a/../b",
            "a/b/c/d/e",
            "sp ace",
            "CON",
            "nul.txt",
            "a\\b",
            "dot.",
            "ümlaut",
        ] {
            assert!(validate_input_name(bad).is_err(), "{bad:?}");
        }
    }
}
