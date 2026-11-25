//! Operator wheelhouse (cycle 5, FR-PK1): pure-Python wheels, validated on the host and extracted
//! once into the cache, next to a copy of the guest helpers. Python runs whose policy allows
//! packages mount that merged directory at [`sandboxd_policy::HELPER_GUEST_PATH`] instead of the
//! plain helpers.
//!
//! Why the helper directory: every interpreter path already has it on `sys.path`, *after* the
//! stdlib, including the snapshot interpreter, whose `sys.path` is fixed when the snapshot is
//! built (it runs `/code/main.py` from C, not through `sandboxd_boot`). Packages therefore can't
//! shadow the stdlib, and need no interpreter rebuild. The merged directory is a different
//! directory from the one the snapshot saw, so CPython's `FileFinder` (keyed on the directory's
//! mtime) rescans it.
//!
//! Agents can't install anything: the operator chooses the wheels (and can pin them by SHA-256).
//! The host never runs package code. It only reads the zip, and every entry is checked before
//! anything is written: no absolute or `..` paths, no symlinks, no native binaries, a size cap.

use std::{
    collections::{BTreeMap, HashMap},
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

/// Largest accepted wheel, uncompressed (zip-bomb guard).
pub const MAX_WHEEL_BYTES: u64 = 64 << 20;
/// Most entries in one wheel.
pub const MAX_WHEEL_ENTRIES: usize = 20_000;
/// Most wheels in one wheelhouse.
pub const MAX_WHEELS: usize = 1_000;

const MARKER: &str = ".sandboxd-packages";
/// Suffixes of native code, which can't run in the WebAssembly interpreter.
const NATIVE: &[&str] = &[".so", ".pyd", ".dll", ".dylib"];

/// `[packages]` from the server config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageConfig {
    /// Directory holding the `.whl` files.
    pub dir: PathBuf,
    /// Optional lock: wheel file name → SHA-256 (hex). When non-empty, every wheel must be listed
    /// and match, and every listed wheel must exist.
    pub sha256: BTreeMap<String, String>,
}

/// One accepted wheel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wheel {
    pub file: String,
    pub name: String,
    pub version: String,
    pub sha256: String,
    /// Files it contributes to the package directory.
    pub files: usize,
}

/// The validated, extracted wheelhouse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSet {
    /// Host directory mounted in runs.
    pub dir: PathBuf,
    /// Content hash of the set (sorted file names and SHA-256s).
    pub hash: String,
    pub wheels: Vec<Wheel>,
}

impl PackageSet {
    /// `name version` for each wheel, for messages.
    pub fn names(&self) -> Vec<String> {
        self.wheels
            .iter()
            .map(|w| format!("{} {}", w.name, w.version))
            .collect()
    }
}

/// Why the wheelhouse was refused (start-up fails; the message names the file).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("packages: {0}")]
pub struct PackageError(pub String);

fn err(msg: impl Into<String>) -> PackageError {
    PackageError(msg.into())
}

/// Validate every wheel in `cfg.dir` and return the set, without extracting anything.
pub fn scan(cfg: &PackageConfig) -> Result<Vec<(PathBuf, Wheel)>, PackageError> {
    let rd =
        std::fs::read_dir(&cfg.dir).map_err(|e| err(format!("read {}: {e}", cfg.dir.display())))?;
    let mut paths = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|e| err(format!("read {}: {e}", cfg.dir.display())))?;
        let path = entry.path();
        let is_whl = path
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("whl"));
        if !is_whl {
            continue;
        }
        // Regular files only: a symlink could point anywhere on the host.
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| err(format!("stat {}: {e}", path.display())))?;
        if !meta.is_file() {
            return Err(err(format!(
                "{}: not a regular file (symlinks are not followed)",
                file_name(&path)
            )));
        }
        paths.push(path);
    }
    paths.sort();
    if paths.len() > MAX_WHEELS {
        return Err(err(format!("more than {MAX_WHEELS} wheels")));
    }
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let w = inspect(&p, &cfg.sha256)?;
        out.push((p, w));
    }
    for listed in cfg.sha256.keys() {
        if !out.iter().any(|(_, w)| &w.file == listed) {
            return Err(err(format!(
                "{listed}: listed in [packages] sha256 but not found in {}",
                cfg.dir.display()
            )));
        }
    }
    Ok(out)
}

/// Validate, then build `cache_dir/packages/<hash>/site`: a copy of `helpers` plus the extracted
/// wheels. The hash covers the wheels and `helpers_key` (the helpers' content hash), so new
/// helpers or wheels give a new directory; an unchanged set is reused.
pub fn prepare(
    cfg: &PackageConfig,
    cache_dir: &Path,
    helpers: &Path,
    helpers_key: &str,
) -> Result<PackageSet, PackageError> {
    let wheels = scan(cfg)?;
    let mut h = Sha256::new();
    h.update(helpers_key.as_bytes());
    h.update(b"\n");
    for (_, w) in &wheels {
        h.update(w.file.as_bytes());
        h.update([0]);
        h.update(w.sha256.as_bytes());
        h.update(b"\n");
    }
    let hash = hex::encode(h.finalize());
    let root = cache_dir.join("packages");
    let final_dir = root.join(&hash);
    let set = |dir: PathBuf| PackageSet {
        dir,
        hash: hash.clone(),
        wheels: wheels.iter().map(|(_, w)| w.clone()).collect(),
    };
    if marker_ok(&final_dir, &hash) {
        return Ok(set(final_dir.join("site")));
    }
    std::fs::create_dir_all(&root).map_err(|e| err(format!("create {}: {e}", root.display())))?;
    if final_dir.exists() {
        std::fs::remove_dir_all(&final_dir)
            .map_err(|e| err(format!("remove stale {}: {e}", final_dir.display())))?;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let tmp = root.join(format!(".tmp-{}-{nonce}", std::process::id()));
    let result = (|| {
        let site = tmp.join("site");
        std::fs::create_dir_all(&site)
            .map_err(|e| err(format!("create {}: {e}", site.display())))?;
        let mut owners: HashMap<PathBuf, String> = HashMap::new();
        copy_helpers(helpers, &site, &mut owners)?;
        for (path, w) in &wheels {
            extract(path, &w.file, &site, &mut owners)?;
        }
        std::fs::write(tmp.join(MARKER), &hash).map_err(|e| err(format!("write marker: {e}")))?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    match std::fs::rename(&tmp, &final_dir) {
        Ok(()) => {}
        Err(_) if marker_ok(&final_dir, &hash) => {
            let _ = std::fs::remove_dir_all(&tmp); // another process won the race
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(err(format!("install {}: {e}", final_dir.display())));
        }
    }
    Ok(set(final_dir.join("site")))
}

/// Owner label of the helpers' top-level names, which no wheel may provide.
const HELPERS_OWNER: &str = "the sandboxd guest helpers";

/// Copy the helper directory (files and `__pycache__`) into `site`, recording its top-level names
/// so a wheel can't replace a helper.
fn copy_helpers(
    helpers: &Path,
    site: &Path,
    owners: &mut HashMap<PathBuf, String>,
) -> Result<(), PackageError> {
    fn walk(
        src: &Path,
        dst: &Path,
        rel: &Path,
        owners: &mut HashMap<PathBuf, String>,
    ) -> Result<(), PackageError> {
        let rd = std::fs::read_dir(src).map_err(|e| err(format!("read {}: {e}", src.display())))?;
        for entry in rd {
            let entry = entry.map_err(|e| err(format!("read {}: {e}", src.display())))?;
            let name = entry.file_name();
            // Our own markers stay with the plain helper dir.
            if name.to_string_lossy().starts_with(".pyc-complete") {
                continue;
            }
            let ty = entry
                .file_type()
                .map_err(|e| err(format!("stat {}: {e}", entry.path().display())))?;
            let (s, d, r) = (entry.path(), dst.join(&name), rel.join(&name));
            if rel.as_os_str().is_empty() {
                owners.insert(r.clone(), HELPERS_OWNER.into());
            }
            if ty.is_dir() {
                std::fs::create_dir_all(&d)
                    .map_err(|e| err(format!("create {}: {e}", d.display())))?;
                walk(&s, &d, &r, owners)?;
            } else if ty.is_file() {
                std::fs::copy(&s, &d).map_err(|e| err(format!("copy {}: {e}", s.display())))?;
            }
        }
        Ok(())
    }
    walk(helpers, site, Path::new(""), owners)
}

/// The top-level importable name of an entry: `pkg/x.py` -> `pkg`, `mod.py` -> `mod`.
fn top_level(rel: &Path) -> Option<String> {
    let first = rel
        .components()
        .next()?
        .as_os_str()
        .to_string_lossy()
        .into_owned();
    Some(
        first
            .strip_suffix(".py")
            .or_else(|| first.strip_suffix(".pyc"))
            .unwrap_or(&first)
            .to_string(),
    )
}

fn marker_ok(dir: &Path, hash: &str) -> bool {
    std::fs::read_to_string(dir.join(MARKER)).is_ok_and(|m| m.trim() == hash)
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl` → (name, version), pure only.
fn parse_wheel_name(file: &str) -> Result<(String, String), PackageError> {
    let stem = file
        .strip_suffix(".whl")
        .or_else(|| file.strip_suffix(".WHL"))
        .ok_or_else(|| err(format!("{file}: not a .whl file")))?;
    let parts: Vec<&str> = stem.split('-').collect();
    if !(parts.len() == 5 || parts.len() == 6) {
        return Err(err(format!("{file}: not a wheel file name (PEP 427)")));
    }
    let (py, abi, plat) = (
        parts[parts.len() - 3],
        parts[parts.len() - 2],
        parts[parts.len() - 1],
    );
    let pure_py = py
        .split('.')
        .all(|t| t.starts_with("py") && t[2..].chars().all(|c| c.is_ascii_digit()) && t.len() > 2)
        && py.split('.').any(|t| t.starts_with("py3"));
    if !(pure_py && abi == "none" && plat == "any") {
        return Err(err(format!(
            "{file}: only pure-Python wheels are supported (tags py3-none-any or py2.py3-none-any; got {py}-{abi}-{plat})"
        )));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// Hash and check one wheel (tags, lock, entries) without extracting it.
fn inspect(path: &Path, lock: &BTreeMap<String, String>) -> Result<Wheel, PackageError> {
    let file = file_name(path);
    let (name, version) = parse_wheel_name(&file)?;
    let bytes = std::fs::read(path).map_err(|e| err(format!("{file}: read: {e}")))?;
    let sha256 = hex::encode(Sha256::digest(&bytes));
    if !lock.is_empty() {
        match lock.get(&file) {
            None => {
                return Err(err(format!(
                    "{file}: not listed in [packages] sha256 (every wheel must be pinned when a lock is given)"
                )));
            }
            Some(want) if !want.eq_ignore_ascii_case(&sha256) => {
                return Err(err(format!(
                    "{file}: SHA-256 mismatch (lock {want}, file {sha256})"
                )));
            }
            Some(_) => {}
        }
    }
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&bytes))
        .map_err(|e| err(format!("{file}: not a valid zip: {e}")))?;
    if zip.len() > MAX_WHEEL_ENTRIES {
        return Err(err(format!(
            "{file}: more than {MAX_WHEEL_ENTRIES} entries"
        )));
    }
    let mut total = 0u64;
    let mut files = 0usize;
    for i in 0..zip.len() {
        let f = zip
            .by_index_raw(i)
            .map_err(|e| err(format!("{file}: entry {i}: {e}")))?;
        let Some(rel) = target(&f, &file)? else {
            continue;
        };
        total = total.saturating_add(f.size());
        if total > MAX_WHEEL_BYTES {
            return Err(err(format!(
                "{file}: larger than {} MiB uncompressed",
                MAX_WHEEL_BYTES >> 20
            )));
        }
        if !f.is_dir() && !rel.as_os_str().is_empty() {
            files += 1;
        }
    }
    Ok(Wheel {
        file,
        name,
        version,
        sha256,
        files,
    })
}

/// Where a zip entry goes under the package directory, or `None` to skip it. Errors for unsafe
/// or native entries.
fn target(
    f: &zip::read::ZipFile<'_, impl Read>,
    file: &str,
) -> Result<Option<PathBuf>, PackageError> {
    let raw = f
        .name()
        .map_err(|e| err(format!("{file}: entry name: {e}")))?
        .into_owned();
    // Absolute (`/x`, `\x`, `C:...`) names are refused outright, even though `enclosed_name`
    // would strip them to a relative path.
    let absolute = raw.starts_with('/') || raw.starts_with('\\') || raw.contains(':');
    let (false, Some(rel)) = (absolute, f.enclosed_name()) else {
        return Err(err(format!("{file}: unsafe entry name {raw:?}")));
    };
    if f.is_symlink() {
        return Err(err(format!("{file}: symlink entry {raw:?}")));
    }
    let lower = raw.to_ascii_lowercase();
    if NATIVE
        .iter()
        .any(|s| lower.ends_with(s) || lower.contains(&format!("{s}.")))
    {
        return Err(err(format!(
            "{file}: contains native code ({raw}); only pure-Python wheels are supported"
        )));
    }
    // `<name>-<ver>.data/<scheme>/...`: purelib is installed like the root; platlib means native
    // code; scripts, headers and data aren't importable, so they are skipped.
    let mut comps = rel.components();
    if let Some(first) = comps.next()
        && first.as_os_str().to_string_lossy().ends_with(".data")
    {
        let scheme = comps
            .next()
            .map(|c| c.as_os_str().to_string_lossy().into_owned());
        return match scheme.as_deref() {
            Some("purelib") => Ok(Some(comps.as_path().to_path_buf())),
            Some("platlib") => Err(err(format!(
                "{file}: has platlib content ({raw}); only pure-Python wheels are supported"
            ))),
            _ => Ok(None),
        };
    }
    Ok(Some(rel))
}

fn extract(
    path: &Path,
    file: &str,
    site: &Path,
    owners: &mut HashMap<PathBuf, String>,
) -> Result<(), PackageError> {
    let bytes = std::fs::read(path).map_err(|e| err(format!("{file}: read: {e}")))?;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&bytes))
        .map_err(|e| err(format!("{file}: not a valid zip: {e}")))?;
    for i in 0..zip.len() {
        let mut f = zip
            .by_index(i)
            .map_err(|e| err(format!("{file}: entry {i}: {e}")))?;
        let Some(rel) = target(&f, file)? else {
            continue;
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        let out = site.join(&rel);
        if f.is_dir() {
            std::fs::create_dir_all(&out)
                .map_err(|e| err(format!("{file}: create {}: {e}", rel.display())))?;
            continue;
        }
        // A wheel can't replace a helper module or package (e.g. `sandbox_net`).
        if let Some(top) = top_level(&rel) {
            let clash = owners
                .iter()
                .any(|(p, o)| o == HELPERS_OWNER && top_level(p).is_some_and(|t| t == top));
            if clash {
                return Err(err(format!(
                    "{file}: provides {top:?}, which is reserved by {HELPERS_OWNER}"
                )));
            }
        }
        if let Some(other) = owners.insert(rel.clone(), file.to_string()) {
            return Err(err(format!(
                "{file} and {other} both provide {}",
                rel.display()
            )));
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| err(format!("{file}: create {}: {e}", parent.display())))?;
        }
        // Bounded by the size check in `inspect`; `take` guards a lying header.
        let mut buf = Vec::new();
        (&mut f)
            .take(MAX_WHEEL_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| err(format!("{file}: read {}: {e}", rel.display())))?;
        if buf.len() as u64 > MAX_WHEEL_BYTES {
            return Err(err(format!("{file}: entry {} too large", rel.display())));
        }
        std::fs::write(&out, buf)
            .map_err(|e| err(format!("{file}: write {}: {e}", rel.display())))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a wheel in memory: `(entry name, content)` pairs.
    pub(crate) fn wheel(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default();
            for (name, content) in entries {
                z.start_file(*name, opts).expect("start");
                z.write_all(content.as_bytes()).expect("write");
            }
            z.finish().expect("finish");
        }
        buf.into_inner()
    }

    fn house(tag: &str, wheels: &[(&str, Vec<u8>)]) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("sandboxd-pkg-unit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        for (n, b) in wheels {
            std::fs::write(d.join(n), b).expect("write");
        }
        d
    }

    /// A fake helper directory with one helper module.
    fn helpers(d: &Path) -> PathBuf {
        let h = d.join("helpers");
        std::fs::create_dir_all(h.join("__pycache__")).expect("mkdir");
        std::fs::write(h.join("sandbox_net.py"), "# helper\n").expect("write");
        std::fs::write(h.join("__pycache__/sandbox_net.pyc"), "pyc").expect("write");
        std::fs::write(h.join(".pyc-complete"), "x").expect("write");
        h
    }

    fn prep(c: &PackageConfig, d: &Path) -> Result<PackageSet, PackageError> {
        prepare(c, &d.join("cache"), &helpers(d), "helpers-v1")
    }

    fn cfg(dir: &Path) -> PackageConfig {
        PackageConfig {
            dir: dir.to_path_buf(),
            sha256: BTreeMap::new(),
        }
    }

    #[test]
    fn wheel_names() {
        assert_eq!(
            parse_wheel_name("attrs-25.1.0-py3-none-any.whl"),
            Ok(("attrs".into(), "25.1.0".into()))
        );
        assert!(parse_wheel_name("six-1.17.0-py2.py3-none-any.whl").is_ok());
        assert!(parse_wheel_name("demo-1.0-1-py3-none-any.whl").is_ok());
        for bad in [
            "numpy-2.3.0-cp313-cp313-manylinux_2_17_x86_64.whl",
            "x-1.0-py3-abi3-any.whl",
            "x-1.0-py2-none-any.whl",
            "x-1.0-py3-none-win_amd64.whl",
            "x-1.0.whl",
            "x-1.0-py3-none-any.zip",
        ] {
            assert!(parse_wheel_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn prepare_extracts_and_reuses() {
        let w = wheel(&[
            ("demo_pkg/__init__.py", "VALUE = 42\n"),
            ("demo_pkg-1.0.dist-info/METADATA", "Name: demo-pkg\n"),
            ("demo_pkg-1.0.data/purelib/demo_extra.py", "X = 1\n"),
            ("demo_pkg-1.0.data/scripts/demo", "#!/bin/sh\n"),
        ]);
        let d = house("ok", &[("demo_pkg-1.0-py3-none-any.whl", w)]);
        let set = prep(&cfg(&d), &d).expect("prepare");
        assert_eq!(set.wheels.len(), 1);
        assert_eq!(set.wheels[0].name, "demo_pkg");
        assert!(set.dir.join("demo_pkg/__init__.py").is_file());
        assert!(set.dir.join("demo_extra.py").is_file(), "purelib flattened");
        assert!(!set.dir.join("demo").exists(), "scripts skipped");
        assert!(set.dir.join("sandbox_net.py").is_file(), "helpers copied");
        assert!(
            set.dir.join("__pycache__/sandbox_net.pyc").is_file(),
            "helper bytecode copied"
        );
        assert!(
            !set.dir.join(".pyc-complete").exists(),
            "helper marker not copied"
        );
        let again = prep(&cfg(&d), &d).expect("again");
        assert_eq!(again, set);
        // New helpers -> a new directory.
        let other = prepare(&cfg(&d), &d.join("cache"), &helpers(&d), "helpers-v2").expect("v2");
        assert_ne!(other.dir, set.dir);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn refuses_unsafe_wheels() {
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            (
                "nat-1.0-py3-none-any.whl",
                wheel(&[("nat/_speed.cpython-315-wasm32-wasi.so", "x")]),
                "native code",
            ),
            (
                "nat2-1.0-py3-none-any.whl",
                wheel(&[("nat2/lib.pyd", "x")]),
                "native code",
            ),
            (
                "trav-1.0-py3-none-any.whl",
                wheel(&[("../evil.py", "x")]),
                "unsafe entry",
            ),
            (
                "abs-1.0-py3-none-any.whl",
                wheel(&[("/etc/evil.py", "x")]),
                "unsafe entry",
            ),
            (
                "plat-1.0-py3-none-any.whl",
                wheel(&[("plat-1.0.data/platlib/plat.py", "x")]),
                "platlib",
            ),
            (
                "junk-1.0-py3-none-any.whl",
                b"not a zip".to_vec(),
                "valid zip",
            ),
        ];
        for (name, bytes, want) in cases {
            let d = house(name.split('-').next().unwrap_or("x"), &[(name, bytes)]);
            let e = prep(&cfg(&d), &d).expect_err(name);
            assert!(e.0.contains(want) && e.0.contains(name), "{name}: {e}");
            assert!(
                !d.join("evil.py").exists() && !d.join("cache/evil.py").exists(),
                "{name}: nothing written outside"
            );
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn lock_is_enforced() {
        let w = wheel(&[("locked/__init__.py", "")]);
        let sha = hex::encode(Sha256::digest(&w));
        let d = house("lock", &[("locked-1.0-py3-none-any.whl", w)]);
        let mut c = cfg(&d);
        c.sha256
            .insert("locked-1.0-py3-none-any.whl".into(), sha.to_uppercase());
        prep(&c, &d).expect("matching lock");
        c.sha256
            .insert("locked-1.0-py3-none-any.whl".into(), "00".repeat(32));
        assert!(prep(&c, &d).expect_err("mismatch").0.contains("mismatch"));
        c.sha256.clear();
        c.sha256.insert("missing-1.0-py3-none-any.whl".into(), sha);
        let e = prep(&c, &d).expect_err("unlisted");
        assert!(e.0.contains("not listed"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn overlapping_wheels_are_refused() {
        let d = house(
            "overlap",
            &[
                ("a-1.0-py3-none-any.whl", wheel(&[("shared/x.py", "1")])),
                ("b-1.0-py3-none-any.whl", wheel(&[("shared/x.py", "2")])),
            ],
        );
        let e = prep(&cfg(&d), &d).expect_err("overlap");
        assert!(e.0.contains("both provide"), "{e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn wheels_cannot_replace_helpers() {
        for (name, entry) in [
            ("evil-1.0-py3-none-any.whl", "sandbox_net.py"),
            ("evil2-1.0-py3-none-any.whl", "sandbox_net/__init__.py"),
        ] {
            let d = house("helperclash", &[(name, wheel(&[(entry, "x = 1")]))]);
            let e = prep(&cfg(&d), &d).expect_err(name);
            assert!(e.0.contains("reserved"), "{name}: {e}");
            let _ = std::fs::remove_dir_all(&d);
        }
    }
}
