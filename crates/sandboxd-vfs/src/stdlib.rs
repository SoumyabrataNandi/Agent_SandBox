//! Hash-keyed, atomically extracted CPython stdlib cache (U3 design §5, ADR-004).

use std::{
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::error::{VfsError, io};

const MARKER: &str = ".complete";

/// Guest path the stdlib is mounted at. Must match `sandboxd_policy::STDLIB_GUEST_PATH`.
pub const STDLIB_GUEST: &str = sandboxd_policy::STDLIB_GUEST_PATH;

/// Host directory (`.../lib/python3.15`) holding the extracted stdlib, extracting it on first use.
///
/// `cache_dir/stdlib/<sha256>/` is extracted to a temp sibling and renamed into place; a marker
/// file containing the sha proves completeness. A missing or mismatched marker → re-extract.
pub fn ensure_stdlib(
    cache_dir: &Path,
    asset: &sandboxd_assets::Asset,
) -> Result<PathBuf, VfsError> {
    let root = cache_dir.join("stdlib");
    let final_dir = root.join(asset.sha256);
    let lib = final_dir.join("lib").join(lib_dir_name(asset)?);
    if marker_ok(&final_dir, asset.sha256) && lib.is_dir() {
        return Ok(lib);
    }
    std::fs::create_dir_all(&root).map_err(io("create stdlib cache", &root))?;
    if final_dir.exists() {
        // Incomplete or corrupt: rebuild.
        std::fs::remove_dir_all(&final_dir).map_err(io("remove stale stdlib", &final_dir))?;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let tmp = root.join(format!(".tmp-{}-{nonce}", std::process::id()));
    extract(asset.bytes, &tmp)?;
    std::fs::write(tmp.join(MARKER), asset.sha256).map_err(io("write stdlib marker", &tmp))?;
    match std::fs::rename(&tmp, &final_dir) {
        Ok(()) => {}
        Err(_) if marker_ok(&final_dir, asset.sha256) => {
            // Another process won the race; use theirs.
            let _ = std::fs::remove_dir_all(&tmp);
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(VfsError::Io {
                what: "install stdlib",
                path: final_dir,
                source: e,
            });
        }
    }
    if !lib.is_dir() {
        return Err(VfsError::Stdlib(format!(
            "{} missing after extraction",
            lib.display()
        )));
    }
    Ok(lib)
}

fn marker_ok(dir: &Path, sha: &str) -> bool {
    std::fs::read_to_string(dir.join(MARKER)).is_ok_and(|m| m.trim() == sha)
}

/// `python3.15` from the asset version `3.15.2`.
fn lib_dir_name(asset: &sandboxd_assets::Asset) -> Result<String, VfsError> {
    let mut it = asset.version.split('.');
    match (it.next(), it.next()) {
        (Some(maj), Some(min)) => Ok(format!("python{maj}.{min}")),
        _ => Err(VfsError::Stdlib(format!(
            "unexpected python version {:?}",
            asset.version
        ))),
    }
}

/// Extract `lib/**` and `LICENSE` (not `python.wasm`, which the runtime loads from memory).
fn extract(zip_bytes: &[u8], dest: &Path) -> Result<(), VfsError> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes))
        .map_err(|e| VfsError::Stdlib(format!("open embedded zip: {e}")))?;
    std::fs::create_dir_all(dest).map_err(io("create temp stdlib dir", dest))?;
    for i in 0..zip.len() {
        let mut f = zip
            .by_index(i)
            .map_err(|e| VfsError::Stdlib(format!("zip entry {i}: {e}")))?;
        // `enclosed_name` rejects absolute paths and `..` (zip-slip), even though the asset is trusted.
        let Some(rel) = f.enclosed_name() else {
            return Err(VfsError::Stdlib(format!(
                "unsafe zip entry name {:?}",
                f.name()
            )));
        };
        if !(rel.starts_with("lib") || rel == Path::new("LICENSE")) {
            continue;
        }
        let out = dest.join(&rel);
        if f.is_dir() {
            std::fs::create_dir_all(&out).map_err(io("create stdlib dir", &out))?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(io("create stdlib dir", parent))?;
        }
        let mut buf = Vec::with_capacity(f.size() as usize);
        f.read_to_end(&mut buf)
            .map_err(io("read zip entry", &out))?;
        std::fs::write(&out, buf).map_err(io("write stdlib file", &out))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_once_and_repairs_corruption() {
        let dir = std::env::temp_dir().join(format!("sandboxd-stdlib-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let lib = ensure_stdlib(&dir, &sandboxd_assets::PYTHON).expect("extract");
        assert!(lib.join("os.py").is_file());
        assert!(lib.ends_with("python3.15"));

        // Second call is a no-op (marker present): mtime of os.py unchanged.
        let m1 = std::fs::metadata(lib.join("os.py"))
            .and_then(|m| m.modified())
            .expect("mtime");
        let lib2 = ensure_stdlib(&dir, &sandboxd_assets::PYTHON).expect("cached");
        assert_eq!(lib, lib2);
        let m2 = std::fs::metadata(lib.join("os.py"))
            .and_then(|m| m.modified())
            .expect("mtime");
        assert_eq!(m1, m2);

        // Corrupt the marker → re-extracted.
        let base = dir.join("stdlib").join(sandboxd_assets::PYTHON.sha256);
        std::fs::write(base.join(MARKER), "bogus").expect("corrupt");
        std::fs::remove_file(lib.join("os.py")).expect("rm");
        let lib3 = ensure_stdlib(&dir, &sandboxd_assets::PYTHON).expect("repair");
        assert!(lib3.join("os.py").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
