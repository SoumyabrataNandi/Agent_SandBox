//! Per-run filesystem (U3 design §1, §4).

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use sandboxd_audit::{
    AuditEvent, AuditSink, Decision, EventKind, FsOp, LimitKind, RunId, sha256_hex,
};
use sandboxd_policy::{ByteSize, MountMode, Policy};
use wasmtime_wasi::{FsPerms, WasiCtxBuilder, p1::WasiP1Ctx};

use crate::{
    config::VfsConfig,
    error::{VfsError, io},
    interposer::{Interposer, InterposerParts, MountInfo, MountKind, OutQuota},
    paths::validate_input_name,
    stdlib::STDLIB_GUEST,
    vfd::VirtualFdTable,
};

/// A file supplied with the run request; exposed read-only under `filesystem.inputs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputFile {
    /// `/`-separated relative name, validated by rule I1.
    pub name: String,
    pub bytes: Vec<u8>,
}

/// A file collected from `/out`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// `/`-separated path relative to `/out`.
    pub name: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

/// Result of [`RunFs::collect_artifacts`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collected {
    pub artifacts: Vec<Artifact>,
    /// `Some(Artifacts)` if caps truncated the collection.
    pub limit_hit: Option<LimitKind>,
    /// `(name, reason)` for entries that were not collected (symlinks, special files).
    pub skipped: Vec<(String, String)>,
}

/// One run's guest filesystem. The run directory is deleted on drop.
pub struct RunFs {
    run_dir: PathBuf,
    out_dir: PathBuf,
    outputs_guest: String,
    mounts: Vec<MountInfo>,
    artifact_count: u32,
    artifact_bytes: u64,
    run_id: RunId,
    policy: String,
    audit: Arc<dyn AuditSink>,
}

impl std::fmt::Debug for RunFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunFs")
            .field("run_dir", &self.run_dir)
            .field("mounts", &self.mounts)
            .field("run_id", &self.run_id)
            .finish_non_exhaustive()
    }
}

impl RunFs {
    /// Build the layout for one run.
    ///
    /// `stdlib` is the host stdlib directory from [`crate::ensure_stdlib`] (Python runs), or
    /// `None` (JavaScript). Inputs are validated and size-checked before anything is written.
    pub fn create(
        cfg: &VfsConfig,
        policy: &Policy,
        run_id: RunId,
        inputs: Vec<InputFile>,
        stdlib: Option<&Path>,
        audit: Arc<dyn AuditSink>,
    ) -> Result<RunFs, VfsError> {
        // I1: names, duplicates, size, all before touching the disk.
        let mut seen = BTreeSet::new();
        let mut total: u64 = 0;
        for f in &inputs {
            validate_input_name(&f.name).map_err(VfsError::InvalidInput)?;
            let lower = f.name.to_ascii_lowercase(); // case-insensitive hosts (Windows, macOS)
            if !seen.insert(lower) {
                return Err(VfsError::InvalidInput(format!(
                    "duplicate input name {:?}",
                    f.name
                )));
            }
            total = total.saturating_add(f.bytes.len() as u64);
        }
        let limits = policy.limits();
        if total > limits.input_bytes.bytes() {
            return Err(VfsError::InputsTooLarge {
                total: ByteSize(total),
                limit: limits.input_bytes,
            });
        }
        let names: Vec<&str> = inputs.iter().map(|f| f.name.as_str()).collect();
        for a in &names {
            for b in &names {
                if a != b
                    && b.to_ascii_lowercase()
                        .starts_with(&format!("{}/", a.to_ascii_lowercase()))
                {
                    return Err(VfsError::InvalidInput(format!(
                        "input {a:?} is both a file and a directory"
                    )));
                }
            }
        }

        let empty_root = cfg.work_dir.join("empty-root");
        mkdir_private(&empty_root)?;
        let not_empty = std::fs::read_dir(&empty_root)
            .map_err(io("read catch-all root", &empty_root))?
            .next()
            .is_some();
        if not_empty {
            return Err(VfsError::Wasi(format!(
                "catch-all root {} must be empty",
                empty_root.display()
            )));
        }

        let run_dir = cfg.work_dir.join("runs").join(run_id.to_string());
        if run_dir.exists() {
            return Err(VfsError::Wasi(format!(
                "run dir {} already exists",
                run_dir.display()
            )));
        }
        let in_dir = run_dir.join("in");
        let out_dir = run_dir.join("out");
        mkdir_private(&in_dir)?;
        mkdir_private(&out_dir)?;

        let mut fs = RunFs {
            run_dir,
            out_dir: out_dir.clone(),
            outputs_guest: policy.filesystem().outputs.clone(),
            mounts: Vec::new(),
            artifact_count: limits.artifact_count,
            artifact_bytes: limits.artifact_bytes.bytes(),
            run_id,
            policy: policy.name().to_string(),
            audit,
        };

        for f in &inputs {
            let dest = in_dir.join(f.name.replace('/', std::path::MAIN_SEPARATOR_STR));
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(io("create input dir", parent))?;
            }
            write_new(&dest, &f.bytes)?;
        }

        // Preopen order == fd order (3, 4, ...). Keep in sync with `preopen`.
        let mut mounts = vec![MountInfo {
            guest: "/".into(),
            host: empty_root,
            kind: MountKind::CatchAll,
        }];
        if let Some(lib) = stdlib {
            mounts.push(MountInfo {
                guest: STDLIB_GUEST.into(),
                host: lib.to_path_buf(),
                kind: MountKind::Stdlib,
            });
        }
        mounts.push(MountInfo {
            guest: policy.filesystem().inputs.clone(),
            host: in_dir,
            kind: MountKind::Inputs,
        });
        mounts.push(MountInfo {
            guest: policy.filesystem().outputs.clone(),
            host: out_dir,
            kind: MountKind::Outputs,
        });
        for m in &policy.filesystem().mounts {
            mounts.push(MountInfo {
                guest: m.guest.clone(),
                host: m.host.clone(),
                kind: MountKind::Policy,
            });
        }
        fs.mounts = mounts;
        Ok(fs)
    }

    /// Add every preopen to `builder`, in the order the interposer expects.
    pub fn preopen(&self, builder: &mut WasiCtxBuilder, policy: &Policy) -> Result<(), VfsError> {
        for m in &self.mounts {
            let perms = match m.kind {
                MountKind::CatchAll | MountKind::Stdlib | MountKind::Inputs => FsPerms::ReadOnly,
                MountKind::Outputs => FsPerms::ReadWrite,
                MountKind::Policy => {
                    let rw = policy
                        .filesystem()
                        .mounts
                        .iter()
                        .any(|p| p.guest == m.guest && p.mode == MountMode::ReadWrite);
                    if rw {
                        FsPerms::ReadWrite
                    } else {
                        FsPerms::ReadOnly
                    }
                }
            };
            builder
                .preopened_dir(&m.host, &m.guest, perms)
                .map_err(|e| {
                    VfsError::Wasi(format!("preopen {} → {}: {e}", m.host.display(), m.guest))
                })?;
        }
        Ok(())
    }

    /// Wrap the built wasmtime-wasi context with the interposer for this run.
    pub fn interposer(&self, inner: WasiP1Ctx, vfds: VirtualFdTable) -> Interposer {
        Interposer::new(
            inner,
            InterposerParts {
                quiet_probes: quiet_probes(&self.mounts),
                mounts: self.mounts.clone(),
                quota: OutQuota {
                    max_bytes: self.artifact_bytes,
                    max_files: self.artifact_count,
                    bytes: 0,
                    files: 0,
                    hit: false,
                },
                vfds,
                audit: self.audit.clone(),
                run_id: self.run_id,
                policy: self.policy.clone(),
            },
        )
    }

    /// The preopened mounts, in fd order (for diagnostics and tests).
    pub fn mounts(&self) -> &[MountInfo] {
        &self.mounts
    }

    /// Host directory of this run (deleted on drop).
    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    /// Collect `/out` (rules A1–A3).
    pub fn collect_artifacts(&self) -> Result<Collected, VfsError> {
        let mut entries = Vec::new();
        walk(&self.out_dir, "", &mut entries)?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut c = Collected::default();
        let mut total: u64 = 0;
        for (name, path, kind) in entries {
            match kind {
                Kind::File(len) => {
                    if c.artifacts.len() as u32 >= self.artifact_count
                        || total.saturating_add(len) > self.artifact_bytes
                    {
                        c.limit_hit = Some(LimitKind::Artifacts);
                        c.skipped.push((name, "artifact limit".into()));
                        continue;
                    }
                    let bytes = std::fs::read(&path).map_err(io("read artifact", &path))?;
                    total += bytes.len() as u64;
                    let sha256 = sha256_hex(&bytes);
                    c.artifacts.push(Artifact {
                        name,
                        bytes,
                        sha256,
                    });
                }
                Kind::Other(why) => {
                    self.audit.emit(
                        AuditEvent::new(EventKind::FsAccess {
                            op: FsOp::Stat,
                            path: format!("{}/{name}", self.outputs_guest),
                            mode: None,
                            decision: Decision::Deny,
                            reason: Some(format!("not collected: {why}")),
                        })
                        .run(self.run_id)
                        .policy(self.policy.clone()),
                    );
                    c.skipped.push((name, why.into()));
                }
            }
        }
        Ok(c)
    }
}

impl Drop for RunFs {
    fn drop(&mut self) {
        // Windows may briefly hold handles after the guest's fds close; retry a little.
        for attempt in 0..5 {
            match std::fs::remove_dir_all(&self.run_dir) {
                Ok(()) => return,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                Err(_) if attempt < 4 => std::thread::sleep(Duration::from_millis(20 << attempt)),
                Err(e) => eprintln!(
                    "sandboxd: could not remove run dir {}: {e}",
                    self.run_dir.display()
                ),
            }
        }
    }
}

/// Paths interpreters probe at start-up that are expected to be absent (V2 noise control):
/// every ancestor directory of a mount, plus CPython `getpath` probes when the stdlib is mounted.
fn quiet_probes(mounts: &[MountInfo]) -> Vec<String> {
    let mut q = BTreeSet::new();
    for m in mounts.iter().filter(|m| m.guest != "/") {
        let mut cur = m.guest.as_str();
        while let Some((parent, _)) = cur.rsplit_once('/') {
            if parent.is_empty() {
                break;
            }
            q.insert(parent.to_string());
            cur = parent;
        }
    }
    if mounts.iter().any(|m| m.kind == MountKind::Stdlib) {
        // "/usr/local/lib/python3.15" → prefix "/usr/local", "3.15", "315".
        let lib = STDLIB_GUEST;
        let ver = lib
            .rsplit_once("python")
            .map(|(_, v)| v)
            .unwrap_or_default();
        let nodot = ver.replace('.', "");
        let prefix = lib.trim_end_matches(&format!("/lib/python{ver}"));
        for p in [
            "/pyvenv.cfg".to_string(),
            "/pybuilddir.txt".to_string(),
            format!("{prefix}/pyvenv.cfg"),
            format!("{prefix}/pybuilddir.txt"),
            format!("{prefix}/lib/python{nodot}.zip"),
            format!("/lib/python{nodot}.zip"),
            format!("/lib/python{ver}/os.py"),
            format!("/lib/python{ver}/os.pyc"),
            format!("/lib/python{ver}/lib-dynload"),
            format!("{prefix}/lib/python{ver}/lib-dynload"),
        ] {
            q.insert(p);
        }
    }
    q.into_iter().collect()
}

enum Kind {
    File(u64),
    Other(&'static str),
}

fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, PathBuf, Kind)>) -> Result<(), VfsError> {
    for e in std::fs::read_dir(dir).map_err(io("read outputs", dir))? {
        let e = e.map_err(io("read outputs", dir))?;
        let name = e.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let path = e.path();
        // symlink_metadata: never follow links (rule A1).
        let meta = std::fs::symlink_metadata(&path).map_err(io("stat output", &path))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            out.push((rel, path, Kind::Other("symlink")));
        } else if ft.is_dir() {
            walk(&path, &rel, out)?;
        } else if ft.is_file() {
            out.push((rel, path, Kind::File(meta.len())));
        } else {
            out.push((rel, path, Kind::Other("special file")));
        }
    }
    Ok(())
}

fn mkdir_private(p: &Path) -> Result<(), VfsError> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(p).map_err(io("create dir", p))
}

fn write_new(p: &Path, bytes: &[u8]) -> Result<(), VfsError> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(p)
        .map_err(io("create input file", p))?;
    f.write_all(bytes).map_err(io("write input file", p))
}
