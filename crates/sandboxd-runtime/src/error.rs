/// Errors constructing a [`crate::Sandbox`] (per-run failures are reported in `RunResult`).
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("compile: {0}")]
    Compile(String),
    #[error("io: {0}")]
    Io(String),
    #[error("vfs: {0}")]
    Vfs(#[from] sandboxd_vfs::VfsError),
}
