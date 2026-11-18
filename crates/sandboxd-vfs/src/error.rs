use std::path::PathBuf;

use sandboxd_policy::ByteSize;

/// Errors creating a run filesystem or collecting its outputs.
#[derive(Debug, thiserror::Error)]
pub enum VfsError {
    /// Host I/O failure, with what we were doing and where.
    #[error("{what} ({path}): {source}")]
    Io {
        what: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A request input file name or set is invalid.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Request inputs exceed `limits.input_bytes`.
    #[error("inputs total {total} exceed the policy limit {limit}")]
    InputsTooLarge { total: ByteSize, limit: ByteSize },
    /// The embedded stdlib archive could not be provisioned.
    #[error("stdlib cache: {0}")]
    Stdlib(String),
    /// Problem configuring WASI preopens.
    #[error("wasi setup: {0}")]
    Wasi(String),
}

pub(crate) fn io(
    what: &'static str,
    path: impl Into<PathBuf>,
) -> impl FnOnce(std::io::Error) -> VfsError {
    let path = path.into();
    move |source| VfsError::Io { what, path, source }
}
