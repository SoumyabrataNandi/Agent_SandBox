//! Extension points for later phases (FR-1.5 fallback, FR-7 network, FR-8 pooling/sessions).
//! Only interfaces live here; the cycle-1 runtime uses `InstancePre` directly (naive pool).

use std::{future::Future, pin::Pin, sync::Arc};

use sandboxd_policy::Policy;
use sandboxd_vfs::VirtualDevice;

use crate::types::{RunRequest, RunResult, SessionId};

/// Boxed future used by the object-safe seams.
pub type SeamFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Runs requests the WASM tier can't (e.g. NumPy) in a container/microVM. Not implemented.
pub trait FallbackBackend: Send + Sync {
    fn execute<'a>(&'a self, req: RunRequest, policy: Arc<Policy>) -> SeamFuture<'a, RunResult>;
}

/// Persistent notebook-style sessions (Phase 5). Not implemented.
pub trait SessionStore: Send + Sync {
    fn create(&self) -> SeamFuture<'_, Result<SessionId, String>>;
    fn evict(&self, id: &SessionId) -> SeamFuture<'_, ()>;
}

/// Phase 4 egress broker. Implementations return devices registered in the run's
/// `VirtualFdTable` (`/dev/sandbox/http`, `/dev/sandbox/tcp/<host>:<port>`, ADR-002).
pub trait NetworkBroker: Send + Sync {
    fn http(&self, policy: Arc<Policy>) -> Result<Box<dyn VirtualDevice>, String>;
    fn tcp_connect(
        &self,
        policy: Arc<Policy>,
        host: &str,
        port: u16,
    ) -> Result<Box<dyn VirtualDevice>, String>;
}
