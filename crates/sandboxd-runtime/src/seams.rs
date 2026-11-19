//! Extension points for later phases (FR-1.5 fallback, FR-8 pooling/sessions). The network
//! broker (FR-7) is the concrete `sandboxd_net::Broker` (cycle 2, C2-U3 Q8).
//! Only interfaces live here; the cycle-1 runtime uses `InstancePre` directly (naive pool).

use std::{future::Future, pin::Pin, sync::Arc};

use sandboxd_policy::Policy;

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
