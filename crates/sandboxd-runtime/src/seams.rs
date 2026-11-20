//! Extension points for later phases (FR-1.5 fallback). Sessions are `crate::session` (C3-U4). The network
//! broker (FR-7) is the concrete `sandboxd_net::Broker` (cycle 2, C2-U3 Q8).
//! Only interfaces live here; the cycle-1 runtime uses `InstancePre` directly (naive pool).

use std::{future::Future, pin::Pin, sync::Arc};

use sandboxd_policy::Policy;

use crate::types::{RunRequest, RunResult};

/// Boxed future used by the object-safe seams.
pub type SeamFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Runs requests the WASM tier can't (e.g. NumPy) in a container/microVM. Not implemented.
pub trait FallbackBackend: Send + Sync {
    fn execute<'a>(&'a self, req: RunRequest, policy: Arc<Policy>) -> SeamFuture<'a, RunResult>;
}
