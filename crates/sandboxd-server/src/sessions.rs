//! Live sessions behind the HTTP and MCP front ends (cycle 3, C3-U4).
//!
//! The registry maps `ses_…` ids to [`Session`]s and enforces the server-wide cap
//! (`[runtime] max_sessions`) and each policy's `[session] max_sessions`. Creating a session
//! takes a [`Reservation`] first, so concurrent creations can't overshoot either cap while the
//! interpreters start.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use sandboxd_runtime::Session;

#[derive(Default)]
struct State {
    sessions: HashMap<String, Session>,
    /// Policies of creations in progress.
    pending: Vec<String>,
}

/// The session registry.
pub(crate) struct SessionStore {
    state: Mutex<State>,
    max: usize,
}

impl SessionStore {
    pub(crate) fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            max,
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Hold a place for a new session of `policy`; `None` when a cap is reached.
    pub(crate) fn reserve(self: &Arc<Self>, policy: &str, policy_max: u32) -> Option<Reservation> {
        let mut st = self.lock();
        let total = st.sessions.len() + st.pending.len();
        let of_policy = st
            .sessions
            .values()
            .filter(|s| s.policy().name() == policy)
            .count()
            + st.pending.iter().filter(|p| *p == policy).count();
        if total >= self.max || of_policy >= policy_max as usize {
            return None;
        }
        st.pending.push(policy.to_string());
        Some(Reservation {
            store: self.clone(),
            policy: policy.to_string(),
            done: false,
        })
    }

    pub(crate) fn get(&self, id: &str) -> Option<Session> {
        self.lock().sessions.get(id).cloned()
    }

    pub(crate) fn remove(&self, id: &str) -> Option<Session> {
        self.lock().sessions.remove(id)
    }

    pub(crate) fn all(&self) -> Vec<Session> {
        self.lock().sessions.values().cloned().collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.lock().sessions.len()
    }

    fn unpend(&self, st: &mut State, policy: &str) {
        if let Some(i) = st.pending.iter().position(|p| p == policy) {
            st.pending.swap_remove(i);
        }
    }
}

/// A place held for a session being created; released on drop unless committed.
pub(crate) struct Reservation {
    store: Arc<SessionStore>,
    policy: String,
    done: bool,
}

impl Reservation {
    /// Register the created session.
    pub(crate) fn commit(mut self, s: Session) {
        let mut st = self.store.lock();
        self.store.unpend(&mut st, &self.policy);
        st.sessions.insert(s.id().to_string(), s);
        self.done = true;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.done {
            let mut st = self.store.lock();
            self.store.unpend(&mut st, &self.policy);
        }
    }
}
