// Drop-safe RAII guards for partially-started proxy state.
//
// These guards exist so that `ProxyManager::start_inner` can be written as a
// cancel-safe future: if the future is dropped mid-flight (for example because
// a `tokio::select!` arm fired the cancellation branch), every active guard
// runs its `Drop` and cleans up the partial state that would otherwise leak.
//
// Guards use the `Option::take` idiom: `commit(self)` consumes the guard and
// extracts the inner value, disarming the `Drop` cleanup. Because `commit`
// takes `self` by value, double-commit is a compile error (not a runtime
// check) — the first call moves ownership out of the caller.

use std::path::PathBuf;
use tokio::task::JoinHandle;
use tracing::warn;

// StateFileGuard ======================================================================================================

/// Deletes `bridge-routes.json` in `state_dir` on drop unless committed.
///
/// Used in `ProxyManager::start_inner` for the brief window between
/// `route_state::save` and `RouteGuard` construction: during this window the
/// state file exists on disk but there is no other RAII owner that would
/// clean it up if the future is dropped.
///
/// Once `RouteGuard` is constructed (after `setup_routes` succeeds), call
/// `commit()` on this guard — `RouteGuard::drop` takes over state-file
/// cleanup as part of its normal teardown.
pub struct StateFileGuard {
    state_dir: Option<PathBuf>,
}

impl StateFileGuard {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir: Some(state_dir),
        }
    }

    /// Disarm the guard. The state file will NOT be cleared on drop.
    pub fn commit(mut self) {
        self.state_dir.take();
    }
}

impl Drop for StateFileGuard {
    fn drop(&mut self) {
        if let Some(dir) = self.state_dir.take() {
            if let Err(e) = crate::route_state::clear(&dir) {
                warn!(error = %e, "failed to clear route-state file in StateFileGuard drop");
            }
        }
    }
}

// TaskHandleGuard =====================================================================================================

/// Aborts a `JoinHandle` on drop unless committed.
///
/// Used in `ProxyManager::start_inner` to own the shadowsocks-service task
/// between `backend.start_ss` and commit-to-self. If start is cancelled or
/// a later step fails, dropping the guard aborts the spawned task.
pub struct TaskHandleGuard<T> {
    handle: Option<JoinHandle<T>>,
}

impl<T> TaskHandleGuard<T> {
    pub fn new(handle: JoinHandle<T>) -> Self {
        Self { handle: Some(handle) }
    }

    /// Disarm the guard and return the inner handle. The task will NOT be
    /// aborted on drop.
    pub fn commit(mut self) -> JoinHandle<T> {
        self.handle
            .take()
            .expect("TaskHandleGuard has no handle — internal invariant violated")
    }
}

impl<T> Drop for TaskHandleGuard<T> {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

#[cfg(test)]
#[path = "guards_tests.rs"]
mod guards_tests;
