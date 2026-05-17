//! Tracing-subscriber test helper that enforces the current-thread
//! runtime invariant.
//!
//! `tracing::subscriber::set_default` returns a thread-local guard. On
//! a multi-thread tokio runtime, any `tokio::spawn`'d task runs on a
//! worker thread that has no subscriber, so its events are dropped.
//! Tests that install a subscriber as their assertion target therefore
//! require a *current-thread* runtime so spawned tasks stay on the
//! caller's thread. See [bindreams/hole#302](https://github.com/bindreams/hole/issues/302).
//!
//! This module exposes [`set_default_in_current_thread`], a thin
//! wrapper that performs the runtime-flavor check before delegating to
//! `tracing::subscriber::set_default`. Workspace-wide clippy
//! `disallowed_methods` rules force all callers through this helper.
//!
//! **Limitation.** If the helper is invoked from a sync context that
//! later enters a multi-thread `block_on`, the check cannot see the
//! future runtime and silently passes. Call this helper from *inside*
//! the `block_on` async block — the regression tests in
//! `tracing_test_tests` document this gap.

use tokio::runtime::{Handle, RuntimeFlavor};
use tracing::subscriber::DefaultGuard;
use tracing::Subscriber;

/// Install `subscriber` as the thread-local default, asserting that
/// any current tokio runtime is single-threaded.
///
/// Returns the [`DefaultGuard`] from `tracing::subscriber::set_default`
/// unchanged. The guard restores the previous default on drop.
///
/// # Panics
///
/// Panics if called from inside a tokio runtime whose flavor is
/// [`RuntimeFlavor::MultiThread`]. Out of `block_on`
/// (`Handle::try_current()` returns `Err`), the helper passes through
/// — sync tests are unaffected. `#[skuld::test] async fn` builds a
/// current-thread runtime by default and satisfies the invariant.
pub fn set_default_in_current_thread<S>(subscriber: S) -> DefaultGuard
where
    S: Subscriber + Send + Sync + 'static,
{
    if let Ok(handle) = Handle::try_current() {
        assert!(
            matches!(handle.runtime_flavor(), RuntimeFlavor::CurrentThread),
            "set_default_in_current_thread called from a multi-thread tokio runtime — \
             set_default is thread-local; tokio::spawn'd tasks would run on worker \
             threads without the subscriber. Use Builder::new_current_thread() or \
             #[skuld::test] async fn (which builds a current-thread runtime). \
             See https://github.com/bindreams/hole/issues/302",
        );
    }
    #[allow(clippy::disallowed_methods)] // canonical wrapper — see module doc
    tracing::subscriber::set_default(subscriber)
}
