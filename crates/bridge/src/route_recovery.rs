//! Startup route + standing-cover recovery, and the one place its verdict is
//! recorded on the [`ProxyManager`].
//!
//! `tun_engine::routing::recover_routes` returns a decision the bridge must not
//! discard: an `Adopt` decision paired with a MEASURED-LIVE presence means a
//! standing kill-switch cover is live right now, which the tray's escape and
//! the connect path both need to know regardless of what `bridge-lockdown.json`
//! says (it may be missing, corrupt, or a different install's). `Adopt` alone
//! is not that evidence — it also covers `CoverPresence::Recorded` and
//! `::Indeterminate`, neither of which the OS confirmed — so recording the
//! claim additionally checks `recovery.presence == CoverPresence::Live`.
//! Routing every entry point through this one function is what stops a third
//! caller from recovering without recording.

use std::path::Path;
use std::sync::Arc;

use tokio::sync::Mutex;
use tun_engine::routing::{CoverPresence, CoverRecovery, Recovery, Routing};

use crate::dns::system::Dns;
use crate::proxy::Proxy;
use crate::proxy_manager::ProxyManager;

/// Run crash recovery for routes and the standing lockdown cover, then record
/// on `proxy` whether this run adopted a live standing cover.
///
/// Offloaded to a blocking thread so a hung `netsh`/`route`/`pfctl` cannot
/// wedge the runtime while the IPC socket is bound but not yet serving. A
/// panicked task is logged and leaves the claim false — the conservative
/// direction for the connect path, and the intent file still carries the tray's
/// answer.
pub async fn recover_and_record<P, R, D>(state_dir: &Path, proxy: &Arc<Mutex<ProxyManager<P, R, D>>>)
where
    P: Proxy,
    R: Routing,
    D: Dns,
{
    let dir = state_dir.to_path_buf();
    // Taken from the manager rather than re-derived, so recovery's intent
    // repair cannot chown to a different owner than the manager's own writes.
    let owner = proxy.lock().await.state_owner();
    let outcome = tokio::task::spawn_blocking(move || tun_engine::routing::recover_routes(&dir, owner)).await;
    record_recovery_outcome(outcome, proxy).await;
}

/// Apply a `recover_routes` outcome to `proxy`. Split out of
/// [`recover_and_record`] so tests can drive the claim's logic — including the
/// panicking-task branch, with a REAL [`tokio::task::JoinError`] — without a
/// live OS-level `recover_routes` call, which the WFP/pf presence probe makes
/// impossible to control outside elevation.
async fn record_recovery_outcome<P, R, D>(
    outcome: Result<Recovery, tokio::task::JoinError>,
    proxy: &Arc<Mutex<ProxyManager<P, R, D>>>,
) where
    P: Proxy,
    R: Routing,
    D: Dns,
{
    match outcome {
        Ok(recovery) => {
            // `action == Adopt` alone is not evidence of a LIVE cover — it also
            // covers `CoverPresence::Recorded` and `::Indeterminate`, whose own
            // docs say the OS did NOT confirm one. Gate the claim on the
            // measured presence too, so `lockdown_enabled`/`standing_cover_expected`
            // never assert liveness recovery itself did not confirm.
            let live = recovery.action == CoverRecovery::Adopt && recovery.presence == CoverPresence::Live;
            proxy.lock().await.set_standing_cover_adopted(live);
        }
        Err(e) => {
            // Actively cleared, not merely left at whatever `proxy` started
            // with: `recover_and_record` runs once per bridge startup before
            // anything else could have set the claim, so in practice this is
            // always a no-op — but the guarantee this doc promises ("leaves
            // the claim false") should not rest on that call-ordering
            // invariant holding forever.
            tracing::warn!(error = %e, "recover_routes task panicked");
            proxy.lock().await.set_standing_cover_adopted(false);
        }
    }
}

#[cfg(test)]
#[path = "route_recovery_tests.rs"]
mod route_recovery_tests;
