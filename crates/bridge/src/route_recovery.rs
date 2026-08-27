//! Startup route + standing-cover recovery, and the one place its verdict is
//! recorded on the [`ProxyManager`].
//!
//! `tun_engine::routing::recover_routes` returns a decision the bridge must not
//! discard: an `Adopt` means a standing kill-switch cover is live right now,
//! which the tray's escape and the connect path both need to know regardless of
//! what `bridge-lockdown.json` says (it may be missing, corrupt, or a different
//! install's). Routing every entry point through this one function is what
//! stops a third caller from recovering without recording.

use std::path::Path;
use std::sync::Arc;

use tokio::sync::Mutex;
use tun_engine::routing::{CoverRecovery, Routing};

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
    match tokio::task::spawn_blocking(move || tun_engine::routing::recover_routes(&dir, owner)).await {
        Ok(recovery) => {
            proxy
                .lock()
                .await
                .set_standing_cover_adopted(recovery.action == CoverRecovery::Adopt);
        }
        Err(e) => tracing::warn!(error = %e, "recover_routes task panicked"),
    }
}

#[cfg(test)]
#[path = "route_recovery_tests.rs"]
mod route_recovery_tests;
