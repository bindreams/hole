//! The bridge's boot sequence, in the one order all three entry points share.

use std::path::Path;
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tun_engine::routing::{Recovery, Routing};

use crate::dns::system::Dns;
use crate::proxy::Proxy;
use crate::proxy_manager::ProxyManager;

/// Recover what a previous bridge left behind, then reconcile the persisted
/// target. Runs once, after the IPC socket is bound and before it is served.
pub async fn recover_then_reconcile<P, R, D>(proxy: &Arc<Mutex<ProxyManager<P, R, D>>>, cancel: &CancellationToken)
where
    P: Proxy,
    R: Routing + 'static,
    D: Dns,
{
    recover_then_reconcile_with(proxy, cancel, crate::route_recovery::recover_bridge_routes).await;
}

/// [`recover_then_reconcile`] with the route-recovery verdict injected, for
/// tests: the real one finds a live cover only with elevation.
pub(crate) async fn recover_then_reconcile_with<P, R, D, F>(
    proxy: &Arc<Mutex<ProxyManager<P, R, D>>>,
    cancel: &CancellationToken,
    recover: F,
) where
    P: Proxy,
    R: Routing + 'static,
    D: Dns,
    F: FnOnce(&Path, Option<(u32, u32)>) -> Recovery + Send + 'static,
{
    let state_dir = proxy.lock().await.routing_handle().state_dir().to_path_buf();
    crate::route_recovery::recover_and_record(proxy, recover).await;
    // Before the reconcile: the reap kills every plugin the state file records
    // and cannot tell a previous bridge's from the one the reconcile's
    // auto-connect is about to record.
    reap_leftover_plugins(&state_dir).await;
    crate::reconciler::reconcile_once(proxy, cancel).await;
}

async fn reap_leftover_plugins(state_dir: &Path) {
    let state_dir = state_dir.to_path_buf();
    if let Err(e) = tokio::task::spawn_blocking(move || crate::plugin_recovery::reap_recorded_plugins(&state_dir)).await
    {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "reap_recorded_plugins task panicked"
        );
    }
}

#[cfg(test)]
#[path = "boot_tests.rs"]
mod boot_tests;
