//! TCP/UDP dispatcher — thin orchestrator around `tun_engine::Engine` and
//! [`HoleRouter`](crate::hole_router::HoleRouter).
//!
//! Owned by `ProxyManager::start`, destroyed on `stop`. The actual
//! packet-loop and smoltcp state live inside `tun_engine`; this struct
//! just hands it a prepared Device + Router and drives the engine's run
//! loop on a background task.

use std::sync::Arc;

use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use tun_engine::{Device, Engine, MutDeviceConfig};

use crate::filter::rules::RuleSet;
use crate::hole_router::HoleRouter;
use crate::proxy::{TUN_DEVICE_NAME, TUN_SUBNET};

/// The main dispatcher — owns the TUN device (via the engine driver)
/// and coordinates per-connection filter decisions (via `HoleRouter`).
pub struct Dispatcher {
    router: Arc<HoleRouter>,
    cancel: CancellationToken,
    /// `Option` so `shutdown()` can take it for graceful await. `Drop`
    /// aborts via `driver_abort` as a safety net.
    driver_handle: Option<JoinHandle<()>>,
    driver_abort: AbortHandle,
}

impl Dispatcher {
    /// Create and start the dispatcher.
    ///
    /// - `local_port`: SS SOCKS5 listen port on 127.0.0.1.
    /// - `iface_index`: upstream interface index for bypass sockets.
    /// - `ipv6_available`: whether the upstream has IPv6.
    /// - `udp_proxy_available`: whether the plugin (if any) supports UDP relay.
    /// - `rules`: compiled filter rules.
    pub fn new(
        local_port: u16,
        iface_index: u32,
        ipv6_available: bool,
        udp_proxy_available: bool,
        rules: RuleSet,
    ) -> std::io::Result<Self> {
        // Open the TUN device.
        let v4_cidr = TUN_SUBNET
            .parse()
            .expect("TUN_SUBNET is a hard-coded valid CIDR string");
        let v6_cidr: smoltcp::wire::Ipv6Cidr = "fd00::ff00:1/64".parse().expect("hard-coded IPv6 CIDR is valid");

        let device = Device::build(|c: &mut MutDeviceConfig| {
            c.tun_name = TUN_DEVICE_NAME.into();
            c.mtu = 1400;
            c.ipv4 = Some(v4_cidr);
            c.ipv6 = Some(v6_cidr);
        })
        .map_err(|e| std::io::Error::other(format!("failed to create TUN device: {e}")))?;

        // Build the HoleRouter.
        let router = Arc::new(HoleRouter::new(
            local_port,
            iface_index,
            ipv6_available,
            udp_proxy_available,
            rules,
        ));

        // Build the engine. Hole no longer registers a DnsInterceptor —
        // DNS queries traverse the tunnel like any other traffic, and
        // names are recovered from TLS/HTTP peek at connect time.
        let router_for_engine: Arc<dyn tun_engine::Router> = router.clone();
        let engine = Engine::build(device, router_for_engine, |_c| {})
            .map_err(|e| std::io::Error::other(format!("failed to build engine: {e}")))?;

        // Cancellation token drives shutdown.
        let cancel = CancellationToken::new();
        let cancel_for_driver = cancel.clone();
        let driver_handle = tokio::spawn(async move {
            engine.run(cancel_for_driver).await;
        });
        let driver_abort = driver_handle.abort_handle();

        debug!("Dispatcher started (local_port={local_port}, iface_index={iface_index})");

        Ok(Self {
            router,
            cancel,
            driver_handle: Some(driver_handle),
            driver_abort,
        })
    }

    /// Get the list of invalid (dropped) filter rules from the current ruleset.
    pub fn invalid_filters(&self) -> Vec<hole_common::protocol::InvalidFilter> {
        self.router.invalid_filters()
    }

    /// Hot-swap the filter rules without restarting the dispatcher.
    pub fn swap_rules(&self, new_rules: RuleSet) {
        self.router.swap_rules(new_rules);
    }

    /// Graceful shutdown. Cancels the driver, waits up to 2s, then aborts
    /// if needed. Idempotent — safe to call multiple times or after Drop
    /// has already aborted.
    pub async fn shutdown(&mut self) {
        debug!("Dispatcher shutting down");
        self.cancel.cancel();

        if let Some(handle) = self.driver_handle.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(2), handle).await {
                Ok(Ok(())) => debug!("Dispatcher driver exited cleanly"),
                Ok(Err(e)) if e.is_cancelled() => debug!("Dispatcher driver was aborted"),
                Ok(Err(e)) => warn!("Dispatcher driver panicked: {e}"),
                Err(_) => {
                    warn!("Dispatcher driver did not exit in 2s, aborting");
                    self.driver_abort.abort();
                }
            }
        }

        debug!("Dispatcher shutdown complete");
    }
}

/// Cancel the driver and abort it on drop. This ensures implicit drops
/// (e.g., from `check_health` or a cancelled `start_cancellable`) do not
/// leak the driver task. `shutdown()` is preferred for graceful teardown,
/// but the `Drop` provides a safety net.
impl Drop for Dispatcher {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.driver_abort.abort();
    }
}
