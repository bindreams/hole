//! TCP/UDP dispatcher — thin orchestrator around `tun_engine::Engine` and
//! [`HoleRouter`](crate::hole_router::HoleRouter).
//!
//! Owned by `ProxyManager::start`, destroyed on `stop`. The actual
//! packet-loop and smoltcp state live inside `tun_engine`; this struct
//! just hands it a prepared Device + Router and drives the engine's run
//! loop on a background task.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use tun_engine::{Device, Engine, MutDeviceConfig};

use crate::endpoint::{BlockEndpoint, InterfaceEndpoint, LocalDnsEndpoint, Socks5Endpoint};
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
    /// - `plugin_name`: optional human-readable plugin identifier, for
    ///   diagnostic logs. Kept adjacent to `plugin_supports_udp` — both
    ///   describe the plugin.
    /// - `plugin_supports_udp`: whether the configured plugin can carry
    ///   UDP through the SS tunnel. When `false`, the router's cascade
    ///   drops UDP flows whose rule resolved to `Proxy` instead of
    ///   falling back to the clear-text bypass (privacy invariant).
    /// - `rules`: compiled filter rules.
    /// - `local_dns_endpoint`: optional in-tunnel DNS interceptor. When
    ///   `Some`, the router diverts UDP/53 flows to it. Callers pass
    ///   `Some` when the `DnsConfig.intercept_udp53` flag is set and the
    ///   forwarder has bound successfully.
    pub fn new(
        local_port: u16,
        iface_index: u32,
        ipv6_available: bool,
        plugin_name: Option<String>,
        plugin_supports_udp: bool,
        rules: RuleSet,
        local_dns_endpoint: Option<LocalDnsEndpoint>,
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

        // Build the three endpoints and the HoleRouter.
        let proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_port);
        let proxy = Socks5Endpoint::new(proxy_addr, plugin_name, plugin_supports_udp);
        let bypass = InterfaceEndpoint::new(iface_index, ipv6_available);
        let block = BlockEndpoint::new();
        let router = Arc::new(HoleRouter::with_local_dns(
            proxy,
            bypass,
            block,
            local_dns_endpoint,
            rules,
        ));

        // Build the engine. Hole no longer registers a DnsInterceptor —
        // DNS queries traverse the tunnel like any other traffic, and
        // names are recovered from TLS/HTTP peek at connect time.
        let router_for_engine: Arc<dyn tun_engine::Router> = router.clone();
        let engine = Engine::build(device, router_for_engine, |_c| {})
            .map_err(|e| std::io::Error::other(format!("failed to build engine: {e}")))?;

        // Cancellation token drives shutdown.
        #[allow(clippy::disallowed_methods)]
        // Dispatcher owns its own subsystem cancel scope (tied to its lifecycle, not the start-cancel). See clippy.toml CancellationToken::new rule.
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

/// Cancel the driver and synchronously drain the spawned task so the
/// wintun adapter handle (owned by the future) is dropped before this
/// method returns. `shutdown()` is preferred for graceful teardown; the
/// `Drop` provides a safety net for non-graceful paths (panic, cancel
/// mid-`start_inner`, `start_inner` Err that drops the local dispatcher).
///
/// **#388 rationale**: pre-#388 this only called `cancel + abort`. The
/// spawned task that owns the `tun::AsyncDevice` (and therefore the
/// kernel wintun adapter handle) was abort-flagged but not joined, so
/// runtime shutdown could happen before the task was polled to its end —
/// leaving the kernel adapter alive until reboot or
/// `scripts/network-reset.py`. `block_on` inside Drop works on the
/// multi-thread runtime the bridge uses in production. Current-thread
/// runtimes (skuld tests) take the abort-only fallback path, with the
/// PowerShell `Remove-NetAdapter` shell-out in `SystemRoutes::drop` as
/// the belt-and-suspenders second layer.
///
/// **Graceful path interaction**: `ProxyManager::stop` →
/// `Dispatcher::shutdown` already calls
/// `tokio::time::timeout(2s, handle).await`, so the handle is `None`
/// here on the normal stop path and only the abort fallback runs
/// (a no-op).
impl Drop for Dispatcher {
    fn drop(&mut self) {
        self.cancel.cancel();

        let Some(handle) = self.driver_handle.take() else {
            // shutdown() already awaited; nothing to drain.
            self.driver_abort.abort();
            return;
        };

        match tokio::runtime::Handle::try_current() {
            Ok(rt) if matches!(rt.runtime_flavor(), tokio::runtime::RuntimeFlavor::MultiThread) => {
                // CRITICAL: use `rt.block_on`, NOT `futures::executor::block_on`.
                // The `timeout` future needs the tokio reactor; an external
                // executor would panic with "no reactor running."
                // `block_in_place` keeps the worker thread available for
                // other tasks. It panics on a current-thread runtime —
                // that's why we gated on `MultiThread` above.
                tokio::task::block_in_place(|| {
                    let _ = rt.block_on(tokio::time::timeout(std::time::Duration::from_secs(2), handle));
                });
            }
            _ => {
                // Current-thread runtime (skuld tests) or no runtime —
                // `block_in_place` would panic. Abort and rely on the
                // defensive `adapter_cleanup` in `SystemRoutes::drop` to
                // sweep any leaked wintun adapter.
                self.driver_abort.abort();
            }
        }
    }
}
