//! TCP/UDP dispatcher — thin orchestrator around `tun_engine::Engine` and
//! [`HoleRouter`](crate::hole_router::HoleRouter).
//!
//! Owned by `ProxyManager::start`, destroyed on `stop`. The actual
//! packet-loop and smoltcp state live inside `tun_engine`; this struct
//! just hands it a prepared Device + Router and drives the engine's run
//! loop on a background task.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use tun_engine::{Assigned, Device, Engine, MutDeviceConfig, TunIdentity};

use crate::drop_sink::LoggingDropSink;
use crate::endpoint::{InterfaceEndpoint, LocalDnsEndpoint, Socks5Endpoint};
use crate::filter::rules::RuleSet;
use crate::hole_router::HoleRouter;
use crate::proxy::{TUN_DEVICE_NAME, TUN_SUBNET, TUN_SUBNET6};

/// How the spawned driver task ended, reported by `drain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverExit {
    /// The task returned normally — the TUN device (and kernel adapter
    /// handle) it owned is dropped.
    Drained,
    /// The task was aborted before it returned.
    Aborted,
    /// The task panicked.
    Panicked,
    /// `shutdown()` was called again after already draining the driver.
    AlreadyDrained,
}

/// What [`Dispatcher::new`] can fail with. Keeps `tun_engine::DeviceError`
/// distinguishable from every other start-time I/O failure, so a caller can
/// match the specific variant (e.g. `DeviceError::ForeignAdapter`) instead
/// of a flattened `io::Error` whose type information is already gone.
#[derive(Debug, thiserror::Error)]
pub enum DispatcherStartError {
    #[error(transparent)]
    Device(#[from] tun_engine::DeviceError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Awaits `handle` in place and classifies how the driver task ended. No
/// bound: `Driver::run` observes its cancellation token at every await
/// (see `tun_engine::engine::{dns, egress}`), so this can only hang if
/// that guarantee is broken.
pub(crate) async fn drain(handle: &mut JoinHandle<()>) -> DriverExit {
    match handle.await {
        Ok(()) => DriverExit::Drained,
        Err(e) if e.is_cancelled() => DriverExit::Aborted,
        Err(e) if e.is_panic() => DriverExit::Panicked,
        Err(e) => {
            warn!("Dispatcher driver join error: {e}");
            DriverExit::Panicked
        }
    }
}

/// The main dispatcher — owns the TUN device (via the engine driver)
/// and coordinates per-connection filter decisions (via `HoleRouter`).
pub struct Dispatcher {
    router: Arc<HoleRouter>,
    cancel: CancellationToken,
    /// Cleared only once a [`DriverExit`] exists for it — a `shutdown()`
    /// future dropped mid-drain leaves this `Some` so `Drop` can still
    /// drain the task rather than detaching it.
    driver_handle: Option<JoinHandle<()>>,
    driver_abort: AbortHandle,
    /// Panics in debug builds if dropped without an awaited `shutdown()`.
    /// See `SystemDnsApplied` for the same discipline.
    bomb: drop_bomb::DebugDropBomb,
    ipv6_assigned: Option<Assigned>,
    /// The identity of the TUN device this dispatcher opened. Captured
    /// before the device is consumed by `Engine::build`; threaded to
    /// `Dns::apply` (bindreams/hole#846) so DNS is confined to the adapter
    /// this process actually opened, never a name lookup.
    identity: TunIdentity,
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
    ///   `Some` whenever DNS is enabled (and not SocksOnly mode).
    /// - `cancel`: the start's cancel token. `Ok(None)` means it fired while
    ///   the device was being built; the half-built device is dropped on the
    ///   blocking thread that owns it, releasing the adapter.
    // Every parameter is an independent start-time input; bundling them into a
    // struct adds more noise than the warning.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        local_port: u16,
        iface_index: u32,
        ipv6_available: bool,
        plugin_name: Option<String>,
        plugin_supports_udp: bool,
        rules: RuleSet,
        local_dns_endpoint: Option<LocalDnsEndpoint>,
        cancel: &CancellationToken,
    ) -> Result<Option<Self>, DispatcherStartError> {
        // Open the TUN device.
        let v4_cidr = TUN_SUBNET
            .parse()
            .expect("TUN_SUBNET is a hard-coded valid CIDR string");
        let v6_cidr: smoltcp::wire::Ipv6Cidr = TUN_SUBNET6
            .parse()
            .expect("TUN_SUBNET6 is a hard-coded valid CIDR string");

        let built = build_or_cancel(cancel, move || {
            Device::build(|c: &mut MutDeviceConfig| {
                c.tun_name = TUN_DEVICE_NAME.into();
                c.mtu = 1400;
                c.ipv4 = Some(v4_cidr);
                c.ipv6 = Some(v6_cidr);
            })
        })
        .await;
        let Some(device) = built else {
            return Ok(None);
        };
        let device = device?;

        // Give hole-tun the lowest possible interface metric so Windows
        // prefers whatever resolver Hole advertises over the physical
        // adapter's (#846's positive half; the negative half is
        // `tun_engine::dns_confine`). IPv4 absence is fatal — a v4 row must
        // exist for an adapter that was just created. IPv6 absence is
        // logged and accepted: the host may have IPv6 off, or the v6 row
        // may not have appeared yet — see `tun_engine::net::metric`'s
        // module doc for why that race is reported, not asserted away.
        #[cfg(target_os = "windows")]
        {
            use tun_engine::net::metric::{set_interface_metric, Family, MetricOutcome, TUNNEL_INTERFACE_METRIC};
            let luid = device.identity().luid();
            match set_interface_metric(luid, TUNNEL_INTERFACE_METRIC, Family::V4) {
                Ok(MetricOutcome::Applied) => {}
                Ok(MetricOutcome::NoInterfaceRow) => {
                    return Err(
                        std::io::Error::other("hole-tun has no IPv4 interface row immediately after creation").into(),
                    );
                }
                Err(e) => {
                    return Err(
                        std::io::Error::other(format!("failed to set hole-tun's IPv4 interface metric: {e}")).into(),
                    );
                }
            }
            match set_interface_metric(luid, TUNNEL_INTERFACE_METRIC, Family::V6) {
                Ok(MetricOutcome::Applied) => {}
                Ok(MetricOutcome::NoInterfaceRow) => {
                    warn!("hole-tun has no IPv6 interface row yet; IPv6 metric not set (host may lack IPv6, or the row has not appeared)");
                }
                Err(e) => {
                    return Err(
                        std::io::Error::other(format!("failed to set hole-tun's IPv6 interface metric: {e}")).into(),
                    );
                }
            }
        }

        // Read BEFORE `Engine::build`: that consumes the device through
        // `Device::into_inner`, which returns only the `AsyncDevice` and the
        // frozen config, so no later read is possible.
        let ipv6_assigned = device.ipv6_assigned();

        // Captured BEFORE `Engine::build` consumes `device` below — this is
        // the identity of the concrete OS object this call opened, never a
        // name lookup (bindreams/hole#846).
        let identity = device.identity().clone();

        // Build the two endpoints, the drop sink, and the HoleRouter.
        let proxy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_port);
        let proxy = Socks5Endpoint::new(proxy_addr, plugin_name, plugin_supports_udp);
        let bypass = InterfaceEndpoint::new(iface_index, ipv6_available);
        let drops = LoggingDropSink::new();
        let router = Arc::new(HoleRouter::with_local_dns(
            proxy,
            bypass,
            drops,
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
        let subsystem_cancel = CancellationToken::new();
        let cancel_for_driver = subsystem_cancel.clone();
        let driver_handle = tokio::spawn(async move {
            engine.run(cancel_for_driver).await;
        });
        let driver_abort = driver_handle.abort_handle();

        debug!("Dispatcher started (local_port={local_port}, iface_index={iface_index})");

        Ok(Some(Self {
            router,
            cancel: subsystem_cancel,
            driver_handle: Some(driver_handle),
            driver_abort,
            bomb: drop_bomb::DebugDropBomb::new(
                "Dispatcher dropped without shutdown().await — the wintun adapter handle may leak",
            ),
            ipv6_assigned,
            identity,
        }))
    }

    /// What the OS TUN interface ended up holding for [`TUN_SUBNET6`].
    ///
    /// `Ipv6StackAbsent` is the second operand of the route-install fatality
    /// rule: the IPv6 route adds are non-fatal when the upstream has no IPv6
    /// **or** the TUN interface has no IPv6 half.
    pub fn ipv6_assigned(&self) -> Option<Assigned> {
        self.ipv6_assigned
    }

    /// Get the list of invalid (dropped) filter rules from the current ruleset.
    pub fn invalid_filters(&self) -> Vec<hole_common::protocol::InvalidFilter> {
        self.router.invalid_filters()
    }

    /// Hot-swap the filter rules without restarting the dispatcher.
    pub fn swap_rules(&self, new_rules: RuleSet) {
        self.router.swap_rules(new_rules);
    }

    /// The identity of the TUN device this dispatcher opened — the LUID and
    /// alias of the concrete OS object, not a name lookup. See
    /// `crate::proxy_manager::start_inner`'s Phase 7.
    pub fn identity(&self) -> &TunIdentity {
        &self.identity
    }

    /// Graceful shutdown. Cancels the driver, then joins its task with no
    /// bound — sound because `Driver::run` observes the same token at
    /// every await (`tun_engine::engine::{dns, egress}`), so the task is
    /// guaranteed to return once cancelled. Awaits through `&mut` rather
    /// than taking the handle, so a caller that drops this future mid-drain
    /// leaves `driver_handle` in place for `Drop` to finish draining
    /// instead of detaching the task. Idempotent — a second call reports
    /// [`DriverExit::AlreadyDrained`].
    ///
    /// What this actually waits for, on Windows: `Driver::run` returning
    /// drops the `tun::AsyncDevice`, which runs the synchronous
    /// `WintunCloseAdapter` call (plus a registry subtree delete) in its
    /// `Drop`. That call is finite and uninterruptible — the reason a
    /// bound here would leak the adapter rather than merely being
    /// unnecessary.
    pub async fn shutdown(&mut self) -> DriverExit {
        debug!("Dispatcher shutting down");
        self.cancel.cancel();

        let exit = match self.driver_handle.as_mut() {
            None => DriverExit::AlreadyDrained,
            Some(handle) => {
                let started = Instant::now();
                debug!("Dispatcher draining driver");
                let exit = drain(handle).await;
                debug!(
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    ?exit,
                    "Dispatcher driver drained"
                );
                self.driver_handle = None;
                exit
            }
        };

        self.bomb.defuse();
        debug!("Dispatcher shutdown complete");
        exit
    }
}

/// Run `build` on a blocking thread, racing it against `cancel`; `None` when
/// the cancel won.
///
/// The device build can block on an OS interface-appearance notification, so
/// it must neither occupy a tokio worker nor outlive a Cancel — on a covered
/// (auto-connect) start the user's whole host stays fail-closed for exactly
/// that window. Nothing is future-drop-cancelled: on cancel the blocking task
/// runs to completion and drops its own `Device` there, releasing the wintun
/// adapter.
async fn build_or_cancel<T, F>(cancel: &CancellationToken, build: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let task = tokio::task::spawn_blocking(build);
    tokio::select! {
        biased;
        _ = cancel.cancelled() => None,
        // The task is never aborted, so a `JoinError` is always a panic.
        r = task => Some(r.unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))),
    }
}

/// Safety net for non-graceful paths (panic, cancel mid-`start_inner`, a
/// dropped future that owned this `Dispatcher`) — `shutdown()` is the
/// preferred, graceful teardown and clears `driver_handle` once it has
/// drained the task, so the normal stop path only runs the no-op `None`
/// arm below.
///
/// On the bridge's multi-thread runtime this always takes the
/// `MultiThread` arm and blocks — for as long as the driver task takes to
/// observe cancellation and return, plus the WintunCloseAdapter call in
/// its `Drop` — before this method returns. **Dropping a future that owns
/// a `Dispatcher` does not cancel that wait; it converts it into a
/// synchronous block on the dropping thread.** No caller may drop such a
/// future as a way to bound anything.
impl Drop for Dispatcher {
    fn drop(&mut self) {
        self.cancel.cancel();

        let Some(handle) = self.driver_handle.as_mut() else {
            // shutdown() already drained it; nothing to do.
            self.driver_abort.abort();
            return;
        };

        match tokio::runtime::Handle::try_current() {
            Ok(rt) if matches!(rt.runtime_flavor(), tokio::runtime::RuntimeFlavor::MultiThread) => {
                // `block_in_place` releases this worker thread so the driver
                // task can be polled to completion on another one — the
                // `MultiThread` gate above is what makes that legal.
                // `rt.block_on` then blocks on that same runtime from
                // inside the released region.
                let exit = tokio::task::block_in_place(|| rt.block_on(drain(handle)));
                self.driver_handle = None;
                self.bomb.defuse();
                match exit {
                    DriverExit::Drained => debug!("Dispatcher driver drained"),
                    DriverExit::Aborted => warn!("Dispatcher driver was aborted"),
                    DriverExit::Panicked => warn!("Dispatcher driver panicked"),
                    DriverExit::AlreadyDrained => {
                        unreachable!("handle was Some; drain() cannot report AlreadyDrained")
                    }
                }
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

#[cfg(test)]
#[path = "dispatcher_tests.rs"]
mod dispatcher_tests;
