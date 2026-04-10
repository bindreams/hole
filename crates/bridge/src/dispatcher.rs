//! TCP dispatcher — owns the TUN device and smoltcp interface, runs
//! per-connection filter decisions, and dispatches to proxy/bypass/block
//! paths. Constructed by `ProxyManager::start`, destroyed on `stop`.

pub mod block_log;
pub mod bypass;
pub mod device;
pub mod driver;
pub mod smoltcp_stream;
pub mod socks5_client;
pub mod socks5_udp;
pub mod tcp_handler;
pub mod udp_flow;
pub mod upstream_dns;

use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use self::block_log::BlockLog;
use self::driver::{TunDriver, MTU};
use self::tcp_handler::HandlerContext;
use self::upstream_dns::UpstreamResolver;
use crate::filter::rules::RuleSet;
use crate::filter::FakeDns;

/// The main dispatcher — owns the TUN device (via the driver) and
/// coordinates per-connection filter decisions.
pub struct Dispatcher {
    rules: Arc<ArcSwap<RuleSet>>,
    cancel: CancellationToken,
    /// `Option` so `shutdown()` can take it for graceful await.
    /// `Drop` aborts via `driver_abort` as a safety net.
    driver_handle: Option<JoinHandle<()>>,
    driver_abort: AbortHandle,
}

impl Dispatcher {
    /// Create and start the dispatcher.
    ///
    /// - `local_port`: SS SOCKS5 listen port on 127.0.0.1.
    /// - `iface_index`: upstream interface index for bypass sockets.
    /// - `ipv6_available`: whether the upstream has IPv6.
    /// - `rules`: compiled filter rules.
    /// - `dns_servers`: upstream DNS server IPs (discovered before TUN up).
    pub fn new(
        local_port: u16,
        iface_index: u32,
        ipv6_available: bool,
        udp_proxy_available: bool,
        rules: RuleSet,
        dns_servers: &[IpAddr],
    ) -> std::io::Result<Self> {
        // Create TUN device.
        let mut tun_config = tun::Configuration::default();
        tun_config
            .tun_name("hole-tun")
            .address("10.255.0.1")
            .netmask("255.255.255.0")
            .mtu(MTU as u16)
            .up();

        let tun_device = tun::create_as_async(&tun_config)
            .map_err(|e| std::io::Error::other(format!("failed to create TUN device: {e}")))?;

        // Set up shared state.
        let rules_arc = Arc::new(ArcSwap::from_pointee(rules.clone()));

        // FakeDns — only when domain rules exist.
        let fake_dns = if rules.has_domain_rules {
            Some(Arc::new(FakeDns::with_defaults()))
        } else {
            None
        };

        // Upstream resolver.
        let upstream_resolver = UpstreamResolver::new(dns_servers);

        // Handler context (shared by all TCP handlers).
        let handler_ctx = Arc::new(HandlerContext {
            local_port,
            iface_index,
            ipv6_available,
            upstream_resolver,
            block_log: std::sync::Mutex::new(BlockLog::new()),
            ipv6_bypass_warned: AtomicBool::new(false),
            udp_proxy_available,
        });

        // Cancellation token.
        let cancel = CancellationToken::new();

        // Create and spawn the driver.
        let driver = TunDriver::new(
            tun_device,
            fake_dns,
            Arc::clone(&rules_arc),
            handler_ctx,
            cancel.clone(),
        );

        let driver_handle = tokio::spawn(driver.run());
        let driver_abort = driver_handle.abort_handle();

        debug!("Dispatcher started (local_port={local_port}, iface_index={iface_index})");

        Ok(Self {
            rules: rules_arc,
            cancel,
            driver_handle: Some(driver_handle),
            driver_abort,
        })
    }

    /// Hot-swap the filter rules without restarting the dispatcher.
    pub fn swap_rules(&self, new_rules: RuleSet) {
        self.rules.store(Arc::new(new_rules));
    }

    /// Graceful shutdown. Cancels the driver, waits up to 2s, then
    /// aborts if needed. Idempotent — safe to call multiple times or
    /// after Drop has already aborted.
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

/// Cancel the driver and abort it on drop. This ensures that implicit
/// drops (e.g., from `check_health` or a cancelled `start_cancellable`)
/// do not leak the driver task. `shutdown()` is preferred for graceful
/// teardown, but the `Drop` provides a safety net.
impl Drop for Dispatcher {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.driver_abort.abort();
    }
}
