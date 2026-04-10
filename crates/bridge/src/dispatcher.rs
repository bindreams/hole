//! TCP dispatcher — owns the TUN device and smoltcp interface, runs
//! per-connection filter decisions, and dispatches to proxy/bypass/block
//! paths. Constructed by `ProxyManager::start`, destroyed on `stop`.

pub mod block_log;
pub mod bypass;
pub mod device;
pub mod driver;
pub mod smoltcp_stream;
pub mod socks5_client;
pub mod tcp_handler;
pub mod upstream_dns;

use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use self::block_log::BlockLog;
use self::driver::{TunDriver, MTU};
use self::tcp_handler::TcpHandlerContext;
use self::upstream_dns::UpstreamResolver;
use crate::filter::rules::RuleSet;
use crate::filter::FakeDns;

/// The main dispatcher — owns the TUN device (via the driver) and
/// coordinates per-connection filter decisions.
pub struct Dispatcher {
    rules: Arc<ArcSwap<RuleSet>>,
    cancel: CancellationToken,
    driver_handle: JoinHandle<()>,
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
        let handler_ctx = Arc::new(TcpHandlerContext {
            local_port,
            iface_index,
            ipv6_available,
            upstream_resolver,
            block_log: std::sync::Mutex::new(BlockLog::new()),
            ipv6_bypass_warned: AtomicBool::new(false),
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

        debug!("Dispatcher started (local_port={local_port}, iface_index={iface_index})");

        Ok(Self {
            rules: rules_arc,
            cancel,
            driver_handle,
        })
    }

    /// Hot-swap the filter rules without restarting the dispatcher.
    pub fn swap_rules(&self, new_rules: RuleSet) {
        self.rules.store(Arc::new(new_rules));
    }

    /// Graceful shutdown.
    ///
    /// 1. Cancel token (signals driver + handlers to stop; driver's
    ///    TUN read is racing against cancelled(), so cancel unblocks it)
    /// 2. Wait up to 2 s for the driver to finish
    /// 3. Abort the driver handle if it doesn't finish in time
    pub async fn shutdown(self) {
        debug!("Dispatcher shutting down");

        // Signal cancellation. The driver's main loop uses `tokio::select!`
        // between TUN read and cancel, so this unblocks the driver promptly.
        self.cancel.cancel();

        // Abort handle before awaiting so we can force-stop on timeout.
        let abort_handle = self.driver_handle.abort_handle();

        // Wait for the driver with a timeout.
        match tokio::time::timeout(std::time::Duration::from_secs(2), self.driver_handle).await {
            Ok(Ok(())) => debug!("Dispatcher driver exited cleanly"),
            Ok(Err(e)) if e.is_cancelled() => debug!("Dispatcher driver was aborted"),
            Ok(Err(e)) => warn!("Dispatcher driver panicked: {e}"),
            Err(_) => {
                warn!("Dispatcher driver did not exit in 2s, aborting");
                abort_handle.abort();
            }
        }

        debug!("Dispatcher shutdown complete");
    }
}
