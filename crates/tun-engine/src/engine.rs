//! The TUN2* engine — smoltcp-backed packet loop that dispatches inbound
//! flows to a caller-supplied [`Router`].
//!
//! Construction is closure-based:
//!
//! ```ignore
//! let device = Device::build(|c| {
//!     c.tun_name = "hole-tun".into();
//!     c.mtu = 1400;
//!     c.ipv4 = Some("10.255.0.1/24".parse().unwrap());
//!     c.ipv6 = Some("fd00::ff00:1/64".parse().unwrap());
//! })?;
//! let router = Arc::new(my_router);
//! let engine = Engine::build(device, router, |c| {
//!     c.max_connections = 4096;
//!     // Optional: c.dns_interceptor = Some(Arc::new(my_dns_interceptor));
//! })?;
//! engine.run(cancel_token).await;
//! ```

mod config;
mod dns;
// Widened so `sim::packet` (a sibling of `engine`, not a descendant) can
// reach `driver::build_udp_packet` — there is no dedicated emitter module in
// this tree yet (bindreams/hole#900 is unmerged), so the packet-builder the
// simulator needs to share still lives on `Driver`'s own module.
pub(crate) mod driver;
mod router;
mod tcp_flow;
pub(crate) mod udp_flow;
mod virtual_device;

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tun::AsyncDevice;

pub use config::{EngineConfig, MutEngineConfig};
pub use dns::DnsInterceptor;
pub use router::{Router, TcpMeta, UdpMeta};
pub use tcp_flow::TcpFlow;
pub use udp_flow::{FlowKey, UdpFlow, UdpSender};

use crate::device::{Device, DeviceConfig};
use crate::error::EngineError;

/// The engine. Owns the packet I/O, the Router, and runtime config.
///
/// `T` defaults to `tun::AsyncDevice`, the real adapter opened by
/// [`Engine::build`]. [`Engine::from_io`] drives the same packet loop over
/// any other `AsyncRead + AsyncWrite` — see its doc for the framing
/// contract a substitute must uphold.
///
/// Driven to completion via [`Engine::run`].
pub struct Engine<T = AsyncDevice> {
    tun: T,
    device_config: DeviceConfig,
    router: Arc<dyn Router>,
    config: Arc<EngineConfig>,
}

impl Engine<AsyncDevice> {
    /// Build an engine from a ready TUN device + a Router, with optional
    /// configuration via a closure.
    ///
    /// The closure mutates a `MutEngineConfig` seeded with sensible
    /// defaults; after the closure returns, the config is frozen and no
    /// further mutation is possible.
    pub fn build<F>(device: Device, router: Arc<dyn Router>, init: F) -> Result<Self, EngineError>
    where
        F: FnOnce(&mut MutEngineConfig),
    {
        let (tun, device_config) = device.into_inner();
        Self::from_io(tun, device_config, router, init)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Engine<T> {
    /// Build an engine from any packet-framed I/O, bypassing
    /// [`Device::build`]'s real-adapter open.
    ///
    /// Framing contract `io` must uphold: one `poll_read` yields exactly one
    /// IP packet; one `write_all` writes exactly one IP packet. A real TUN
    /// device satisfies this (wintun and a character device each
    /// deliver/accept a whole packet per call, and macOS's 4-byte utun
    /// protocol header is stripped/prepended inside `tun-0.8.14` before the
    /// engine ever sees a buffer); `sim::SimTun` (test-only; not a doc link
    /// since `sim` is feature-gated out of a plain build) is the sanctioned
    /// in-memory implementation for tests.
    pub fn from_io<F>(io: T, device_config: DeviceConfig, router: Arc<dyn Router>, init: F) -> Result<Self, EngineError>
    where
        F: FnOnce(&mut MutEngineConfig),
    {
        // `Device::build` enforces both of these; `from_io` bypasses that
        // gate, so a violation here is a caller contract bug, not user
        // input to reject gracefully.
        debug_assert!(device_config.mtu > 0, "from_io: device_config.mtu must be > 0");
        debug_assert!(
            device_config.ipv4.is_some() || device_config.ipv6.is_some(),
            "from_io: device_config must set at least one of ipv4 / ipv6"
        );

        let mut c = MutEngineConfig::default();
        init(&mut c);
        let config = Arc::new(c.freeze());
        Ok(Self {
            tun: io,
            device_config,
            router,
            config,
        })
    }

    /// Run the engine until the cancel token fires or the TUN device
    /// closes.
    pub async fn run(self, cancel: CancellationToken) {
        let driver = driver::Driver::new(self.tun, self.device_config, self.router, self.config, cancel);
        driver.run().await;
    }
}
