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
mod driver;
mod router;
mod tcp_flow;
mod udp_flow;
mod virtual_device;

use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tun::AsyncDevice;

pub use config::{EngineConfig, MutEngineConfig};
pub use dns::DnsInterceptor;
pub use router::{Router, TcpMeta, UdpMeta};
pub use tcp_flow::TcpFlow;
pub use udp_flow::{FlowKey, UdpFlow, UdpSender};

use crate::device::{Device, DeviceConfig};
use crate::error::EngineError;

/// The engine. Owns the TUN device, the Router, and runtime config.
///
/// Constructed via [`Engine::build`]; driven to completion via
/// [`Engine::run`].
pub struct Engine {
    tun: AsyncDevice,
    device_config: DeviceConfig,
    router: Arc<dyn Router>,
    config: Arc<EngineConfig>,
}

impl Engine {
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
        let mut c = MutEngineConfig::default();
        init(&mut c);
        let config = Arc::new(c.freeze());
        let (tun, device_config) = device.into_inner();
        Ok(Self {
            tun,
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
