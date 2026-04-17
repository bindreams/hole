//! TUN device lifecycle — cross-platform open + per-platform driver loading.

mod config;
#[cfg(target_os = "windows")]
pub mod wintun;

pub use config::{DeviceConfig, MutDeviceConfig};

use tun::AsyncDevice;

use crate::error::DeviceError;

/// An opened TUN device, ready to be handed to [`Engine::build`](crate::engine::Engine::build).
///
/// Owns the underlying `tun::AsyncDevice` and retains the frozen
/// [`DeviceConfig`] so the engine can consult values like `mtu` without
/// plumbing them separately.
pub struct Device {
    tun: AsyncDevice,
    config: DeviceConfig,
}

impl Device {
    /// Build and open a TUN device.
    ///
    /// ```ignore
    /// let device = Device::build(|c| {
    ///     c.tun_name = "hole-tun".into();
    ///     c.mtu = 1400;
    ///     c.ipv4 = Some("10.255.0.1/24".parse().unwrap());
    ///     c.ipv6 = Some("fd00::ff00:1/64".parse().unwrap());
    /// })?;
    /// ```
    pub fn build<F>(init: F) -> Result<Self, DeviceError>
    where
        F: FnOnce(&mut MutDeviceConfig),
    {
        let mut c = MutDeviceConfig::default();
        init(&mut c);

        if c.tun_name.is_empty() {
            return Err(DeviceError::InvalidConfig("tun_name is required"));
        }
        if c.mtu == 0 {
            return Err(DeviceError::InvalidConfig("mtu is required"));
        }
        if c.ipv4.is_none() && c.ipv6.is_none() {
            return Err(DeviceError::InvalidConfig("at least one of ipv4 / ipv6 must be set"));
        }

        let config = c.freeze();

        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(&config.tun_name).mtu(config.mtu).up();
        if let Some(cidr) = config.ipv4 {
            let addr = cidr.address();
            let mask = std::net::Ipv4Addr::from(v4_mask(cidr.prefix_len()));
            tun_config.address(addr).netmask(mask);
        }
        // IPv6: the `tun` crate's `Configuration` doesn't expose a v6
        // address setter — the OS assigns one via route/addr commands
        // elsewhere (or via smoltcp's internal address list for routing).
        // Engine::build configures the smoltcp interface with both addrs
        // regardless.

        let tun = tun::create_as_async(&tun_config).map_err(|e| DeviceError::TunOpen(std::io::Error::other(e)))?;

        Ok(Self { tun, config })
    }

    /// Access the frozen configuration.
    pub fn config(&self) -> &DeviceConfig {
        &self.config
    }

    /// Consume and return the underlying async TUN device. Used by the
    /// engine to drive its packet loop.
    #[doc(hidden)]
    pub fn into_inner(self) -> (AsyncDevice, DeviceConfig) {
        (self.tun, self.config)
    }
}

fn v4_mask(prefix_len: u8) -> [u8; 4] {
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len as u32)
    };
    mask.to_be_bytes()
}
