//! TUN device lifecycle — cross-platform open + per-platform driver loading.

mod config;
mod ipv6_addr;
#[cfg(target_os = "windows")]
pub mod wintun;

#[cfg(test)]
#[path = "device_tests.rs"]
mod device_tests;

#[cfg(all(test, target_os = "windows"))]
mod ipv6_addr_privileged_tests;

pub use config::{DeviceConfig, MutDeviceConfig};
pub use ipv6_addr::Assigned;

use tracing::warn;
use tun::{AbstractDevice, AsyncDevice};

use crate::error::DeviceError;

/// An opened TUN device, ready to be handed to [`Engine::build`](crate::engine::Engine::build).
///
/// Owns the underlying `tun::AsyncDevice` and retains the frozen
/// [`DeviceConfig`] so the engine can consult values like `mtu` without
/// plumbing them separately.
pub struct Device {
    tun: AsyncDevice,
    config: DeviceConfig,
    /// `None` when no IPv6 CIDR was configured — the index is resolved only
    /// for the assignment, so `ipv6_assigned` is `None` under exactly the same
    /// condition.
    interface_index: Option<u32>,
    ipv6_assigned: Option<Assigned>,
}

impl Device {
    /// Build and open a TUN device.
    ///
    /// ```ignore
    /// let device = Device::build(|c| {
    ///     c.tun_name = "hole-tun".into();
    ///     c.mtu = 1400;
    ///     c.ipv4 = Some("10.255.0.1/24".parse().unwrap());
    ///     c.ipv6 = Some("fdf8:f6d5:536e::1/64".parse().unwrap());
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
        // The `tun` crate's `Configuration` holds a single address, so the v6
        // CIDR is assigned to the OS interface separately, below.

        let tun = tun::create_as_async(&tun_config).map_err(|e| DeviceError::TunOpen(std::io::Error::other(e)))?;

        let (interface_index, ipv6_assigned) = match config.ipv6 {
            // Read the index from the CREATED device, never from the requested
            // name: macOS can grant a different one.
            Some(cidr) => {
                let index = interface_index_from(tun.tun_index().map_err(|e| e.to_string()))?;
                let verdict = ipv6_addr::assign(index, cidr)?;
                if verdict == Assigned::Ipv6StackAbsent {
                    warn!(
                        interface_index = index,
                        verdict = ?verdict,
                        "TUN interface holds no IPv6 address; IPv6 flows cannot be sourced into the tunnel"
                    );
                }
                (Some(index), Some(verdict))
            }
            None => (None, None),
        };

        Ok(Self {
            tun,
            config,
            interface_index,
            ipv6_assigned,
        })
    }

    /// The OS interface index of the created device. `None` when no IPv6 CIDR
    /// was configured.
    pub fn interface_index(&self) -> Option<u32> {
        self.interface_index
    }

    /// What the OS interface ended up holding for the configured IPv6 CIDR.
    /// `None` when none was configured.
    ///
    /// Read this BEFORE handing the device to
    /// [`Engine::build`](crate::engine::Engine::build): that consumes the
    /// device through [`into_inner`](Self::into_inner), which returns only the
    /// `AsyncDevice` and the config.
    pub fn ipv6_assigned(&self) -> Option<Assigned> {
        self.ipv6_assigned
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

/// The device's interface index, or the reason there isn't one. `0` is a
/// reserved sentinel — real indices start at 1 — so it reads as a broken
/// device handle, never as a host without IPv6.
fn interface_index_from(raw: Result<i32, String>) -> Result<u32, DeviceError> {
    match raw {
        Ok(index) if index > 0 => Ok(index as u32),
        Ok(index) => Err(DeviceError::Ipv6Assign {
            index: 0,
            message: format!("the TUN reported interface index {index}; real indices start at 1"),
        }),
        Err(message) => Err(DeviceError::Ipv6Assign {
            index: 0,
            message: format!("the TUN's interface index is unavailable: {message}"),
        }),
    }
}
