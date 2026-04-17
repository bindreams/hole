//! `DeviceConfig` — immutable configuration for a TUN device, constructed
//! via [`MutDeviceConfig`] inside [`Device::build`](super::Device::build).

use smoltcp::wire::{Ipv4Cidr, Ipv6Cidr};

use tun_engine_macros::freeze;

/// Configuration for a TUN device.
///
/// `tun_name` and `mtu` are required (empty / zero values cause
/// [`Device::build`](super::Device::build) to fail). At least one of
/// `ipv4`/`ipv6` must be set.
#[freeze]
pub struct DeviceConfig {
    /// The TUN interface name. On Windows, the wintun adapter friendly
    /// name. On macOS, the utun device name (e.g. `utun5`, or a custom
    /// name like `hole-tun`).
    pub tun_name: String,
    /// The TUN device MTU. Typical value: `1400`.
    pub mtu: u16,
    /// The IPv4 address + mask assigned to the TUN.
    pub ipv4: Option<Ipv4Cidr>,
    /// The IPv6 address + mask assigned to the TUN.
    pub ipv6: Option<Ipv6Cidr>,
}

#[allow(clippy::derivable_impls)]
impl Default for MutDeviceConfig {
    fn default() -> Self {
        Self {
            tun_name: String::new(),
            mtu: 0,
            ipv4: None,
            ipv6: None,
        }
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
