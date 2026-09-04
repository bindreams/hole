//! `DeviceConfig` — immutable configuration for a TUN device, constructed
//! via [`MutDeviceConfig`] inside [`Device::build`](super::Device::build).

use smoltcp::wire::{Ipv4Cidr, Ipv6Cidr};

use tun_engine_macros::freeze;

/// Where the TUN device's OS-visible name comes from.
///
/// The read-back is keyed on the variant, not on the platform:
///
/// - `Requested(name)` — the caller names the device and the OS is trusted
///   to honour it exactly, as it does on Windows (`wintun` always assigns
///   the requested friendly name). [`super::Device::identity`] carries
///   `name` straight through; the OS is never asked to confirm it. See
///   `crate::device::identity`'s module doc for why a read-back here would
///   be actively harmful: Windows' own interface-name table can transiently
///   answer "not found" on a live machine, and the no-time-sync rule bars a
///   retry loop working around it.
/// - `KernelAssigned` — there is no requested name; only macOS's `utun`
///   driver supports this (an unset `sc_unit` asks the kernel for the next
///   free `utunN`). The device's real name is read back from the just-opened
///   handle, and that read failing is fatal — there is nothing to fall back
///   to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunName {
    Requested(String),
    #[cfg(target_os = "macos")]
    KernelAssigned,
}

impl From<&str> for TunName {
    fn from(name: &str) -> Self {
        TunName::Requested(name.to_string())
    }
}

impl From<String> for TunName {
    fn from(name: String) -> Self {
        TunName::Requested(name)
    }
}

/// Configuration for a TUN device.
///
/// `tun_name` and `mtu` are required (an empty [`TunName::Requested`] name,
/// or a zero MTU, cause [`Device::build`](super::Device::build) to fail). At
/// least one of `ipv4`/`ipv6` must be set.
#[freeze]
pub struct DeviceConfig {
    /// The name requested for the TUN interface — NOT necessarily the name
    /// the OS ended up using: see [`TunName`]'s doc. The only correct
    /// post-open source of the device's real name is
    /// [`super::Device::identity`]`().alias()`.
    pub tun_name: TunName,
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
            tun_name: TunName::Requested(String::new()),
            mtu: 0,
            ipv4: None,
            ipv6: None,
        }
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
