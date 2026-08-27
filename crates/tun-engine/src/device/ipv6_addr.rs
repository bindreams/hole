//! Assignment of the TUN device's IPv6 address to the OS interface.
//!
//! The `tun` crate's `Configuration` holds a single address, so the v4 CIDR
//! goes to it and the v6 CIDR comes here. Without this the `::/1` + `8000::/1`
//! split routes point at an interface the kernel cannot source a packet from,
//! and every IPv6 flow fails on a host that has no global IPv6 of its own.
//!
//! `assign` takes `(if_index, cidr)` on every platform — the Windows
//! implementation resolves the LUID itself — so [`Device::build`](super::Device::build)
//! needs no `#[cfg]` and no parameter goes unused under `-D warnings`.

use smoltcp::wire::Ipv6Cidr;

use crate::error::DeviceError;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// What the OS interface ended up holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assigned {
    /// The interface holds the address.
    Address,
    /// The interface has no IPv6 half, so it cannot hold an IPv6 address and
    /// the assignment is a no-op. Says nothing about whether the *host* can
    /// emit IPv6 — that is `GatewayInfo::ipv6_available`, an independent
    /// question about upstream reachability.
    Ipv6StackAbsent,
}

/// Assign `cidr` to the OS interface identified by `if_index`.
#[cfg(target_os = "windows")]
pub(crate) fn assign(if_index: u32, cidr: Ipv6Cidr) -> Result<Assigned, DeviceError> {
    windows::assign(if_index, cidr)
}

/// Assign `cidr` to the OS interface identified by `if_index`.
#[cfg(target_os = "macos")]
pub(crate) fn assign(if_index: u32, cidr: Ipv6Cidr) -> Result<Assigned, DeviceError> {
    macos::assign(if_index, cidr)
}

/// Assign `cidr` to the OS interface identified by `if_index`.
///
/// Windows and macOS are the platforms this crate opens a TUN on, and the only
/// two with an assignment path. Refusing beats reporting `Ipv6StackAbsent`,
/// which would claim something about the interface that was never asked.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub(crate) fn assign(if_index: u32, _cidr: Ipv6Cidr) -> Result<Assigned, DeviceError> {
    Err(DeviceError::Ipv6Assign {
        index: if_index,
        message: "this platform has no IPv6 address assignment path".into(),
    })
}
