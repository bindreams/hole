//! Default gateway detection — wraps the `default-net` crate.

use std::net::IpAddr;

use crate::net::bind_to_interface_v6;

/// Gateway detection result, bundling the gateway IP with the original
/// interface name.
pub struct GatewayInfo {
    /// Default gateway IP address (typically IPv4 — `default-net` does not
    /// expose IPv6 gateways on Windows).
    pub gateway_ip: IpAddr,
    /// Platform-appropriate interface name for route commands.
    /// On Windows: friendly name (e.g., "Wi-Fi"). On macOS: BSD name (e.g., "en0").
    pub interface_name: String,
    /// OS interface index (used by bypass socket helpers to bind to the
    /// upstream NIC).
    pub interface_index: u32,
    /// Whether the upstream interface can reach an IPv6 destination.
    pub ipv6_available: bool,
}

/// Detect the system's default gateway IP and original interface name.
pub fn get_default_gateway_info() -> std::io::Result<GatewayInfo> {
    let iface = default_net::get_default_interface().map_err(|e| std::io::Error::other(e.to_string()))?;

    let gateway_ip = iface
        .gateway
        .as_ref()
        .map(|gw| gw.ip_addr)
        .ok_or_else(|| std::io::Error::other("default interface has no gateway"))?;

    let interface_name = platform_interface_name(&iface)?;
    let interface_index = platform_interface_index(&iface)?;
    let ipv6_available = probe_ipv6(interface_index);

    Ok(GatewayInfo {
        gateway_ip,
        interface_name,
        interface_index,
        ipv6_available,
    })
}

#[cfg(target_os = "windows")]
fn platform_interface_name(iface: &default_net::Interface) -> std::io::Result<String> {
    iface
        .friendly_name
        .clone()
        .ok_or_else(|| std::io::Error::other("default interface has no friendly name"))
}

#[cfg(target_os = "macos")]
fn platform_interface_name(iface: &default_net::Interface) -> std::io::Result<String> {
    Ok(iface.name.clone())
}

// Interface index detection ===========================================================================================

#[cfg(target_os = "windows")]
fn platform_interface_index(iface: &default_net::Interface) -> std::io::Result<u32> {
    let friendly_name = iface
        .friendly_name
        .as_deref()
        .ok_or_else(|| std::io::Error::other("default interface has no friendly name"))?;
    interface_index_by_name(friendly_name)
}

/// Resolve an interface's OS index from its route-command name (Windows:
/// friendly name/alias, e.g. `hole-tun`; macOS: BSD name, e.g. `utun7`).
/// Shared by upstream-gateway lookup and [`tun_ipv6_available`], which needs
/// the TUN's own index rather than the upstream one.
#[cfg(target_os = "windows")]
pub(crate) fn interface_index_by_name(name: &str) -> std::io::Result<u32> {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex};
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let alias = HSTRING::from(name);
    let mut luid = NET_LUID_LH::default();
    let err = unsafe { ConvertInterfaceAliasToLuid(&alias, &mut luid) };
    if err != NO_ERROR {
        return Err(std::io::Error::other(format!(
            "ConvertInterfaceAliasToLuid: error {err:?}"
        )));
    }
    let mut index = 0u32;
    let err = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if err != NO_ERROR {
        return Err(std::io::Error::other(format!(
            "ConvertInterfaceLuidToIndex: error {err:?}"
        )));
    }
    Ok(index)
}

#[cfg(target_os = "macos")]
fn platform_interface_index(iface: &default_net::Interface) -> std::io::Result<u32> {
    interface_index_by_name(&iface.name)
}

/// Resolve an interface's OS index from its route-command name (Windows:
/// friendly name/alias; macOS: BSD name, e.g. `utun7`). Shared by
/// upstream-gateway lookup and [`tun_ipv6_available`], which needs the TUN's
/// own index rather than the upstream one.
#[cfg(target_os = "macos")]
pub(crate) fn interface_index_by_name(name: &str) -> std::io::Result<u32> {
    let c_name =
        std::ffi::CString::new(name).map_err(|e| std::io::Error::other(format!("invalid interface name: {e}")))?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        return Err(std::io::Error::other(format!("if_nametoindex failed for '{name}'")));
    }
    Ok(idx)
}

// IPv6 availability probes ============================================================================================

/// A fresh IPv6 UDP socket scoped to `interface_index`, or `None` if that
/// interface has no IPv6 binding at all (e.g. `DisabledComponents`, or an EDR
/// policy that unbinds IPv6 from the adapter) — the scoping call itself is
/// what fails there, before any network I/O.
fn bound_ipv6_socket(interface_index: u32) -> Option<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .ok()?;
    bind_to_interface_v6(&socket, interface_index).ok()?;
    Some(socket)
}

/// Whether `interface_index` has an IPv6 binding, with no attempt to reach
/// anywhere. Used where the question is "can a route command targeting this
/// specific interface succeed", not "can this interface reach the internet"
/// — see [`tun_ipv6_available`].
fn probe_ipv6_bound(interface_index: u32) -> bool {
    bound_ipv6_socket(interface_index).is_some()
}

/// Whether `interface_index` can reach a real IPv6 destination. Used for the
/// upstream gateway, where "bound but no route to the internet" is a
/// legitimate state — see [`GatewayInfo::ipv6_available`]'s doc.
fn probe_ipv6(interface_index: u32) -> bool {
    let Some(socket) = bound_ipv6_socket(interface_index) else {
        return false;
    };
    let target: std::net::SocketAddrV6 = "[2606:4700:4700::1111]:443".parse().unwrap();
    socket
        .connect(&socket2::SockAddr::from(std::net::SocketAddr::V6(target)))
        .is_ok()
}

/// Whether the TUN device named `tun_name` has an IPv6 binding. Meant to be
/// probed AFTER the OS creates the adapter, so it reflects the interface the
/// IPv6 split-route commands (`SetupCommand`) actually target — unlike
/// [`GatewayInfo::ipv6_available`], which measures the upstream interface the
/// commands do NOT name. `false` on any resolution failure (including the
/// adapter not existing yet): `SetupCommand::fatal` treats `false` as
/// "tolerate this command failing", never as "skip issuing it".
pub fn tun_ipv6_available(tun_name: &str) -> bool {
    match interface_index_by_name(tun_name) {
        Ok(index) => probe_ipv6_bound(index),
        Err(_) => false,
    }
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod gateway_tests;
