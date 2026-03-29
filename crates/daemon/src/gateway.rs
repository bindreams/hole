// Default gateway detection — wraps the `default-net` crate.

use std::net::IpAddr;

/// Gateway detection result, bundling the gateway IP with the original interface name.
pub struct GatewayInfo {
    /// Default gateway IP address (typically IPv4 — `default-net` does not expose IPv6 gateways on Windows).
    pub gateway_ip: IpAddr,
    /// Platform-appropriate interface name for route commands.
    /// On Windows: friendly name (e.g., "Wi-Fi"). On macOS: BSD name (e.g., "en0").
    pub interface_name: String,
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

    Ok(GatewayInfo {
        gateway_ip,
        interface_name,
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

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod gateway_tests;
