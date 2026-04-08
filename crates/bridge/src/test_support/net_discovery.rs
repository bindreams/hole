//! Network interface discovery helpers for tests.
//!
//! TUN-mode tests cannot use loopback for the HTTP target because the kernel
//! short-circuits loopback traffic before consulting the routing table — it
//! never reaches the TUN interface. Tests instead bind the HTTP target to
//! the host's primary non-loopback IPv4 address, discovered here.

use std::net::{Ipv4Addr, SocketAddr};

/// Discover a routable primary IPv4 address.
///
/// Strategy:
///
/// 1. Prefer `default_net::get_default_interface()` (authoritative).
/// 2. Fallback: bind a UDP socket and `connect()` to a public sentinel
///    (`8.8.8.8:53`). UDP `connect` does no I/O — it just asks the kernel to
///    pick a source address for packets routed to the sentinel. Read that
///    source address with `local_addr()`.
///
/// Returns `Err` if both strategies produce a loopback / link-local /
/// unspecified address (which would defeat the TUN routing purpose).
pub(crate) fn detect_primary_ipv4() -> Result<Ipv4Addr, String> {
    if let Ok(iface) = default_net::get_default_interface() {
        if let Some(v4) = iface.ipv4.into_iter().next() {
            let ip = v4.addr;
            if !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() {
                return Ok(ip);
            }
        }
    }

    // UDP-connect fallback: ask the kernel to pick a source addr without
    // sending anything.
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.connect("8.8.8.8:53").map_err(|e| e.to_string())?;
    match sock.local_addr().map_err(|e| e.to_string())? {
        SocketAddr::V4(v4) => {
            let ip = *v4.ip();
            if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
                Err(format!("detected unusable primary IPv4: {ip}"))
            } else {
                Ok(ip)
            }
        }
        SocketAddr::V6(_) => Err("no IPv4 primary interface".to_string()),
    }
}
