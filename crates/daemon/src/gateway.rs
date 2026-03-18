// Default gateway detection — wraps the `default-net` crate.

use std::net::IpAddr;

/// Detect the system's default gateway IP address.
pub fn get_default_gateway() -> std::io::Result<IpAddr> {
    let gw = default_net::get_default_gateway().map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(gw.ip_addr)
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod gateway_tests;
