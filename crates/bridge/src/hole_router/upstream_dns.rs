//! Upstream DNS resolver for the bypass dispatch path.
//!
//! Resolves real domain names for bypass-path connections whose dst_ip
//! is a fake-DNS synthetic IP. Uses the host's real DNS servers,
//! discovered before TUN routes are installed.

use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::{Resolver, TokioResolver};
use std::net::{IpAddr, SocketAddr};

/// Discover the OS's configured DNS server IPs.
///
/// Called once at proxy start, before TUN routes are installed, so the
/// returned IPs are reachable via the real upstream interface.
pub fn discover_dns_servers() -> std::io::Result<Vec<IpAddr>> {
    let (config, _opts) = hickory_resolver::system_conf::read_system_conf()
        .map_err(|e| std::io::Error::other(format!("failed to read system DNS config: {e}")))?;
    let servers: Vec<IpAddr> = config.name_servers().iter().map(|ns| ns.socket_addr.ip()).collect();
    if servers.is_empty() {
        return Err(std::io::Error::other("no DNS servers found in system config"));
    }
    Ok(servers)
}

/// Async DNS resolver that uses the discovered upstream DNS servers.
pub struct UpstreamResolver {
    resolver: TokioResolver,
}

impl UpstreamResolver {
    /// Construct a resolver from the given DNS server IPs.
    ///
    /// Note: the resolver's transport sockets are NOT interface-bound
    /// (hickory-resolver doesn't expose socket customization). The DNS
    /// server IPs need host-route exceptions added alongside the SS
    /// server IP exception to prevent routing loops through the TUN.
    pub fn new(servers: &[IpAddr]) -> Self {
        let mut config = ResolverConfig::new();
        for &ip in servers {
            config.add_name_server(NameServerConfig::new(SocketAddr::new(ip, 53), Protocol::Udp));
        }
        let resolver = Resolver::builder_with_config(config, Default::default()).build();
        Self { resolver }
    }

    /// Resolve a domain name to IP addresses. Prefers IPv4.
    pub async fn resolve(&self, domain: &str) -> std::io::Result<Vec<IpAddr>> {
        let response = self
            .resolver
            .lookup_ip(domain)
            .await
            .map_err(|e| std::io::Error::other(format!("DNS resolution failed for {domain}: {e}")))?;
        let mut v4: Vec<IpAddr> = response.iter().filter(|ip| ip.is_ipv4()).collect();
        let v6: Vec<IpAddr> = response.iter().filter(|ip| ip.is_ipv6()).collect();
        v4.extend(v6);
        if v4.is_empty() {
            return Err(std::io::Error::other(format!("no addresses returned for {domain}")));
        }
        Ok(v4)
    }
}

#[cfg(test)]
#[path = "upstream_dns_tests.rs"]
mod upstream_dns_tests;
