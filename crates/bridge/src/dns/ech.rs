//! ECH-config DoH source for the plugin chain.
//!
//! ex-ray fetches the ECHConfigList itself, over a Go HTTP client that dials
//! whatever host the `ech-doh` URL names via `internet.DialSystem`. A hostname
//! URL would cost a plaintext system-DNS lookup — the channel the private DoH
//! bootstrap exists to avoid — so the URL is always IP-literal. It also names
//! the resolver that answered the bootstrap rather than the first configured
//! one, because ex-ray takes a single URL and does no failover.
//!
//! The bridge's own DoT/DoH transports are different: they dial the configured
//! IP and use the provider hostname only for SNI and the `Host:` header, which
//! leaks nothing to a system resolver.

use std::net::IpAddr;

use hole_common::config::DnsConfig;

/// Which resolver the ECH lookup is pinned to — and when none is, why.
///
/// An unpinned URL names an endpoint nothing has demonstrated this host can
/// reach. The reasons stay distinct because they are not equally benign:
/// `NoQueryNeeded` means nothing needed pinning, while `SecureBootstrapFailed`
/// means every configured resolver already failed for the proxy hostname.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSource {
    /// This resolver answered the DoH bootstrap.
    Answered(IpAddr),
    /// The proxy server entry was a literal IP, so no resolver was consulted.
    NoQueryNeeded,
    /// Every configured resolver failed and `allow_insecure_bootstrap` let the
    /// OS resolver resolve the server instead.
    SecureBootstrapFailed,
    /// A covered retry's cached resolver is no longer listed in `dns.servers`.
    ResolverDeselected,
}

/// DoH endpoint URL that pins the resolver by IP: `https://<ip>/dns-query`,
/// IPv6 bracketed per RFC 3986 §3.2.2. It names no host, so a client dials
/// `ip` directly and verifies the certificate against an IP SAN — it has
/// nothing to resolve and cannot fall back to the system resolver.
pub fn doh_url_for_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("https://{v4}/dns-query"),
        IpAddr::V6(v6) => format!("https://[{v6}]/dns-query"),
    }
}

/// The `ech-doh` Hole offers, and whether it names a resolver that ANSWERED.
/// Only a pinned URL displaces one the config already carries: unpinned, Hole's
/// URL is a guess, and on `SecureBootstrapFailed` it names a resolver that just
/// failed — while the config's own value may be the one that works.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchDoh {
    pub url: String,
    pub pinned: bool,
}

/// The `ech-doh=<url>` value: the pinned resolver, or a configured one when
/// there is no pin. `None` only when nothing is configured — omitting the key
/// makes ex-ray refuse to start under `ech=always`, so an unverified endpoint
/// still beats leaving it out.
///
/// Unpinned, the fallback prefers IPv4 — the same bias the bootstrap applies
/// when picking the server address. A positional `first()` would nail the URL to
/// one address family on a path where nothing demonstrated the host has it, and
/// ex-ray cannot fail over to the other.
pub fn ech_doh_url(dns: &DnsConfig, source: PinSource) -> Option<EchDoh> {
    let (resolver, pinned) = match source {
        PinSource::Answered(ip) => (Some(ip), true),
        _ => (
            dns.servers
                .iter()
                .find(|ip| ip.is_ipv4())
                .or_else(|| dns.servers.first())
                .copied(),
            false,
        ),
    };
    resolver.map(|ip| EchDoh {
        url: doh_url_for_ip(ip),
        pinned,
    })
}

/// Re-check a pin against the resolver set of the config now being started. A
/// covered retry reuses a cached pin without re-resolving, so a resolver the
/// user deselected in between would otherwise keep receiving the ECH lookup —
/// which carries the destination hostname.
pub fn revalidate(source: PinSource, servers: &[IpAddr]) -> PinSource {
    match source {
        PinSource::Answered(ip) if !servers.contains(&ip) => PinSource::ResolverDeselected,
        other => other,
    }
}

#[cfg(test)]
#[path = "ech_tests.rs"]
mod ech_tests;
