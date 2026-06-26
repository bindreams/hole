//! IP → DoH-URL mapping shared across config / GUI / bridge.
//!
//! [`doh_url`] resolves any resolver IP to a DoH endpoint: a known provider's
//! URL, or the literal-IP `https://<ip>/dns-query` fallback (IPv6 bracketed).
//! Used by the bridge's bootstrap resolver, the in-TUN forwarder's DoH
//! transport, and the `ech-doh=<url>` opt the bridge injects into the plugin
//! chain. The bridge keeps a separate `KnownProvider`/`tls_dns_name` table for
//! DoT SNI; only the URL mapping is centralized here.

use std::net::IpAddr;

/// DoH endpoint URL for `ip`: the known provider's URL, or the literal-IP
/// `https://<ip>/dns-query` fallback (IPv6 bracketed).
pub fn doh_url(ip: IpAddr) -> String {
    for (addr, url) in TABLE {
        if addr.parse::<IpAddr>().ok() == Some(ip) {
            return (*url).to_string();
        }
    }
    match ip {
        IpAddr::V4(v4) => format!("https://{v4}/dns-query"),
        IpAddr::V6(v6) => format!("https://[{v6}]/dns-query"),
    }
}

/// The resolver IPs [`doh_url`] maps to a known provider (i.e. not the
/// literal-IP fallback). The bridge's `KnownProvider` table must cover the same
/// set; a bridge-side test asserts the two agree.
pub fn provider_ips() -> impl Iterator<Item = IpAddr> {
    TABLE
        .iter()
        .map(|(addr, _)| addr.parse::<IpAddr>().expect("provider table IP literal parses"))
}

// Mirrors the provider IP set the bridge's `crates/bridge/src/dns/providers.rs` SNI table covers (a bridge-side test enforces the two agree).
const TABLE: &[(&str, &str)] = &[
    ("1.1.1.1", "https://cloudflare-dns.com/dns-query"),
    ("1.0.0.1", "https://cloudflare-dns.com/dns-query"),
    ("2606:4700:4700::1111", "https://cloudflare-dns.com/dns-query"),
    ("2606:4700:4700::1001", "https://cloudflare-dns.com/dns-query"),
    ("8.8.8.8", "https://dns.google/dns-query"),
    ("8.8.4.4", "https://dns.google/dns-query"),
    ("2001:4860:4860::8888", "https://dns.google/dns-query"),
    ("2001:4860:4860::8844", "https://dns.google/dns-query"),
    ("9.9.9.9", "https://dns.quad9.net/dns-query"),
    ("149.112.112.112", "https://dns.quad9.net/dns-query"),
    ("2620:fe::fe", "https://dns.quad9.net/dns-query"),
    ("2620:fe::9", "https://dns.quad9.net/dns-query"),
    ("208.67.222.222", "https://doh.opendns.com/dns-query"),
    ("208.67.220.220", "https://doh.opendns.com/dns-query"),
    ("94.140.14.14", "https://dns.adguard-dns.com/dns-query"),
    ("94.140.15.15", "https://dns.adguard-dns.com/dns-query"),
];

#[cfg(test)]
#[path = "dns_providers_tests.rs"]
mod dns_providers_tests;
