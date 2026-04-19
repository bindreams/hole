//! Known-provider table: maps a resolver IP to hostname-form metadata
//! for DoT (SNI / cert verification) and DoH (full URL).
//!
//! IPs not in the table fall back to IP-SAN cert verification for TLS and
//! URL shape `https://<ip>/dns-query` for DoH — which works for Cloudflare
//! / Google / Quad9 today but requires the provider to continue shipping
//! IP-SAN-bearing certs.

use std::net::IpAddr;

/// Hostname-form metadata for a known DNS provider IP.
#[derive(Debug, Clone, Copy)]
pub struct KnownProvider {
    pub tls_dns_name: &'static str,
    pub doh_url: &'static str,
}

/// Lookup metadata by IP. Returns `None` for free-form addresses.
pub fn lookup(ip: IpAddr) -> Option<KnownProvider> {
    for (addr, provider) in TABLE {
        if addr.parse::<IpAddr>().ok() == Some(ip) {
            return Some(**provider);
        }
    }
    None
}

const CLOUDFLARE: KnownProvider = KnownProvider {
    tls_dns_name: "cloudflare-dns.com",
    doh_url: "https://cloudflare-dns.com/dns-query",
};

const GOOGLE: KnownProvider = KnownProvider {
    tls_dns_name: "dns.google",
    doh_url: "https://dns.google/dns-query",
};

const QUAD9: KnownProvider = KnownProvider {
    tls_dns_name: "dns.quad9.net",
    doh_url: "https://dns.quad9.net/dns-query",
};

const OPENDNS: KnownProvider = KnownProvider {
    tls_dns_name: "dns.opendns.com",
    doh_url: "https://doh.opendns.com/dns-query",
};

const ADGUARD: KnownProvider = KnownProvider {
    tls_dns_name: "dns.adguard-dns.com",
    doh_url: "https://dns.adguard-dns.com/dns-query",
};

// Stable order — tests match on this to catch accidental reshuffling.
const TABLE: &[(&str, &KnownProvider)] = &[
    ("1.1.1.1", &CLOUDFLARE),
    ("1.0.0.1", &CLOUDFLARE),
    ("2606:4700:4700::1111", &CLOUDFLARE),
    ("2606:4700:4700::1001", &CLOUDFLARE),
    ("8.8.8.8", &GOOGLE),
    ("8.8.4.4", &GOOGLE),
    ("2001:4860:4860::8888", &GOOGLE),
    ("2001:4860:4860::8844", &GOOGLE),
    ("9.9.9.9", &QUAD9),
    ("149.112.112.112", &QUAD9),
    ("2620:fe::fe", &QUAD9),
    ("2620:fe::9", &QUAD9),
    ("208.67.222.222", &OPENDNS),
    ("208.67.220.220", &OPENDNS),
    ("94.140.14.14", &ADGUARD),
    ("94.140.15.15", &ADGUARD),
];

#[cfg(test)]
#[path = "providers_tests.rs"]
mod providers_tests;
