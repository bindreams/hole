use std::net::IpAddr;

use super::*;

#[skuld::test]
fn cloudflare_by_ip_returns_cloudflare_dns_com() {
    let p = lookup("1.1.1.1".parse::<IpAddr>().unwrap()).expect("1.1.1.1 is known");
    assert_eq!(p.tls_dns_name, "cloudflare-dns.com");
    assert_eq!(p.doh_url, "https://cloudflare-dns.com/dns-query");
}

#[skuld::test]
fn cloudflare_secondary_matches() {
    let p = lookup("1.0.0.1".parse::<IpAddr>().unwrap()).expect("1.0.0.1 is known");
    assert_eq!(p.tls_dns_name, "cloudflare-dns.com");
}

#[skuld::test]
fn cloudflare_ipv6_matches() {
    let p = lookup("2606:4700:4700::1111".parse::<IpAddr>().unwrap()).expect("v6 is known");
    assert_eq!(p.tls_dns_name, "cloudflare-dns.com");
}

#[skuld::test]
fn google_matches() {
    let p = lookup("8.8.8.8".parse::<IpAddr>().unwrap()).expect("8.8.8.8 is known");
    assert_eq!(p.tls_dns_name, "dns.google");
    assert_eq!(p.doh_url, "https://dns.google/dns-query");
}

#[skuld::test]
fn quad9_matches() {
    let p = lookup("9.9.9.9".parse::<IpAddr>().unwrap()).expect("9.9.9.9 is known");
    assert_eq!(p.tls_dns_name, "dns.quad9.net");
}

#[skuld::test]
fn unknown_ip_returns_none() {
    assert!(lookup("203.0.113.42".parse::<IpAddr>().unwrap()).is_none());
}

#[skuld::test]
fn all_doh_urls_start_with_https() {
    for (_, p) in TABLE {
        assert!(
            p.doh_url.starts_with("https://"),
            "doh_url should be https: {}",
            p.doh_url
        );
    }
}

#[skuld::test]
fn all_keys_parse_as_ip() {
    for (addr, _) in TABLE {
        addr.parse::<IpAddr>().unwrap_or_else(|_| panic!("not an IP: {addr}"));
    }
}

// The table drives DoT SNI and the DoH `Host:`/certificate check
// (`tls_server_name_for` / `https_target_for`), so a mistyped or dropped IP
// silently downgrades a hostname-verified channel to IP-SAN verification. Pin
// the set explicitly — the same resolvers `ui/settings.ts` offers as presets.
#[skuld::test]
fn the_table_covers_exactly_the_shipped_resolver_ips() {
    use std::collections::BTreeSet;

    let expected: BTreeSet<IpAddr> = [
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        "9.9.9.9",
        "149.112.112.112",
        "2620:fe::fe",
        "2620:fe::9",
        "208.67.222.222",
        "208.67.220.220",
        "94.140.14.14",
        "94.140.15.15",
    ]
    .iter()
    .map(|a| a.parse().expect("expected IP literal"))
    .collect();
    let actual: BTreeSet<IpAddr> = TABLE
        .iter()
        .map(|(addr, _)| addr.parse().expect("table IP literal"))
        .collect();
    assert_eq!(actual, expected, "the provider IP set changed");
}
