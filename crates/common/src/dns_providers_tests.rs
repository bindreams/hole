use super::*;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[skuld::test]
fn cloudflare_primary() {
    assert_eq!(doh_url(ip("1.1.1.1")), "https://cloudflare-dns.com/dns-query");
}

#[skuld::test]
fn cloudflare_secondary() {
    assert_eq!(doh_url(ip("1.0.0.1")), "https://cloudflare-dns.com/dns-query");
}

#[skuld::test]
fn cloudflare_ipv6() {
    assert_eq!(
        doh_url(ip("2606:4700:4700::1111")),
        "https://cloudflare-dns.com/dns-query"
    );
}

#[skuld::test]
fn google() {
    assert_eq!(doh_url(ip("8.8.8.8")), "https://dns.google/dns-query");
}

#[skuld::test]
fn quad9() {
    assert_eq!(doh_url(ip("9.9.9.9")), "https://dns.quad9.net/dns-query");
}

#[skuld::test]
fn opendns() {
    assert_eq!(doh_url(ip("208.67.222.222")), "https://doh.opendns.com/dns-query");
}

#[skuld::test]
fn adguard() {
    assert_eq!(doh_url(ip("94.140.14.14")), "https://dns.adguard-dns.com/dns-query");
}

#[skuld::test]
fn unknown_ipv4_falls_back_to_ip_literal() {
    assert_eq!(doh_url(ip("203.0.113.42")), "https://203.0.113.42/dns-query");
}

#[skuld::test]
fn unknown_ipv6_brackets_the_literal() {
    assert_eq!(doh_url(ip("2001:db8::1")), "https://[2001:db8::1]/dns-query");
}

#[skuld::test]
fn all_table_doh_urls_are_https() {
    for (_, url) in TABLE {
        assert!(url.starts_with("https://"), "doh_url should be https: {url}");
    }
}

#[skuld::test]
fn all_table_keys_parse_as_ip() {
    for (addr, _) in TABLE {
        addr.parse::<IpAddr>().unwrap_or_else(|_| panic!("not an IP: {addr}"));
    }
}
