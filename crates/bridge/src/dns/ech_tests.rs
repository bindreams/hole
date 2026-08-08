use std::net::IpAddr;

use hole_common::config::DnsConfig;

use super::*;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("test IP literal")
}

/// The URL of a derived `EchDoh`, dropping the reason.
fn url_of(e: Option<EchDoh>) -> Option<String> {
    e.map(|e| e.url)
}

fn dns(servers: &[&str]) -> DnsConfig {
    DnsConfig {
        servers: servers.iter().map(|s| ip(s)).collect(),
        ..Default::default()
    }
}

/// The host portion of `url`, with any IPv6 brackets removed.
fn authority_of(url: &str) -> &str {
    let rest = url.strip_prefix("https://").expect("https URL");
    let authority = rest.split('/').next().expect("split yields at least one part");
    authority
        .strip_prefix('[')
        .and_then(|a| a.strip_suffix(']'))
        .unwrap_or(authority)
}

#[skuld::test]
fn authority_of_strips_scheme_path_and_brackets() {
    assert_eq!(authority_of("https://1.1.1.1/dns-query"), "1.1.1.1");
    assert_eq!(authority_of("https://[2620:fe::fe]/dns-query"), "2620:fe::fe");
}

// The test that decides whether replacing a config's `ech-doh` removes a leak.
#[skuld::test]
fn a_hostname_authority_is_a_name_and_an_ip_literal_is_not() {
    for url in [
        "https://cloudflare-dns.com/dns-query",
        "https://doh.opendns.com:443/dns-query",
        "https://user@dns.google/dns-query",
        "https://1.1.1.1.nip.io/dns-query",
        "not a url at all",
        "",
    ] {
        assert!(authority_is_a_name(url), "{url} must count as a name");
    }
    for url in [
        "https://1.1.1.1/dns-query",
        "https://9.9.9.9:443/dns-query",
        "https://[2620:fe::fe]/dns-query",
        "https://[2620:fe::fe]:443/dns-query",
        "https://user@8.8.8.8/dns-query",
        "https://1.0.0.1",
    ] {
        assert!(!authority_is_a_name(url), "{url} names an IP literal");
    }
}

// Every URL this module emits must pass its own name-free test.
#[skuld::test]
fn a_derived_url_is_never_a_name() {
    for addr in ["1.1.1.1", "2620:fe::fe"] {
        assert!(!authority_is_a_name(&doh_url_for_ip(ip(addr))));
    }
}

#[skuld::test]
fn ipv4_authority_is_the_bare_address() {
    assert_eq!(doh_url_for_ip(ip("1.1.1.1")), "https://1.1.1.1/dns-query");
}

// RFC 3986 §3.2.2: an IPv6 literal in a URI authority is bracketed.
#[skuld::test]
fn ipv6_authority_is_bracketed() {
    assert_eq!(
        doh_url_for_ip(ip("2606:4700:4700::1111")),
        "https://[2606:4700:4700::1111]/dns-query"
    );
}

// An executable pin, not just prose: the URL never carries an explicit port
// (see `DOH_PORT`'s doc), so this asserts against the `url` crate's own
// scheme-default table instead of restating the assumption.
#[skuld::test]
fn doh_url_for_ip_ports_to_the_https_default() {
    for addr in ["1.1.1.1", "2606:4700:4700::1111"] {
        let url = doh_url_for_ip(ip(addr));
        let parsed = url::Url::parse(&url).expect("doh_url_for_ip must produce a parseable URL");
        assert_eq!(parsed.port_or_known_default(), Some(DOH_PORT));
    }
}

// `tun-engine` sits BELOW `hole-bridge` in the crate dependency graph, so its
// `RESOLVER_PERMIT_PORT` can't import THIS crate's `DOH_PORT` — but this
// crate CAN import tun-engine's, so this is the one enforced link: if either
// constant is ever edited alone, this fails instead of the two silently
// drifting (the fail-closed cover would then permit a port ex-ray never
// dials while blocking the one it does).
#[skuld::test]
fn resolver_permit_port_matches_doh_port() {
    assert_eq!(tun_engine::routing::failclosed::RESOLVER_PERMIT_PORT, DOH_PORT);
}

// The shipped default is Cloudflare: the ECH lookup must not be handed
// `cloudflare-dns.com`, whose resolution would go over plaintext system DNS.
#[skuld::test]
fn the_shipped_default_resolver_yields_an_ip_literal_url() {
    assert_eq!(
        url_of(ech_doh_url(&DnsConfig::default(), PinSource::NoQueryNeeded)).as_deref(),
        Some("https://1.1.1.1/dns-query")
    );
}

// ex-ray gets one URL and does no failover, so the URL must name the resolver
// that answered — not whichever entry happens to be first.
#[skuld::test]
fn the_answering_resolver_wins_over_the_first_entry() {
    // Both IPv4, so the fallback's family preference cannot produce this answer:
    // only reading the pin does.
    let cfg = dns(&["1.1.1.1", "9.9.9.9"]);
    assert_eq!(
        url_of(ech_doh_url(&cfg, PinSource::Answered(ip("9.9.9.9")))).as_deref(),
        Some("https://9.9.9.9/dns-query")
    );
}

#[skuld::test]
fn an_answering_ipv6_resolver_is_bracketed() {
    let cfg = dns(&["2620:fe::fe"]);
    assert_eq!(
        url_of(ech_doh_url(&cfg, PinSource::Answered(ip("2620:fe::fe")))).as_deref(),
        Some("https://[2620:fe::fe]/dns-query")
    );
}

// The reason travels with the URL: a caller decides displacement from
// `is_pinned`, and reports the unpinned cases in their own words.
#[skuld::test]
fn the_derived_url_carries_the_reason_it_was_chosen() {
    let cfg = dns(&["9.9.9.9"]);
    let answered = PinSource::Answered(ip("9.9.9.9"));
    let derived = ech_doh_url(&cfg, answered).expect("a resolver is configured");
    assert_eq!(derived.source, answered);
    assert!(derived.is_pinned());
    for source in [
        PinSource::NoQueryNeeded,
        PinSource::SecureBootstrapFailed,
        PinSource::ResolverDeselected,
    ] {
        let derived = ech_doh_url(&cfg, source).expect("a resolver is configured");
        assert_eq!(derived.source, source);
        assert!(!derived.is_pinned(), "{source:?} is not a resolver that answered");
    }
}

// No resolver was pinned, whatever the reason: still yield a URL. Omitting the
// directive instead would refuse to start under ech=always.
#[skuld::test]
fn every_unpinned_reason_still_yields_a_url() {
    let cfg = dns(&["9.9.9.9", "149.112.112.112"]);
    for source in [
        PinSource::NoQueryNeeded,
        PinSource::SecureBootstrapFailed,
        PinSource::ResolverDeselected,
    ] {
        assert_eq!(
            url_of(ech_doh_url(&cfg, source)).as_deref(),
            Some("https://9.9.9.9/dns-query"),
            "unpinned source {source:?} must still yield a URL"
        );
    }
}

// ex-ray does no failover, so an unpinned URL nailed to IPv6 is unreachable on an
// IPv4-only host — where the hostname form it replaces would have resolved to an
// A record. Unpinned, prefer IPv4 rather than whichever entry is first.
#[skuld::test]
fn an_unpinned_fallback_prefers_ipv4_over_a_leading_ipv6_entry() {
    let cfg = dns(&["2606:4700:4700::1111", "1.0.0.1"]);
    assert_eq!(
        url_of(ech_doh_url(&cfg, PinSource::NoQueryNeeded)).as_deref(),
        Some("https://1.0.0.1/dns-query")
    );
}

// An all-IPv6 config has no IPv4 to prefer; the first entry stands.
#[skuld::test]
fn an_all_ipv6_config_falls_back_to_its_first_entry() {
    let cfg = dns(&["2620:fe::fe", "2620:fe::9"]);
    assert_eq!(
        url_of(ech_doh_url(&cfg, PinSource::NoQueryNeeded)).as_deref(),
        Some("https://[2620:fe::fe]/dns-query")
    );
}

// A PINNED resolver is used as-is, IPv6 or not: the bootstrap just reached it.
#[skuld::test]
fn a_pinned_ipv6_resolver_is_not_second_guessed() {
    let cfg = dns(&["2620:fe::fe", "1.0.0.1"]);
    assert_eq!(
        url_of(ech_doh_url(&cfg, PinSource::Answered(ip("2620:fe::fe")))).as_deref(),
        Some("https://[2620:fe::fe]/dns-query")
    );
}

// Nothing configured: no `ech-doh`, so ex-ray's default `auto` mode leaves ECH
// off rather than being pointed at some other source.
#[skuld::test]
fn nothing_configured_means_no_ech_doh() {
    assert_eq!(ech_doh_url(&dns(&[]), PinSource::NoQueryNeeded), None);
}

#[skuld::test]
fn revalidate_drops_a_resolver_the_config_no_longer_lists() {
    let servers = [ip("8.8.8.8"), ip("8.8.4.4")];
    assert_eq!(
        revalidate(PinSource::Answered(ip("1.1.1.1")), &servers),
        PinSource::ResolverDeselected
    );
}

#[skuld::test]
fn revalidate_keeps_a_resolver_the_config_still_lists() {
    let servers = [ip("8.8.8.8"), ip("8.8.4.4")];
    assert_eq!(
        revalidate(PinSource::Answered(ip("8.8.4.4")), &servers),
        PinSource::Answered(ip("8.8.4.4"))
    );
}

// Only a pin can go stale; the unpinned reasons name why no resolver was chosen
// and are not claims about the current config.
#[skuld::test]
fn revalidate_leaves_the_unpinned_reasons_alone() {
    for source in [
        PinSource::NoQueryNeeded,
        PinSource::SecureBootstrapFailed,
        PinSource::ResolverDeselected,
    ] {
        assert_eq!(revalidate(source, &[]), source);
    }
}

// Every shipped provider IP must produce a name-free authority. Driven by the
// real table, so a provider added there — or a derivation that started
// consulting it for a hostname URL again — is caught here.
#[skuld::test]
fn every_provider_ip_yields_a_name_free_authority() {
    for (addr, _) in crate::dns::providers::TABLE {
        let resolver = ip(addr);
        let url = url_of(ech_doh_url(&dns(&[addr]), PinSource::Answered(resolver))).expect("a resolver is configured");
        assert_eq!(
            authority_of(&url).parse::<IpAddr>().ok(),
            Some(resolver),
            "ech-doh authority for {resolver} must be the IP literal, got {url}"
        );
    }
}

#[skuld::test]
fn verified_ip_is_some_only_for_answered() {
    let addr = ip("1.1.1.1");
    assert_eq!(PinSource::Answered(addr).verified_ip(), Some(addr));
    assert_eq!(PinSource::NoQueryNeeded.verified_ip(), None);
    assert_eq!(PinSource::SecureBootstrapFailed.verified_ip(), None);
    assert_eq!(PinSource::ResolverDeselected.verified_ip(), None);
}
