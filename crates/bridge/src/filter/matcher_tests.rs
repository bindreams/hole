use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hole_common::config::MatchType;

use super::*;
use crate::filter::engine::{ConnInfo, L4Proto};

// Helpers =============================================================================================================

fn ip_conn(dst: &str) -> ConnInfo {
    ConnInfo {
        dst_ip: dst.parse().unwrap(),
        dst_port: 443,
        domain: None,
        proto: L4Proto::Tcp,
    }
}

fn dom_conn(dst: &str, domain: &str) -> ConnInfo {
    ConnInfo {
        dst_ip: dst.parse().unwrap(),
        dst_port: 443,
        domain: Some(domain.to_string()),
        proto: L4Proto::Tcp,
    }
}

fn compile(addr: &str, kind: MatchType) -> Matcher {
    Matcher::compile(addr, kind).expect("compile should succeed")
}

// Compile errors ======================================================================================================

#[skuld::test]
fn subnet_with_non_cidr_address_fails() {
    let err = Matcher::compile("example.com", MatchType::Subnet).unwrap_err();
    assert!(err.0.contains("not a valid CIDR"), "got: {err}");
}

#[skuld::test]
fn subnet_with_garbage_fails() {
    let err = Matcher::compile("not-a-cidr/24", MatchType::Subnet).unwrap_err();
    assert!(err.0.contains("not a valid CIDR"), "got: {err}");
}

#[skuld::test]
fn subnet_canonicalizes_host_bits() {
    // 192.168.1.1/24 has host bits set; trunc to 192.168.1.0/24.
    let m = compile("192.168.1.1/24", MatchType::Subnet);
    assert!(m.matches(&ip_conn("192.168.1.42")));
    assert!(!m.matches(&ip_conn("192.168.2.42")));
}

#[skuld::test]
fn exact_with_empty_address_fails() {
    let err = Matcher::compile("", MatchType::Exactly).unwrap_err();
    assert!(err.0.contains("empty"), "got: {err}");
}

#[skuld::test]
fn with_subdomains_with_empty_address_fails() {
    let err = Matcher::compile("", MatchType::WithSubdomains).unwrap_err();
    assert!(err.0.contains("empty"), "got: {err}");
}

#[skuld::test]
fn with_subdomains_with_ip_literal_fails() {
    let err = Matcher::compile("1.2.3.4", MatchType::WithSubdomains).unwrap_err();
    assert!(err.0.contains("not valid"), "got: {err}");
}

#[skuld::test]
fn wildcard_with_empty_address_fails() {
    let err = Matcher::compile("", MatchType::Wildcard).unwrap_err();
    assert!(err.0.contains("empty"), "got: {err}");
}

#[skuld::test]
fn exact_with_invalid_domain_fails() {
    // Whitespace inside the host label is not a valid IDNA name.
    let err = Matcher::compile("exa mple.com", MatchType::Exactly).unwrap_err();
    assert!(err.0.contains("valid domain"), "got: {err}");
}

// ExactDomain matching ================================================================================================

#[skuld::test]
fn exact_domain_matches_literal() {
    let m = compile("example.com", MatchType::Exactly);
    assert!(m.matches(&dom_conn("1.2.3.4", "example.com")));
}

#[skuld::test]
fn exact_domain_does_not_match_subdomain() {
    let m = compile("example.com", MatchType::Exactly);
    assert!(!m.matches(&dom_conn("1.2.3.4", "a.example.com")));
}

#[skuld::test]
fn exact_domain_case_insensitive() {
    let m = compile("Example.COM", MatchType::Exactly);
    assert!(m.matches(&dom_conn("1.2.3.4", "example.com")));
    assert!(m.matches(&dom_conn("1.2.3.4", "EXAMPLE.com")));
}

#[skuld::test]
fn exact_domain_skips_when_no_domain() {
    let m = compile("example.com", MatchType::Exactly);
    assert!(!m.matches(&ip_conn("1.2.3.4")));
}

#[skuld::test]
fn exact_domain_strips_trailing_dot() {
    let m = compile("example.com.", MatchType::Exactly);
    assert!(m.matches(&dom_conn("1.2.3.4", "example.com")));
}

#[skuld::test]
fn exact_domain_idna_normalizes() {
    // 例え.com (Japanese) → xn--r8jz45g.com
    let m = compile("例え.com", MatchType::Exactly);
    assert!(m.matches(&dom_conn("1.2.3.4", "xn--r8jz45g.com")));
}

// SubdomainDomain matching ============================================================================================

#[skuld::test]
fn with_subdomains_matches_self() {
    let m = compile("example.com", MatchType::WithSubdomains);
    assert!(m.matches(&dom_conn("1.2.3.4", "example.com")));
}

#[skuld::test]
fn with_subdomains_matches_subdomain() {
    let m = compile("example.com", MatchType::WithSubdomains);
    assert!(m.matches(&dom_conn("1.2.3.4", "a.example.com")));
    assert!(m.matches(&dom_conn("1.2.3.4", "b.a.example.com")));
}

#[skuld::test]
fn with_subdomains_does_not_match_sibling() {
    let m = compile("example.com", MatchType::WithSubdomains);
    assert!(!m.matches(&dom_conn("1.2.3.4", "notexample.com")));
    assert!(!m.matches(&dom_conn("1.2.3.4", "example.org")));
}

#[skuld::test]
fn with_subdomains_skips_when_no_domain() {
    let m = compile("example.com", MatchType::WithSubdomains);
    assert!(!m.matches(&ip_conn("1.2.3.4")));
}

#[skuld::test]
fn with_subdomains_case_insensitive() {
    let m = compile("Example.COM", MatchType::WithSubdomains);
    assert!(m.matches(&dom_conn("1.2.3.4", "A.EXAMPLE.com")));
}

// WildcardDomain matching =============================================================================================

#[skuld::test]
fn wildcard_star_matches_anything() {
    let m = compile("*", MatchType::Wildcard);
    assert!(m.matches(&dom_conn("1.2.3.4", "example.com")));
    assert!(m.matches(&dom_conn("1.2.3.4", "anything.tld")));
}

#[skuld::test]
fn wildcard_prefix_glob() {
    let m = compile("*.example.com", MatchType::Wildcard);
    assert!(m.matches(&dom_conn("1.2.3.4", "a.example.com")));
    assert!(m.matches(&dom_conn("1.2.3.4", "b.a.example.com")));
    assert!(!m.matches(&dom_conn("1.2.3.4", "example.com")));
}

#[skuld::test]
fn wildcard_question_mark() {
    let m = compile("a?.example.com", MatchType::Wildcard);
    assert!(m.matches(&dom_conn("1.2.3.4", "ab.example.com")));
    assert!(m.matches(&dom_conn("1.2.3.4", "az.example.com")));
    assert!(!m.matches(&dom_conn("1.2.3.4", "abc.example.com")));
}

#[skuld::test]
fn wildcard_escapes_regex_metacharacters() {
    // The literal `.` in `example.com` must not match arbitrary chars.
    let m = compile("example.com", MatchType::Wildcard);
    assert!(m.matches(&dom_conn("1.2.3.4", "example.com")));
    assert!(!m.matches(&dom_conn("1.2.3.4", "exampleXcom")));
}

#[skuld::test]
fn wildcard_skips_when_no_domain() {
    let m = compile("*.example.com", MatchType::Wildcard);
    assert!(!m.matches(&ip_conn("1.2.3.4")));
}

// ExactIp matching ====================================================================================================

#[skuld::test]
fn exact_ipv4_matches() {
    let m = compile("1.2.3.4", MatchType::Exactly);
    assert!(matches!(m, Matcher::ExactIp(_)));
    assert!(m.matches(&ip_conn("1.2.3.4")));
    assert!(!m.matches(&ip_conn("1.2.3.5")));
}

#[skuld::test]
fn exact_ipv6_matches() {
    let m = compile("2001:db8::1", MatchType::Exactly);
    assert!(matches!(m, Matcher::ExactIp(_)));
    assert!(m.matches(&ip_conn("2001:db8::1")));
    assert!(!m.matches(&ip_conn("2001:db8::2")));
}

#[skuld::test]
fn exact_ip_matches_regardless_of_domain_presence() {
    let m = compile("1.2.3.4", MatchType::Exactly);
    assert!(m.matches(&dom_conn("1.2.3.4", "anything.com")));
}

#[skuld::test]
fn exact_ipv4_canonicalizes_v4_mapped_v6() {
    let m = compile("1.2.3.4", MatchType::Exactly);
    let conn = ConnInfo {
        dst_ip: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304)),
        dst_port: 443,
        domain: None,
        proto: L4Proto::Tcp,
    };
    assert!(m.matches(&conn));
}

// Subnet matching =====================================================================================================

#[skuld::test]
fn subnet_ipv4_cidr_matches() {
    let m = compile("10.0.0.0/8", MatchType::Subnet);
    assert!(m.matches(&ip_conn("10.0.0.1")));
    assert!(m.matches(&ip_conn("10.255.255.255")));
    assert!(!m.matches(&ip_conn("11.0.0.1")));
}

#[skuld::test]
fn subnet_ipv6_cidr_matches() {
    let m = compile("2001:db8::/32", MatchType::Subnet);
    assert!(m.matches(&ip_conn("2001:db8::1")));
    assert!(m.matches(&ip_conn("2001:db8:ffff::1")));
    assert!(!m.matches(&ip_conn("2001:db9::1")));
}

#[skuld::test]
fn subnet_zero_prefix_matches_everything_in_family() {
    let m4 = compile("0.0.0.0/0", MatchType::Subnet);
    assert!(m4.matches(&ip_conn("1.2.3.4")));
    assert!(m4.matches(&ip_conn("255.255.255.255")));
    assert!(!m4.matches(&ip_conn("::1")));

    let m6 = compile("::/0", MatchType::Subnet);
    assert!(m6.matches(&ip_conn("::1")));
    assert!(m6.matches(&ip_conn("2001:db8::1")));
    assert!(!m6.matches(&ip_conn("1.2.3.4")));
}

#[skuld::test]
fn subnet_max_prefix_is_single_host() {
    let m = compile("192.168.1.42/32", MatchType::Subnet);
    assert!(m.matches(&ip_conn("192.168.1.42")));
    assert!(!m.matches(&ip_conn("192.168.1.41")));
    assert!(!m.matches(&ip_conn("192.168.1.43")));
}

#[skuld::test]
fn subnet_canonicalizes_v4_mapped_v6() {
    let m = compile("10.0.0.0/8", MatchType::Subnet);
    let conn = ConnInfo {
        dst_ip: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001)),
        dst_port: 443,
        domain: None,
        proto: L4Proto::Tcp,
    };
    assert!(m.matches(&conn));
}

#[skuld::test]
fn subnet_skips_when_family_mismatched() {
    let m = compile("10.0.0.0/8", MatchType::Subnet);
    assert!(!m.matches(&ip_conn("::1")));
}

// Edge cases ==========================================================================================================

#[skuld::test]
fn loopback_ip_in_zero_subnet() {
    let m = compile("127.0.0.1", MatchType::Exactly);
    assert!(m.matches(&ConnInfo {
        dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        dst_port: 80,
        domain: None,
        proto: L4Proto::Tcp,
    }));
}

#[skuld::test]
fn ipv6_unspecified_match() {
    let m = compile("::", MatchType::Exactly);
    assert!(m.matches(&ConnInfo {
        dst_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        dst_port: 80,
        domain: None,
        proto: L4Proto::Tcp,
    }));
}
