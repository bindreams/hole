//! Addresses are from the documentation ranges (RFC 5737 `203.0.113.0/24`,
//! RFC 3849 `2001:db8::/32`) and the `.invalid` TLD so they appear in no
//! other fixture. The registry is process-global and grow-only; these run
//! under `cargo nextest`, one process per test.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use util::redact::redact_str;

use super::{arm_resolved_ip, arm_server, ip_family, ip_scope, server_kind, token_for};
use crate::config::ServerEntry;

fn entry(id: &str, server: &str) -> ServerEntry {
    ServerEntry {
        id: id.to_string(),
        server: server.to_string(),
        ..ServerEntry::default_placeholder()
    }
}

/// Redaction is what the registry does; asserting through it is asserting on
/// exactly the bytes a log sink would rewrite.
fn is_redacted(text: &str) -> bool {
    redact_str(text) != text
}

// arm_server ==========================================================================================================

#[skuld::test]
fn arm_server_matches_a_differently_cased_hostname() {
    arm_server(&entry("11111111-0000-0000-0000-000000000000", "VPN.Example.Invalid"));
    let token = token_for("11111111-0000-0000-0000-000000000000");
    assert_eq!(
        redact_str("dialing vpn.example.invalid:8388"),
        format!("dialing {token}:8388")
    );
}

#[skuld::test]
fn arm_server_covers_the_idn_a_label() {
    arm_server(&entry("22222222-0000-0000-0000-000000000000", "bücher.example.invalid"));
    let token = token_for("22222222-0000-0000-0000-000000000000");
    // A third-party dialer logs the A-label, not what the user typed.
    assert_eq!(
        redact_str("dialing xn--bcher-kva.example.invalid:443"),
        format!("dialing {token}:443")
    );
    assert!(is_redacted("dialing bücher.example.invalid:443"));
}

#[skuld::test]
fn arm_server_covers_the_trailing_dot_fqdn() {
    arm_server(&entry("33333333-0000-0000-0000-000000000000", "vpn.example.invalid."));
    let token = token_for("33333333-0000-0000-0000-000000000000");
    assert_eq!(
        redact_str("dialing vpn.example.invalid:8388"),
        format!("dialing {token}:8388")
    );
}

#[skuld::test]
fn arm_server_survives_a_malformed_idn_hostname() {
    // U+FFFF is a noncharacter and is disallowed by UTS46 unconditionally.
    // Asserting that here keeps the fixture honest: if idna ever accepted
    // it, this test would otherwise silently stop covering the `Err` path.
    const MALFORMED: &str = "ex\u{FFFF}ample.invalid";
    assert!(
        idna::domain_to_ascii(MALFORMED).is_err(),
        "fixture must actually be rejected by idna"
    );
    arm_server(&entry("44444444-0000-0000-0000-000000000000", MALFORMED));
    let token = token_for("44444444-0000-0000-0000-000000000000");
    assert_eq!(
        redact_str(&format!("dialing {MALFORMED}:8388")),
        format!("dialing {token}:8388"),
        "one undrivable candidate must not suppress the others"
    );
}

#[skuld::test]
fn arm_server_ignores_an_empty_address() {
    arm_server(&entry("55555555-0000-0000-0000-000000000000", ""));
    assert_eq!(util::redact::armed_literal_count(), 0);
    assert!(!is_redacted("an ordinary log line"));
}

#[skuld::test]
fn arm_server_ignores_loopback() {
    arm_server(&entry("66666666-0000-0000-0000-000000000000", "127.0.0.1"));
    assert_eq!(util::redact::armed_literal_count(), 0);
    assert!(!is_redacted("socks5 listener on 127.0.0.1:4073"));
}

#[skuld::test]
fn arm_server_ignores_the_unspecified_address() {
    arm_server(&entry("77777777-0000-0000-0000-000000000000", "0.0.0.0"));
    assert_eq!(util::redact::armed_literal_count(), 0);
    assert!(!is_redacted("bound 0.0.0.0:8388"));
}

#[skuld::test]
fn arm_server_ignores_a_trailing_dot_loopback() {
    // `"127.0.0.1."` does not parse as an `IpAddr`, so a carve-out applied
    // to the configured value alone passes it through — and the
    // trailing-dot strip then arms the bare loopback address.
    arm_server(&entry("88888888-0000-0000-0000-000000000000", "127.0.0.1."));
    assert!(
        !is_redacted("netsh wfp show filters localaddr=127.0.0.1"),
        "arming loopback turns every loopback mention in the process into a token"
    );
    assert!(!is_redacted("dns forwarder on 127.0.0.1:53"));
}

#[skuld::test]
fn arm_server_ignores_localhost_in_any_casing() {
    arm_server(&entry("99999999-0000-0000-0000-000000000000", "LocalHost"));
    assert_eq!(util::redact::armed_literal_count(), 0);
    assert!(!is_redacted("connecting to localhost:4073"));
}

// arm_resolved_ip =====================================================================================================

#[skuld::test]
fn arm_resolved_ip_ignores_loopback_and_the_unspecified_address() {
    // The carve-out is implemented once but reached by two callers, and
    // `ServerEntry::default_placeholder` is literally `127.0.0.1`.
    arm_resolved_ip("aaaaaaaa-0000-0000-0000-000000000000", IpAddr::V4(Ipv4Addr::LOCALHOST));
    arm_resolved_ip("aaaaaaaa-0000-0000-0000-000000000000", IpAddr::V6(Ipv6Addr::LOCALHOST));
    arm_resolved_ip(
        "aaaaaaaa-0000-0000-0000-000000000000",
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    );
    arm_resolved_ip(
        "aaaaaaaa-0000-0000-0000-000000000000",
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    );
    assert_eq!(util::redact::armed_literal_count(), 0);
    assert!(!is_redacted("plugin handoff to 127.0.0.1:1080 and [::1]:1080"));
}

#[skuld::test]
fn arm_resolved_ip_covers_the_bracketed_v6_handoff_form() {
    let ip: IpAddr = "2001:db8::1".parse().expect("literal");
    arm_resolved_ip("bbbbbbbb-0000-0000-0000-000000000000", ip);
    let token = token_for("bbbbbbbb-0000-0000-0000-000000000000");
    assert_eq!(
        redact_str("creating connection to [2001:db8::1]:443"),
        format!("creating connection to {token}:443"),
        "handoff_host brackets IPv6; the bare form alone leaves the brackets around a bare address"
    );
    assert_eq!(redact_str("remote 2001:db8::1"), format!("remote {token}"));
}

// Classification ======================================================================================================

#[skuld::test]
fn ip_scope_labels_the_four_classes() {
    let cases: [(&str, &str); 8] = [
        ("203.0.113.7", "global"),
        ("2001:db8::1", "global"),
        ("192.168.1.1", "private"),
        ("fd00::1", "private"),
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("169.254.1.1", "link_local"),
        ("fe80::1", "link_local"),
    ];
    for (text, expected) in cases {
        let ip: IpAddr = text.parse().expect("literal");
        assert_eq!(ip_scope(ip), expected, "{text}");
    }
}

#[skuld::test]
fn server_kind_labels_domain_ipv4_and_ipv6() {
    assert_eq!(server_kind("vpn.example.invalid"), "domain");
    assert_eq!(server_kind("203.0.113.7"), "ipv4");
    assert_eq!(server_kind("2001:db8::1"), "ipv6");
    assert_eq!(server_kind("[2001:db8::1]"), "ipv6");
    assert_eq!(server_kind(""), "domain");
}

#[skuld::test]
fn ip_family_labels_v4_and_v6() {
    assert_eq!(ip_family(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))), "ipv4");
    assert_eq!(ip_family("2001:db8::1".parse().expect("literal")), "ipv6");
}
