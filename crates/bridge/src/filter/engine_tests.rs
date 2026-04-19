use std::net::{IpAddr, SocketAddr};

use hole_common::config::{FilterAction, FilterRule, MatchType};

use super::*;
use crate::filter::rules::RuleSet;

// Helpers =============================================================================================================

fn rule(addr: &str, kind: MatchType, action: FilterAction) -> FilterRule {
    FilterRule {
        address: addr.to_string(),
        matching: kind,
        action,
    }
}

fn conn(dst: &str, port: u16, domain: Option<&str>) -> ConnInfo {
    ConnInfo {
        dst: SocketAddr::new(dst.parse::<IpAddr>().unwrap(), port),
        domain: domain.map(|s| s.to_string()),
        proto: L4Proto::Tcp,
    }
}

// Default fallback ====================================================================================================

#[skuld::test]
fn empty_ruleset_falls_back_to_proxy() {
    let rs = RuleSet::from_user_rules(&[]);
    assert_eq!(decide(&rs, &conn("1.2.3.4", 443, None)).action, FilterAction::Proxy);
}

#[skuld::test]
fn ruleset_with_only_invalid_rules_falls_back_to_proxy() {
    let rs = RuleSet::from_user_rules(&[rule("nonsense", MatchType::Subnet, FilterAction::Block)]);
    assert!(rs.rules.is_empty());
    assert_eq!(rs.dropped.len(), 1);
    assert_eq!(decide(&rs, &conn("1.2.3.4", 443, None)).action, FilterAction::Proxy);
}

// Single-rule basics ==================================================================================================

#[skuld::test]
fn single_proxy_rule() {
    let rs = RuleSet::from_user_rules(&[rule("example.com", MatchType::Exactly, FilterAction::Proxy)]);
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("example.com"))).action,
        FilterAction::Proxy
    );
}

#[skuld::test]
fn single_block_rule() {
    let rs = RuleSet::from_user_rules(&[rule("example.com", MatchType::Exactly, FilterAction::Block)]);
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("example.com"))).action,
        FilterAction::Block
    );
}

#[skuld::test]
fn single_bypass_rule() {
    let rs = RuleSet::from_user_rules(&[rule("10.0.0.0/8", MatchType::Subnet, FilterAction::Bypass)]);
    assert_eq!(decide(&rs, &conn("10.1.2.3", 443, None)).action, FilterAction::Bypass);
}

#[skuld::test]
fn no_matching_rule_falls_back_to_proxy() {
    let rs = RuleSet::from_user_rules(&[rule("example.com", MatchType::Exactly, FilterAction::Block)]);
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("other.com"))).action,
        FilterAction::Proxy
    );
}

// Gitignore semantics: worked example from the design spec ============================================================

#[skuld::test]
fn worked_example_a_example_com_proxied() {
    // example.com (with subdomains) → block
    // a.example.com (exactly) → proxy
    // a.example.com matches rule index 1 (later) → proxy
    let rs = RuleSet::from_user_rules(&[
        rule("example.com", MatchType::WithSubdomains, FilterAction::Block),
        rule("a.example.com", MatchType::Exactly, FilterAction::Proxy),
    ]);
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("a.example.com"))).action,
        FilterAction::Proxy
    );
}

#[skuld::test]
fn worked_example_b_example_com_blocked() {
    let rs = RuleSet::from_user_rules(&[
        rule("example.com", MatchType::WithSubdomains, FilterAction::Block),
        rule("a.example.com", MatchType::Exactly, FilterAction::Proxy),
    ]);
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("b.example.com"))).action,
        FilterAction::Block
    );
}

#[skuld::test]
fn worked_example_apex_blocked() {
    let rs = RuleSet::from_user_rules(&[
        rule("example.com", MatchType::WithSubdomains, FilterAction::Block),
        rule("a.example.com", MatchType::Exactly, FilterAction::Proxy),
    ]);
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("example.com"))).action,
        FilterAction::Block
    );
}

// Reverse-iteration ordering ==========================================================================================

#[skuld::test]
fn later_rule_overrides_earlier_for_same_address() {
    let rs = RuleSet::from_user_rules(&[
        rule("example.com", MatchType::Exactly, FilterAction::Bypass),
        rule("example.com", MatchType::Exactly, FilterAction::Block),
    ]);
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("example.com"))).action,
        FilterAction::Block
    );
}

#[skuld::test]
fn earlier_rule_wins_when_no_later_rule_matches() {
    let rs = RuleSet::from_user_rules(&[
        rule("example.com", MatchType::Exactly, FilterAction::Block),
        rule("other.com", MatchType::Exactly, FilterAction::Bypass),
    ]);
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("example.com"))).action,
        FilterAction::Block
    );
}

// Mixed domain + IP rules =============================================================================================

#[skuld::test]
fn mixed_rules_ip_subnet_later_wins() {
    // Connection has both an IP and a domain. The Subnet rule (index 1)
    // appears later, so it wins over the domain rule.
    let rs = RuleSet::from_user_rules(&[
        rule("example.com", MatchType::Exactly, FilterAction::Block),
        rule("1.2.3.0/24", MatchType::Subnet, FilterAction::Bypass),
    ]);
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("example.com"))).action,
        FilterAction::Bypass
    );
}

#[skuld::test]
fn mixed_rules_domain_later_wins() {
    let rs = RuleSet::from_user_rules(&[
        rule("1.2.3.0/24", MatchType::Subnet, FilterAction::Bypass),
        rule("example.com", MatchType::Exactly, FilterAction::Block),
    ]);
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("example.com"))).action,
        FilterAction::Block
    );
}

#[skuld::test]
fn ip_only_connection_with_domain_rule_in_set_falls_through() {
    // No domain on the connection — domain rule cannot match.
    let rs = RuleSet::from_user_rules(&[
        rule("example.com", MatchType::Exactly, FilterAction::Block),
        rule("1.2.3.0/24", MatchType::Subnet, FilterAction::Bypass),
    ]);
    assert_eq!(decide(&rs, &conn("1.2.3.4", 443, None)).action, FilterAction::Bypass);
}

#[skuld::test]
fn ip_only_connection_no_ip_rule_falls_back_to_proxy() {
    let rs = RuleSet::from_user_rules(&[rule("example.com", MatchType::Exactly, FilterAction::Block)]);
    assert_eq!(decide(&rs, &conn("9.9.9.9", 443, None)).action, FilterAction::Proxy);
}

// Three locked default rules (matches the UI's planned behavior) ======================================================

#[skuld::test]
fn three_locked_default_rules_pass_everything_through() {
    let rs = RuleSet::from_user_rules(&[
        rule("*", MatchType::Wildcard, FilterAction::Proxy),
        rule("0.0.0.0/0", MatchType::Subnet, FilterAction::Proxy),
        rule("::/0", MatchType::Subnet, FilterAction::Proxy),
    ]);
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("example.com"))).action,
        FilterAction::Proxy
    );
    assert_eq!(decide(&rs, &conn("1.2.3.4", 443, None)).action, FilterAction::Proxy);
    assert_eq!(decide(&rs, &conn("::1", 443, None)).action, FilterAction::Proxy);
}

#[skuld::test]
fn block_rule_overrides_locked_defaults() {
    let rs = RuleSet::from_user_rules(&[
        rule("*", MatchType::Wildcard, FilterAction::Proxy),
        rule("0.0.0.0/0", MatchType::Subnet, FilterAction::Proxy),
        rule("::/0", MatchType::Subnet, FilterAction::Proxy),
        rule("evil.com", MatchType::WithSubdomains, FilterAction::Block),
    ]);
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("api.evil.com"))).action,
        FilterAction::Block
    );
    assert_eq!(
        decide(&rs, &conn("1.2.3.4", 443, Some("good.com"))).action,
        FilterAction::Proxy
    );
}
