use hole_common::config::{FilterAction, FilterRule, MatchType};

use super::*;
use crate::filter::matcher::Matcher;

fn rule(addr: &str, kind: MatchType, action: FilterAction) -> FilterRule {
    FilterRule {
        address: addr.to_string(),
        matching: kind,
        action,
    }
}

// Empty / trivial =====================================================================================================

#[skuld::test]
fn empty_input_yields_empty_ruleset() {
    let rs = RuleSet::from_user_rules(&[]);
    assert!(rs.rules.is_empty());
    assert!(rs.dropped.is_empty());
    assert!(!rs.has_domain_rules);
}

#[skuld::test]
fn single_valid_rule_compiles() {
    let rs = RuleSet::from_user_rules(&[rule("example.com", MatchType::Exactly, FilterAction::Proxy)]);
    assert_eq!(rs.rules.len(), 1);
    assert!(rs.dropped.is_empty());
    assert!(rs.has_domain_rules);
    assert!(matches!(rs.rules[0].matcher, Matcher::ExactDomain(_)));
    assert_eq!(rs.rules[0].action, FilterAction::Proxy);
}

// Order preservation ==================================================================================================

#[skuld::test]
fn order_preserved_through_compilation() {
    let rs = RuleSet::from_user_rules(&[
        rule("a.com", MatchType::Exactly, FilterAction::Block),
        rule("b.com", MatchType::Exactly, FilterAction::Bypass),
        rule("c.com", MatchType::Exactly, FilterAction::Proxy),
    ]);
    assert_eq!(rs.rules.len(), 3);
    assert_eq!(rs.rules[0].action, FilterAction::Block);
    assert_eq!(rs.rules[1].action, FilterAction::Bypass);
    assert_eq!(rs.rules[2].action, FilterAction::Proxy);
}

// Drop tracking =======================================================================================================

#[skuld::test]
fn invalid_rule_recorded_in_dropped_with_index() {
    let rs = RuleSet::from_user_rules(&[
        rule("good.com", MatchType::Exactly, FilterAction::Proxy),
        rule("not-a-cidr", MatchType::Subnet, FilterAction::Block),
        rule("also-good.com", MatchType::Exactly, FilterAction::Bypass),
    ]);
    assert_eq!(rs.rules.len(), 2);
    assert_eq!(rs.dropped.len(), 1);
    assert_eq!(rs.dropped[0].index, 1);
    assert!(rs.dropped[0].error.contains("CIDR"), "got: {}", rs.dropped[0].error);
}

#[skuld::test]
fn multiple_invalid_rules_each_recorded() {
    let rs = RuleSet::from_user_rules(&[
        rule("not-a-cidr", MatchType::Subnet, FilterAction::Block),
        rule("good.com", MatchType::Exactly, FilterAction::Proxy),
        rule("", MatchType::Exactly, FilterAction::Bypass),
        rule("1.2.3.4", MatchType::WithSubdomains, FilterAction::Block),
    ]);
    assert_eq!(rs.rules.len(), 1);
    assert_eq!(rs.dropped.len(), 3);
    let indices: Vec<u32> = rs.dropped.iter().map(|d| d.index).collect();
    assert_eq!(indices, vec![0, 2, 3]);
}

#[skuld::test]
fn drop_index_matches_user_input_position() {
    // Indices in `dropped` reference the original positions in the
    // user's `Vec<FilterRule>`, not positions after dropping.
    let rs = RuleSet::from_user_rules(&[
        rule("good1.com", MatchType::Exactly, FilterAction::Proxy),
        rule("good2.com", MatchType::Exactly, FilterAction::Proxy),
        rule("not-a-cidr", MatchType::Subnet, FilterAction::Block),
        rule("good3.com", MatchType::Exactly, FilterAction::Proxy),
    ]);
    assert_eq!(rs.rules.len(), 3);
    assert_eq!(rs.dropped.len(), 1);
    assert_eq!(rs.dropped[0].index, 2);
}

// has_domain_rules cache ==============================================================================================

#[skuld::test]
fn has_domain_rules_false_for_ip_only_set() {
    let rs = RuleSet::from_user_rules(&[
        rule("10.0.0.0/8", MatchType::Subnet, FilterAction::Bypass),
        rule("1.2.3.4", MatchType::Exactly, FilterAction::Block),
    ]);
    assert!(!rs.has_domain_rules);
}

#[skuld::test]
fn has_domain_rules_true_for_exact_domain() {
    let rs = RuleSet::from_user_rules(&[rule("example.com", MatchType::Exactly, FilterAction::Block)]);
    assert!(rs.has_domain_rules);
}

#[skuld::test]
fn has_domain_rules_true_for_subdomain() {
    let rs = RuleSet::from_user_rules(&[rule("example.com", MatchType::WithSubdomains, FilterAction::Block)]);
    assert!(rs.has_domain_rules);
}

#[skuld::test]
fn has_domain_rules_true_for_wildcard() {
    let rs = RuleSet::from_user_rules(&[rule("*.example.com", MatchType::Wildcard, FilterAction::Block)]);
    assert!(rs.has_domain_rules);
}

#[skuld::test]
fn has_domain_rules_false_for_exactly_with_ip_literal() {
    // `Exactly` with an IP literal compiles to ExactIp, not ExactDomain.
    let rs = RuleSet::from_user_rules(&[rule("1.2.3.4", MatchType::Exactly, FilterAction::Block)]);
    assert!(!rs.has_domain_rules);
}

#[skuld::test]
fn has_domain_rules_true_when_mixed() {
    let rs = RuleSet::from_user_rules(&[
        rule("10.0.0.0/8", MatchType::Subnet, FilterAction::Bypass),
        rule("example.com", MatchType::Exactly, FilterAction::Block),
    ]);
    assert!(rs.has_domain_rules);
}

// Compile-time IP-vs-domain dispatch ==================================================================================

#[skuld::test]
fn exactly_with_ipv4_literal_compiles_to_exact_ip() {
    let rs = RuleSet::from_user_rules(&[rule("1.2.3.4", MatchType::Exactly, FilterAction::Block)]);
    assert!(matches!(rs.rules[0].matcher, Matcher::ExactIp(_)));
}

#[skuld::test]
fn exactly_with_ipv6_literal_compiles_to_exact_ip() {
    let rs = RuleSet::from_user_rules(&[rule("2001:db8::1", MatchType::Exactly, FilterAction::Block)]);
    assert!(matches!(rs.rules[0].matcher, Matcher::ExactIp(_)));
}

#[skuld::test]
fn exactly_with_domain_compiles_to_exact_domain() {
    let rs = RuleSet::from_user_rules(&[rule("example.com", MatchType::Exactly, FilterAction::Block)]);
    assert!(matches!(rs.rules[0].matcher, Matcher::ExactDomain(_)));
}
