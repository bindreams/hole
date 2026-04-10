//! Cross-module smoke tests for the filter engine. Per-module unit tests
//! live in `filter/{rules,matcher,engine}_tests.rs`.

use hole_common::config::{FilterAction, FilterRule, MatchType};

use super::{decide, ConnInfo, L4Proto, RuleSet};

#[skuld::test]
fn re_exports_decide_constructable_from_user_rules() {
    let user_rules = vec![FilterRule {
        address: "example.com".into(),
        matching: MatchType::Exactly,
        action: FilterAction::Block,
    }];

    let rs = RuleSet::from_user_rules(&user_rules);
    let conn = ConnInfo {
        dst_ip: "1.2.3.4".parse().unwrap(),
        dst_port: 443,
        domain: Some("example.com".into()),
        proto: L4Proto::Tcp,
    };

    assert_eq!(decide(&rs, &conn), FilterAction::Block);
}
