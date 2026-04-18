//! Minimal smoke tests for `HoleRouter`.
//!
//! The interesting dispatch paths (filter decisions, fake DNS rewrites,
//! SOCKS5 splicing) are exercised indirectly via the full `ProxyManager`
//! e2e tests; this file only guards against trivial mis-wiring.

use super::*;
use crate::filter::rules::RuleSet;

fn resolver() -> upstream_dns::UpstreamResolver {
    upstream_dns::UpstreamResolver::new(&[])
}

#[skuld::test]
fn swap_rules_updates_and_invalid_filters_reads() {
    let r = HoleRouter::new(1080, 1, false, true, RuleSet::default(), None, resolver());
    assert!(r.invalid_filters().is_empty());
    r.swap_rules(RuleSet::default());
    assert!(r.invalid_filters().is_empty());
}
