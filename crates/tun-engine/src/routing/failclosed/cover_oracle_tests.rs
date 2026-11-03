use super::cover_oracle::ruleset_has_block_rule;

// Fixtures are `pfctl -sr` listings written out by hand, not produced by Hole's ruleset builders.

const CLEAN_RUNNER: &str = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n";

#[skuld::test]
fn a_clean_runners_ruleset_has_no_block_rule() {
    assert!(!ruleset_has_block_rule(CLEAN_RUNNER));
}

#[skuld::test]
fn an_empty_listing_has_no_block_rule() {
    assert!(!ruleset_has_block_rule(""));
}

#[skuld::test]
fn a_transient_cover_ruleset_has_a_block_rule() {
    let listing = format!("{CLEAN_RUNNER}block drop out all\npass out quick from any to 203.0.113.9 no state\n");
    assert!(ruleset_has_block_rule(&listing));
}

#[skuld::test]
fn a_lockdown_cover_ruleset_has_a_block_rule() {
    let listing = format!("{CLEAN_RUNNER}block drop out quick all label \"hole-lockdown\"\n");
    assert!(ruleset_has_block_rule(&listing));
}

#[skuld::test]
fn an_indented_block_rule_is_a_block_rule() {
    assert!(ruleset_has_block_rule("  block drop in all\n"));
}

#[skuld::test]
fn a_line_that_only_mentions_block_is_not_a_block_rule() {
    let listing = "anchor \"block-list/*\" all\n\
                   pass out quick proto tcp from any to 203.0.113.9 port = 443 no state label \"block\"\n\
                   scrub-anchor \"blocked/*\" all\n\
                   blocklist\n";
    assert!(!ruleset_has_block_rule(listing));
}

// The macOS oracle reads a block rule off `pfctl -sr`; these feed it the rulesets Hole's own builders emit,
// so a builder that stops starting a line with `block` blinds the oracle here, not only in the privileged lane.

#[cfg(target_os = "macos")]
const SERVER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9));
#[cfg(target_os = "macos")]
const RESOLVER: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 53));

#[cfg(target_os = "macos")]
#[skuld::test]
fn the_transient_ruleset_without_a_resolver_has_a_block_rule() {
    let ruleset = super::platform::build_pf_ruleset(SERVER, None);
    assert!(ruleset_has_block_rule(&ruleset), "{ruleset}");
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn the_transient_ruleset_with_a_resolver_has_a_block_rule() {
    let ruleset = super::platform::build_pf_ruleset(SERVER, Some(RESOLVER));
    assert!(ruleset_has_block_rule(&ruleset), "{ruleset}");
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn the_lockdown_main_ruleset_has_a_block_rule() {
    let ruleset = super::platform::build_lockdown_main_ruleset("utun9", SERVER, "");
    assert!(ruleset_has_block_rule(&ruleset), "{ruleset}");
}
