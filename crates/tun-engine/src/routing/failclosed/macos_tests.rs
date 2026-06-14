use super::*;
use std::net::IpAddr;

fn v4() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}
fn v6() -> IpAddr {
    "2001:db8::1".parse().unwrap()
}

#[skuld::test]
fn ruleset_blocks_all_outbound() {
    let r = build_pf_ruleset(v4());
    assert!(
        r.contains("block") && r.contains("out") && r.contains("all"),
        "ruleset must block all outbound:\n{r}"
    );
}

#[skuld::test]
fn ruleset_passes_loopback() {
    let r = build_pf_ruleset(v4());
    assert!(r.contains("lo0"), "ruleset must pass loopback:\n{r}");
}

#[skuld::test]
fn ruleset_passes_server_ip() {
    let r = build_pf_ruleset(v4());
    assert!(r.contains("203.0.113.7"), "ruleset must pass server IP:\n{r}");
}

#[skuld::test]
fn ruleset_pass_rules_are_quick() {
    // `quick` makes the pass rules win over the earlier block-all without
    // relying on pf's last-match semantics.
    let r = build_pf_ruleset(v4());
    for line in r.lines().filter(|l| l.trim_start().starts_with("pass")) {
        assert!(line.contains("quick"), "pass rule must be quick: {line}");
    }
}

#[skuld::test]
fn ruleset_handles_ipv6_server() {
    let r = build_pf_ruleset(v6());
    assert!(r.contains("2001:db8::1"), "ipv6 server must appear:\n{r}");
}

#[skuld::test]
fn parse_enable_token_extracts_token() {
    // `pfctl -E` prints to stderr e.g. "pf enabled\nToken : 12345678901234567890\n"
    let out = "pf enabled\nToken : 12345678901234567890\n";
    assert_eq!(parse_enable_token(out).as_deref(), Some("12345678901234567890"));
}

#[skuld::test]
fn parse_enable_token_none_when_absent() {
    assert_eq!(parse_enable_token("pf already enabled\n"), None);
}

#[skuld::test]
fn parse_pf_enabled_reads_status() {
    assert!(parse_pf_enabled("Status: Enabled for 0 days...\n"));
    assert!(!parse_pf_enabled("Status: Disabled\n"));
}

// build_lockdown_ruleset (anchor body) ================================================================================

#[skuld::test]
fn lockdown_ruleset_blocks_all_outbound() {
    let r = build_lockdown_ruleset("utun8", v4());
    assert!(r.contains("block out"), "lockdown anchor must block outbound:\n{r}");
}

#[skuld::test]
fn lockdown_ruleset_passes_loopback() {
    let r = build_lockdown_ruleset("utun8", v4());
    assert!(r.contains("lo0"), "lockdown anchor must pass loopback:\n{r}");
}

#[skuld::test]
fn lockdown_ruleset_passes_tun_interface() {
    // The defining difference from the transient cover: app traffic flows
    // through the TUN while connected.
    let r = build_lockdown_ruleset("utun8", v4());
    assert!(
        r.contains("pass out quick on utun8 all"),
        "lockdown anchor must pass the TUN interface:\n{r}"
    );
}

#[skuld::test]
fn lockdown_ruleset_passes_server_ip() {
    let r = build_lockdown_ruleset("utun8", v4());
    // Match the transient cover idiom `pass out quick from any to {ip}` unless
    // a reason to diverge surfaces on the host (Task 15).
    assert!(
        r.contains("pass out quick from any to 203.0.113.7"),
        "lockdown anchor must pass server IP:\n{r}"
    );
}

#[skuld::test]
fn lockdown_ruleset_pass_rules_are_quick() {
    let r = build_lockdown_ruleset("utun8", v4());
    for line in r.lines().filter(|l| l.trim_start().starts_with("pass")) {
        assert!(line.contains("quick"), "pass rule must be quick: {line}");
    }
}

#[skuld::test]
fn lockdown_ruleset_handles_ipv6_server() {
    let r = build_lockdown_ruleset("utun8", v6());
    assert!(r.contains("2001:db8::1"), "ipv6 server must appear:\n{r}");
}

// build_main_ruleset_with_anchor (the inert-anchor fix) ===============================================================

#[skuld::test]
fn composed_main_references_the_lockdown_anchor() {
    // WITHOUT this call-out the anchor body never evaluates and the kill
    // switch is a no-op. This is the test that catches the inert-anchor bug.
    let snapshot = "scrub-anchor \"com.apple/*\" all fragment reassemble\n";
    let main = build_main_ruleset_with_anchor(snapshot);
    assert!(
        main.contains("anchor \"com.hole.lockdown\""),
        "composed main MUST call out the lockdown anchor:\n{main}"
    );
}

#[skuld::test]
fn composed_main_preserves_the_snapshot() {
    // The composed ruleset is loaded without `-Fa`, so it must carry the
    // host's prior rules verbatim (no flush of user/MDM policy).
    let snapshot = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n";
    let main = build_main_ruleset_with_anchor(snapshot);
    assert!(main.contains(snapshot), "snapshot rules must be preserved:\n{main}");
}

#[skuld::test]
fn composed_main_anchor_call_follows_the_snapshot() {
    // The anchor call must come AFTER the snapshot so the snapshot's own
    // anchors keep their relative order; a `quick`-free anchor evaluates by
    // last-match, and our body uses `quick` so position past the snapshot is
    // safe and deterministic.
    let snapshot = "anchor \"com.apple/*\" all\n";
    let main = build_main_ruleset_with_anchor(snapshot);
    let snap_at = main.find("com.apple/*").unwrap();
    let lock_at = main.find("com.hole.lockdown").unwrap();
    assert!(
        lock_at > snap_at,
        "lockdown anchor call must follow the snapshot:\n{main}"
    );
}
