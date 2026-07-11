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
    let r = build_pf_ruleset(v4(), &[]);
    assert!(
        r.contains("block") && r.contains("out") && r.contains("all"),
        "ruleset must block all outbound:\n{r}"
    );
}

#[skuld::test]
fn ruleset_passes_loopback() {
    let r = build_pf_ruleset(v4(), &[]);
    assert!(r.contains("lo0"), "ruleset must pass loopback:\n{r}");
}

#[skuld::test]
fn ruleset_passes_server_ip() {
    let r = build_pf_ruleset(v4(), &[]);
    assert!(r.contains("203.0.113.7"), "ruleset must pass server IP:\n{r}");
}

#[skuld::test]
fn ruleset_pass_rules_are_quick() {
    // `quick` makes the pass rules win over the earlier block-all without
    // relying on pf's last-match semantics.
    let r = build_pf_ruleset(v4(), &[]);
    for line in r.lines().filter(|l| l.trim_start().starts_with("pass")) {
        assert!(line.contains("quick"), "pass rule must be quick: {line}");
    }
}

#[skuld::test]
fn ruleset_handles_ipv6_server() {
    let r = build_pf_ruleset(v6(), &[]);
    assert!(r.contains("2001:db8::1"), "ipv6 server must appear:\n{r}");
}

#[skuld::test]
fn ruleset_passes_resolver_ips_with_quick() {
    // The DoH bootstrap must reach the configured resolver IPs while the cover
    // holds; each resolver gets its own `quick` pass. The resolver IP is distinct
    // from the server IP so the pre-existing server pass cannot satisfy this.
    let resolver_v4: IpAddr = "1.1.1.1".parse().unwrap();
    let resolver_v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
    assert_ne!(resolver_v4, v4());
    let r = build_pf_ruleset(v4(), &[resolver_v4, resolver_v6]);
    for ip in ["1.1.1.1", "2606:4700:4700::1111"] {
        let pass = r
            .lines()
            .find(|l| l.trim_start().starts_with("pass") && l.contains(ip))
            .unwrap_or_else(|| panic!("resolver pass for {ip} missing:\n{r}"));
        assert!(pass.contains("quick"), "resolver pass must be quick: {pass}");
    }
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

#[skuld::test]
fn disengage_lockdown_absent_cover_is_ok() {
    // No state file => no cover engaged => Ok (the early return precedes any
    // pfctl spawn, so this touches no host state). `bridge unlock` on a clean
    // host must succeed, not fail loud.
    let dir = tempfile::tempdir().unwrap();
    assert!(disengage_lockdown(dir.path()).is_ok());
}

// engage_pf_action (idempotent-enable decision) =======================================================================

#[skuld::test]
fn engage_action_no_persisted_state_is_fresh_enable() {
    // First engage: snapshot the host + `pfctl -E`, regardless of pf's current state.
    assert_eq!(engage_pf_action(false, false), PfEngageAction::FreshEnable);
    assert_eq!(engage_pf_action(true, false), PfEngageAction::FreshEnable);
}

#[skuld::test]
fn engage_action_persisted_but_pf_disabled_reenables() {
    // Reboot reset pf + its refcount but the state file survived: the old token is
    // stale, so re-enable and capture a fresh one — else the ruleset loads inert.
    assert_eq!(engage_pf_action(false, true), PfEngageAction::Reenable);
}

#[skuld::test]
fn engage_action_persisted_and_pf_enabled_reuses_token() {
    // Live Adopt re-engage within one boot: pf still enabled and we hold the token —
    // reuse it, do NOT double `-E` (that would inflate the refcount).
    assert_eq!(engage_pf_action(true, true), PfEngageAction::ReuseToken);
}

// ensure_trailing_nl ==================================================================================================

#[skuld::test]
fn ensure_trailing_nl_empty_stays_empty() {
    // Empty NAT snapshot must contribute NOTHING — not a stray blank line that
    // would land between the `set` options and the first filter rule.
    assert_eq!(ensure_trailing_nl(""), "");
}

#[skuld::test]
fn ensure_trailing_nl_adds_missing_newline() {
    assert_eq!(
        ensure_trailing_nl("nat on en0 from any to any -> (en0)"),
        "nat on en0 from any to any -> (en0)\n"
    );
}

#[skuld::test]
fn ensure_trailing_nl_keeps_single_newline() {
    assert_eq!(
        ensure_trailing_nl("nat-anchor \"com.apple/*\" all\n"),
        "nat-anchor \"com.apple/*\" all\n"
    );
}

// build_lockdown_main_ruleset (authoritative main-ruleset replace) ====================================================

const TUN: &str = "hole-tun";

fn lockdown(ip: IpAddr, nat: &str) -> String {
    build_lockdown_main_ruleset(TUN, ip, nat)
}

#[skuld::test]
fn lockdown_main_has_block_drop_out_quick_all_base() {
    // The fail-closed base: every outbound packet is dropped unless an earlier
    // `quick` permit already matched.
    let r = lockdown(v4(), "");
    assert!(
        r.contains("block drop out quick all"),
        "lockdown main must have the block-drop base:\n{r}"
    );
}

#[skuld::test]
fn lockdown_main_blocks_ipv6() {
    // No IPv6 permit exists for app traffic, so v6 egress is dropped wholesale
    // to prevent a v6 leak around the v4 tunnel.
    let r = lockdown(v4(), "");
    assert!(
        r.contains("block drop out quick inet6 all"),
        "lockdown main must block IPv6 egress:\n{r}"
    );
}

#[skuld::test]
fn lockdown_main_passes_tun_interface() {
    // The defining difference from the transient cover: app traffic flows
    // through the TUN while connected.
    let r = lockdown(v4(), "");
    assert!(
        r.contains("pass out quick on hole-tun all"),
        "lockdown main must pass the TUN interface:\n{r}"
    );
}

#[skuld::test]
fn lockdown_main_passes_server_ip_over_tcp() {
    let r = lockdown(v4(), "");
    assert!(
        r.contains("pass out quick proto tcp from any to 203.0.113.7"),
        "lockdown main must pass the server IP over tcp:\n{r}"
    );
}

#[skuld::test]
fn lockdown_main_skips_loopback() {
    // `set skip on lo0` exempts loopback from filtering wholesale.
    let r = lockdown(v4(), "");
    assert!(r.contains("set skip on lo0"), "lockdown main must skip lo0:\n{r}");
}

#[skuld::test]
fn lockdown_main_every_filter_rule_is_quick() {
    // Every pass/block filter rule must be `quick` so it is order-independent
    // and beats any carried-forward host rule once we own the ruleset.
    let r = lockdown(v4(), "nat-anchor \"com.apple/*\" all\n");
    for line in r.lines().filter(|l| {
        let t = l.trim_start();
        t.starts_with("pass") || t.starts_with("block")
    }) {
        assert!(line.contains("quick"), "filter rule must be quick: {line}");
    }
}

#[skuld::test]
fn lockdown_main_set_options_lead() {
    // `set` is main-ruleset-only and `require-order` puts Options first.
    let r = lockdown(v4(), "");
    assert!(
        r.starts_with("set block-policy drop\n"),
        "must open with block-policy:\n{r}"
    );
    assert!(r.contains("set skip on lo0\n"), "must set skip on lo0:\n{r}");
}

#[skuld::test]
fn lockdown_main_no_set_after_first_filter_rule() {
    // No stray `set` may appear after filtering begins — `set` is illegal once
    // the ruleset moves past the Options section.
    let r = lockdown(v4(), "nat-anchor \"com.apple/*\" all\n");
    let first_filter = r
        .find("pass")
        .or_else(|| r.find("block"))
        .expect("a filter rule must exist");
    assert!(
        !r[first_filter..].contains("set "),
        "no `set ` may follow the first filter rule:\n{r}"
    );
}

#[skuld::test]
fn lockdown_main_nat_precedes_filter() {
    // `require-order`: Options -> Translation (nat) -> Filter. The carried NAT
    // must sit before the first filter rule.
    let nat = "nat on en0 from any to any -> (en0)\n";
    let r = lockdown(v4(), nat);
    let nat_at = r.find("nat on en0").expect("nat must appear");
    let first_filter = r.find("block drop out quick inet6 all").expect("filter must appear");
    assert!(nat_at < first_filter, "nat must precede the first filter rule:\n{r}");
}

#[skuld::test]
fn lockdown_main_empty_nat_has_no_blank_line() {
    // An empty NAT snapshot must not inject a blank line between the `set`
    // options and the first filter rule.
    let r = lockdown(v4(), "");
    assert!(!r.contains("\n\n"), "empty nat must not produce a blank line:\n{r}");
}

#[skuld::test]
fn lockdown_main_carries_nat_verbatim() {
    let nat = "nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n";
    let r = lockdown(v4(), nat);
    assert!(r.contains(nat), "nat snapshot must be carried verbatim:\n{r}");
}

#[skuld::test]
fn lockdown_main_v6_server_permit_precedes_inet6_block() {
    // A v6 server must be permitted BEFORE the wholesale inet6 block, or the
    // tunnel's own onward connection is killed.
    let r = lockdown(v6(), "");
    let permit_at = r.find("to 2001:db8::1").expect("v6 server permit must appear");
    let block_at = r
        .find("block drop out quick inet6 all")
        .expect("inet6 block must appear");
    assert!(
        permit_at < block_at,
        "v6 server permit must precede the inet6 block:\n{r}"
    );
}

// build_lockdown_restore_ruleset (Sweep restore) ======================================================================

// `pfctl -sr` on macOS emits a normalization line (`scrub-anchor`) interleaved
// with filter rules; with require-order enforced, `{nat}{filter}` would put
// translation before normalization and the restore would fail to parse.
const FILTER_SNAP: &str = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n";
const NAT_SNAP: &str = "nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n";

#[skuld::test]
fn restore_disables_require_order() {
    // Without this the restore parse-fails on a stock host (scrub after nat).
    let r = build_lockdown_restore_ruleset(NAT_SNAP, FILTER_SNAP);
    assert!(
        r.contains("set require-order no"),
        "restore must disable require-order so the captured snapshot loads verbatim:\n{r}"
    );
}

#[skuld::test]
fn restore_require_order_leads() {
    // `set` is options-section-only; the require-order toggle must precede any
    // captured rule, or it cannot relax the order check for what follows.
    let r = build_lockdown_restore_ruleset(NAT_SNAP, FILTER_SNAP);
    assert!(
        r.starts_with("set require-order no\n"),
        "require-order toggle must lead:\n{r}"
    );
}

#[skuld::test]
fn restore_carries_both_snapshots_verbatim() {
    let r = build_lockdown_restore_ruleset(NAT_SNAP, FILTER_SNAP);
    assert!(r.contains(NAT_SNAP), "nat snapshot must be carried verbatim:\n{r}");
    assert!(
        r.contains(FILTER_SNAP),
        "filter snapshot must be carried verbatim:\n{r}"
    );
}

#[skuld::test]
fn restore_empty_nat_has_no_blank_line() {
    // An empty nat snapshot must not inject a blank line into the restore.
    let r = build_lockdown_restore_ruleset("", FILTER_SNAP);
    assert!(!r.contains("\n\n"), "empty nat must not produce a blank line:\n{r}");
}
