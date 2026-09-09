use super::*;
use std::net::IpAddr;

// Aliased: this file already has its own `const TUN: &str = "hole-tun"` (the
// interface-name fixture for the lockdown ruleset builder tests), colliding
// with the `TUN` skuld label.
use crate::{GLOBAL_NET_STATE, TUN as TUN_LABEL};

fn v4() -> IpAddr {
    "203.0.113.7".parse().unwrap()
}
fn v6() -> IpAddr {
    "2001:db8::1".parse().unwrap()
}
fn resolver() -> IpAddr {
    "198.51.100.5".parse().unwrap()
}
fn resolver_v6() -> IpAddr {
    "2001:db8::abcd".parse().unwrap()
}

#[skuld::test]
fn ruleset_blocks_all_outbound() {
    let r = build_pf_ruleset(v4(), None);
    assert!(
        r.contains("block") && r.contains("out") && r.contains("all"),
        "ruleset must block all outbound:\n{r}"
    );
}

#[skuld::test]
fn ruleset_passes_loopback() {
    let r = build_pf_ruleset(v4(), None);
    assert!(r.contains("lo0"), "ruleset must pass loopback:\n{r}");
}

#[skuld::test]
fn ruleset_passes_server_ip() {
    let r = build_pf_ruleset(v4(), None);
    assert!(r.contains("203.0.113.7"), "ruleset must pass server IP:\n{r}");
}

#[skuld::test]
fn ruleset_pass_rules_are_quick() {
    // `quick` makes the pass rules win over the earlier block-all without
    // relying on pf's last-match semantics.
    let r = build_pf_ruleset(v4(), None);
    for line in r.lines().filter(|l| l.trim_start().starts_with("pass")) {
        assert!(line.contains("quick"), "pass rule must be quick: {line}");
    }
}

#[skuld::test]
fn ruleset_handles_ipv6_server() {
    let r = build_pf_ruleset(v6(), None);
    assert!(r.contains("2001:db8::1"), "ipv6 server must appear:\n{r}");
}

// resolver permit =====================================================================================================

#[skuld::test]
fn ruleset_passes_resolver_ip_when_given() {
    let r = build_pf_ruleset(v4(), Some(resolver()));
    assert!(r.contains("198.51.100.5"), "ruleset must pass the resolver IP:\n{r}");
}

#[skuld::test]
fn ruleset_omits_resolver_when_none() {
    // Negative direction: no resolver means the only "pass ... to <addr>" line
    // targets the server — proves the widening is opt-in.
    let r = build_pf_ruleset(v4(), None);
    let pass_to_lines: Vec<&str> = r
        .lines()
        .filter(|l| l.trim_start().starts_with("pass out quick") && l.contains(" to "))
        .collect();
    assert_eq!(pass_to_lines.len(), 1, "server only, no resolver pass rule:\n{r}");
}

#[skuld::test]
fn ruleset_resolver_pass_rule_is_quick() {
    let r = build_pf_ruleset(v4(), Some(resolver()));
    for line in r.lines().filter(|l| l.contains("198.51.100.5")) {
        assert!(line.contains("quick"), "resolver pass rule must be quick: {line}");
    }
}

#[skuld::test]
fn ruleset_handles_ipv6_resolver() {
    let r = build_pf_ruleset(v4(), Some(resolver_v6()));
    assert!(r.contains("2001:db8::abcd"), "ipv6 resolver must appear:\n{r}");
}

#[skuld::test]
fn ruleset_resolver_pass_is_scoped_to_tcp_443_not_unrestricted() {
    // NOT the server permit's unrestricted shape — see build_pf_ruleset's doc.
    let r = build_pf_ruleset(v4(), Some(resolver()));
    let resolver_line = r
        .lines()
        .find(|l| l.contains("198.51.100.5"))
        .expect("resolver pass rule must exist");
    let port_clause = format!("port {RESOLVER_PERMIT_PORT}");
    assert!(
        resolver_line.contains("proto tcp") && resolver_line.contains(&port_clause),
        "resolver pass rule must be scoped to proto tcp {port_clause}, unlike the server permit: {resolver_line}"
    );
    let server_line = r
        .lines()
        .find(|l| l.contains(&v4().to_string()))
        .expect("server pass rule must exist");
    assert!(
        !server_line.contains("port"),
        "server permit stays unrestricted: {server_line}"
    );
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

// disengage_lockdown_with (#882: gate on presence, not on the file) ===================================================
//
// `disengage_lockdown_absent_cover_is_ok` (the file-only gate this replaces)
// asserted that an absent *state file* alone was proof of nothing to
// disengage. That conflated "confirmed absent" with "could not tell" — the
// exact bug #882 describes: a corrupt/lost file must not read the same as a
// host pf genuinely confirmed clear. The replacement tests below gate on
// `CoverPresence` (pf's own answer folded with the file), which is what
// `disengage_lockdown` now consults, via the same `RecordingPfOps` seam
// `release_all_with` already uses — so none of this touches a real `pfctl`.

#[skuld::test]
fn disengage_lockdown_confirmed_absent_is_ok_and_spawns_no_pfctl() {
    // Both sources agree there is nothing: no pfctl spawned.
    let mut ops = RecordingPfOps::default();
    assert!(disengage_lockdown_with(CoverPresence::Absent, None, &mut ops).is_ok());
    assert!(ops.log.is_empty(), "a confirmed-absent cover must spawn no pfctl");
}

#[skuld::test]
fn an_absent_state_file_with_a_live_pf_label_still_disengages() {
    // pf's own label says the cover IS loaded even though the state file is
    // gone (lost, or never written this run) — presence is established
    // independently of the file. The old file-only gate would have read this
    // as "nothing to disengage" and returned Ok having done nothing (#882).
    // With no snapshot to restore from, the fallback is the blind
    // `/etc/pf.conf` reload.
    let mut ops = RecordingPfOps::default();
    let result = disengage_lockdown_with(CoverPresence::Live, None, &mut ops);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        ops.log,
        vec!["reload_default", "clear_standing"],
        "a live pf label with no persisted snapshot must still attempt the restore"
    );
}

#[skuld::test]
fn an_indeterminate_presence_reports_doing_nothing() {
    // Neither source could confirm anything either way — refuse loud rather
    // than silently claim success, and name the manual recovery command.
    for presence in [CoverPresence::Unreachable, CoverPresence::Indeterminate] {
        let mut ops = RecordingPfOps::default();
        let result = disengage_lockdown_with(presence, None, &mut ops);
        let err = result.expect_err(&format!("{presence:?} must not report success"));
        assert!(
            err.to_string().contains("pfctl -f /etc/pf.conf"),
            "must name the manual recovery command: {err}"
        );
        assert!(ops.log.is_empty(), "an unestablished presence must spawn no pfctl");
    }
}

#[skuld::test]
fn a_live_presence_with_a_captured_snapshot_restores_it_and_drops_the_token() {
    let mut ops = RecordingPfOps::default();
    let result = disengage_lockdown_with(CoverPresence::Live, Some(standing_state()), &mut ops);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(ops.log, vec!["load_ruleset", "drop_token", "clear_standing"]);
}

// pfctl_stdout (non-zero exit must not read as an empty success) ======================================================
//
// A failed `pfctl -sr`/`-sn` used to be read via `.stdout` with no status
// check, persisting an empty snapshot as the host's pre-lockdown policy
// (#901's bug class, surviving in this file). `pfctl_stdout` is the fix: the
// single place every status-bearing read goes through.

fn exit_output(code: i32, stdout: &str, stderr: &str) -> std::process::Output {
    use std::os::unix::process::ExitStatusExt;
    std::process::Output {
        status: std::process::ExitStatus::from_raw(if code == 0 { 0 } else { code << 8 }),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

#[skuld::test]
fn pfctl_stdout_returns_stdout_on_success() {
    let out = pfctl_stdout(Ok(exit_output(0, "block out all\n", "")), "pfctl -sr");
    assert_eq!(out.unwrap(), "block out all\n");
}

#[skuld::test]
fn pfctl_stdout_errs_on_nonzero_exit() {
    let err = pfctl_stdout(Ok(exit_output(1, "", "pfctl: permission denied\n")), "pfctl -sr").unwrap_err();
    let rendered = err.to_string();
    assert!(rendered.contains("pfctl -sr"), "got {rendered}");
    assert!(rendered.contains("permission denied"), "got {rendered}");
}

#[skuld::test]
fn pfctl_stdout_does_not_surface_stdout_text_from_a_failed_run() {
    // The regression this guards: a non-zero exit must never be read as if it
    // were a (possibly empty) successful snapshot.
    let out = pfctl_stdout(Ok(exit_output(1, "stale snapshot text", "")), "pfctl -sn");
    assert!(out.is_err(), "a failed pfctl run must not report Ok, got {out:?}");
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

// restore_confirmed ===================================================================================================

fn exit_status(code: i32) -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    std::process::ExitStatus::from_raw(code)
}

fn output_with_status(code: i32) -> Result<std::process::Output, RoutingError> {
    Ok(std::process::Output {
        status: exit_status(code),
        stdout: Vec::new(),
        stderr: Vec::new(),
    })
}

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_restore_confirmed_requires_a_successful_exit_status() {
    // adopting=true short-circuits to true regardless of `out` — nothing was
    // attempted, so nothing can have failed to confirm.
    assert!(restore_confirmed(true, &output_with_status(0)));
    assert!(restore_confirmed(true, &Err(RoutingError::RouteSetup("unused".into()))));

    // adopting=false: only a successful spawn AND a zero exit status confirms.
    assert!(restore_confirmed(false, &output_with_status(0)));
    assert!(
        !restore_confirmed(false, &output_with_status(1)),
        "a non-zero pfctl exit must NOT be mistaken for confirmation"
    );
    assert!(!restore_confirmed(
        false,
        &Err(RoutingError::RouteSetup("spawn failed".into()))
    ));
}

// release_all_with ====================================================================================================

/// `PfOps` test double: records every call (by method name) and returns a
/// per-method injectable result, so the sequencer's ordering, the
/// no-short-circuit property, and the clear-only-on-confirm rule are
/// table-tested without shelling out to `pfctl`.
#[derive(Default)]
struct RecordingPfOps {
    log: Vec<&'static str>,
    fail_reload_default: bool,
    fail_load_ruleset: bool,
    fail_clear_transient: bool,
    fail_clear_standing: bool,
}

impl PfOps for RecordingPfOps {
    fn reload_default(&mut self) -> Result<(), RoutingError> {
        self.log.push("reload_default");
        if self.fail_reload_default {
            Err(RoutingError::RouteSetup("mock reload_default failure".into()))
        } else {
            Ok(())
        }
    }

    fn load_ruleset(&mut self, _text: &str) -> Result<(), RoutingError> {
        self.log.push("load_ruleset");
        if self.fail_load_ruleset {
            Err(RoutingError::RouteSetup("mock load_ruleset failure".into()))
        } else {
            Ok(())
        }
    }

    fn drop_token(&mut self, _token: &str) -> Result<(), RoutingError> {
        self.log.push("drop_token");
        Ok(())
    }

    fn clear_transient(&mut self) -> Result<(), RoutingError> {
        self.log.push("clear_transient");
        if self.fail_clear_transient {
            Err(RoutingError::RouteSetup("mock clear_transient failure".into()))
        } else {
            Ok(())
        }
    }

    fn clear_standing(&mut self) -> Result<(), RoutingError> {
        self.log.push("clear_standing");
        if self.fail_clear_standing {
            Err(RoutingError::RouteSetup("mock clear_standing failure".into()))
        } else {
            Ok(())
        }
    }
}

fn transient_state() -> state::FailClosedState {
    state::FailClosedState {
        version: state::SCHEMA_VERSION,
        pf_token: "111".into(),
        pf_was_enabled: false,
    }
}

fn standing_state() -> lockdown_state::LockdownPfState {
    lockdown_state::LockdownPfState {
        version: lockdown_state::SCHEMA_VERSION,
        pf_token: "222".into(),
        main_snapshot: String::new(),
        nat_snapshot: String::new(),
        main_snapshot_captured: true,
    }
}

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_attempts_the_standing_cover_after_a_transient_failure() {
    // The short-circuit that would strand the standing cover — the cover that
    // blocks indefinitely — must not exist.
    let mut ops = RecordingPfOps {
        fail_reload_default: true,
        ..Default::default()
    };
    let result = release_all_with(
        StateFile::Present(transient_state()),
        StateFile::Present(standing_state()),
        &mut ops,
    );
    assert!(
        ops.log.contains(&"load_ruleset"),
        "the standing cover must still be attempted: {:?}",
        ops.log
    );
    assert!(result.is_err());
}

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_keeps_the_transient_state_file_when_the_restore_fails() {
    // Erasing the cover's only record here would make the NEXT call return Ok
    // over a still-blocked host — a permanent lockout.
    let mut ops = RecordingPfOps {
        fail_reload_default: true,
        ..Default::default()
    };
    let _ = release_all_with(StateFile::Present(transient_state()), StateFile::Absent, &mut ops);
    assert!(
        !ops.log.contains(&"clear_transient"),
        "must not clear the state file over an unconfirmed restore: {:?}",
        ops.log
    );
}

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_keeps_the_standing_state_file_when_restore_and_fallback_both_fail() {
    let mut ops = RecordingPfOps {
        fail_load_ruleset: true,
        fail_reload_default: true,
        ..Default::default()
    };
    let result = release_all_with(StateFile::Absent, StateFile::Present(standing_state()), &mut ops);
    assert!(
        !ops.log.contains(&"clear_standing"),
        "must not clear the state file when both the snapshot restore and the fallback failed: {:?}",
        ops.log
    );
    assert!(result.is_err());
}

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_falls_back_to_the_default_ruleset_when_the_snapshot_will_not_load() {
    let mut ops = RecordingPfOps {
        fail_load_ruleset: true,
        ..Default::default()
    };
    let result = release_all_with(StateFile::Absent, StateFile::Present(standing_state()), &mut ops);
    assert!(result.is_ok(), "a successful fallback is not an error: {result:?}");
    assert!(
        ops.log.contains(&"clear_standing"),
        "a confirmed fallback must still clear the state file: {:?}",
        ops.log
    );
}

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_treats_an_unusable_state_file_as_a_cover_to_clear() {
    // A corrupt or version-skewed file must never be read as "nothing to clear".
    let mut ops = RecordingPfOps::default();
    let _ = release_all_with(StateFile::Absent, StateFile::Unusable, &mut ops);
    assert!(
        ops.log.contains(&"reload_default"),
        "an Unusable standing state must still trigger the default-ruleset fallback: {:?}",
        ops.log
    );
}

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_touches_nothing_when_both_state_files_are_absent() {
    // A blanket /etc/pf.conf reload here would destroy a healthy host's live
    // third-party ruleset.
    let mut ops = RecordingPfOps::default();
    let result = release_all_with(StateFile::Absent, StateFile::Absent, &mut ops);
    assert!(ops.log.is_empty(), "must touch nothing on a clean host: {:?}", ops.log);
    assert!(result.is_ok());
}

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_treats_an_unusable_transient_state_file_as_a_cover_to_clear() {
    // The transient-side Unusable arm is separately coded (its own warn!
    // wording about a leaked pf enable refcount, and it unconditionally
    // reloads the default ruleset rather than trying a restore first) — the
    // standing-side counterpart above does not exercise it.
    let mut ops = RecordingPfOps::default();
    let result = release_all_with(StateFile::Unusable, StateFile::Absent, &mut ops);
    assert!(
        ops.log.contains(&"reload_default"),
        "an Unusable transient state must still trigger the default-ruleset reload: {:?}",
        ops.log
    );
    assert!(
        ops.log.contains(&"clear_transient"),
        "a confirmed reload must still clear the state file: {:?}",
        ops.log
    );
    assert!(result.is_ok());
}

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_clears_both_covers_end_to_end_on_a_clean_run() {
    // The most common real case release_all exists to handle — both covers
    // stranded, nothing fails — asserted at the sequencer level (not just the
    // slow, real-firewall privileged test), pinning the full call sequence.
    let mut ops = RecordingPfOps::default();
    let result = release_all_with(
        StateFile::Present(transient_state()),
        StateFile::Present(standing_state()),
        &mut ops,
    );
    assert!(result.is_ok(), "everything succeeded: {result:?}");
    assert_eq!(
        ops.log,
        vec![
            "reload_default",
            "drop_token",
            "clear_transient",
            "load_ruleset",
            "drop_token",
            "clear_standing",
        ],
        "the full transient-then-standing sequence must run in order: {:?}",
        ops.log
    );
}

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_logs_a_swallowed_transient_clear_failure_but_still_reports_ok() {
    // clear_transient/clear_standing are best-effort (contract item 5): a
    // failure there must not fail the call, but it also must not vanish
    // silently — every sibling caller of the same underlying clear
    // (`disengage`, `disengage_lockdown`) logs on failure.
    let mut ops = RecordingPfOps {
        fail_clear_transient: true,
        ..Default::default()
    };
    let result = release_all_with(StateFile::Present(transient_state()), StateFile::Absent, &mut ops);
    assert!(
        result.is_ok(),
        "a failed state-file clear must not fail the call: {result:?}"
    );
    assert!(
        ops.log.contains(&"clear_transient"),
        "the clear must still be attempted"
    );
}

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_logs_a_swallowed_standing_clear_failure_but_still_reports_ok() {
    let mut ops = RecordingPfOps {
        fail_clear_standing: true,
        ..Default::default()
    };
    let result = release_all_with(StateFile::Absent, StateFile::Present(standing_state()), &mut ops);
    assert!(
        result.is_ok(),
        "a failed state-file clear must not fail the call: {result:?}"
    );
    assert!(ops.log.contains(&"clear_standing"), "the clear must still be attempted");
}

// Cover presence ======================================================================================================

use crate::routing::CoverPresence;

#[skuld::test]
fn presence_fold_is_closed_over_the_probe_and_the_state_file() {
    // (pf label answer, state file, expected)
    let cases: [(Option<bool>, StateFile<lockdown_state::LockdownPfState>, CoverPresence); 9] = [
        (Some(true), StateFile::Absent, CoverPresence::Live),
        (Some(true), StateFile::Present(standing_state()), CoverPresence::Live),
        (Some(true), StateFile::Unusable, CoverPresence::Live),
        (Some(false), StateFile::Absent, CoverPresence::Absent),
        (
            Some(false),
            StateFile::Present(standing_state()),
            CoverPresence::Recorded,
        ),
        (Some(false), StateFile::Unusable, CoverPresence::Recorded),
        (None, StateFile::Absent, CoverPresence::Unreachable),
        (None, StateFile::Present(standing_state()), CoverPresence::Recorded),
        (None, StateFile::Unusable, CoverPresence::Recorded),
    ];
    for (label, file, expected) in cases {
        assert_eq!(
            fold_presence(label, &file),
            expected,
            "pf_label={label:?} file={file:?} must fold to {expected:?}"
        );
    }
}

#[skuld::test]
fn file_only_presence_never_reports_live() {
    // Pins the file-only body that ships before the pf probe lands: with no pf
    // answer the fold cannot reach `Live`, so it cannot trigger an intent
    // repair write off a state file alone.
    for file in [
        StateFile::Absent,
        StateFile::Present(standing_state()),
        StateFile::Unusable,
    ] {
        assert_ne!(
            fold_presence(None, &file),
            CoverPresence::Live,
            "a file-only answer must never claim the OS confirmed a cover"
        );
    }
}

// pf ruleset label ====================================================================================================

#[skuld::test]
fn lockdown_ruleset_labels_its_block_all_rule() {
    let r = build_lockdown_main_ruleset("utun4", v4(), "");
    let labelled: Vec<&str> = r.lines().filter(|l| l.contains("label")).collect();
    assert_eq!(
        labelled.len(),
        1,
        "exactly one rule may carry our label, got {labelled:?}"
    );
    let line = labelled[0];
    assert!(
        line.trim() == format!("block drop out quick all label \"{LOCKDOWN_PF_LABEL}\""),
        "the label must sit on the block-all base rule, got: {line}"
    );
    assert_eq!(
        r.lines().rfind(|l| !l.trim().is_empty()).map(str::trim),
        Some(line.trim()),
        "the labelled block-all must stay the LAST rule:\n{r}"
    );
}

#[skuld::test]
fn lockdown_restore_ruleset_never_carries_our_label() {
    // The restore reloads the HOST's captured rules. Our label appearing there
    // would make a restored host read back as a live Hole cover forever.
    let r = build_lockdown_restore_ruleset("nat-anchor \"com.apple/*\" all\n", "pass out all\n");
    assert!(
        !r.contains(LOCKDOWN_PF_LABEL),
        "the restore ruleset must not carry our label:\n{r}"
    );
}

#[skuld::test]
fn labels_listing_matcher_is_anchored_to_the_first_field() {
    assert!(labels_listing_carries_our_label(&format!(
        "{LOCKDOWN_PF_LABEL} 0 0 0 0 0 0 0 0\n"
    )));
    assert!(
        !labels_listing_carries_our_label(""),
        "an empty listing carries nothing"
    );
    assert!(
        !labels_listing_carries_our_label("com.apple.internet-sharing 0 0 0 0\n"),
        "another rule's label is not ours"
    );
    assert!(
        !labels_listing_carries_our_label(&format!("{LOCKDOWN_PF_LABEL}-staging 0 0 0 0\n")),
        "a label that merely CONTAINS ours is not ours"
    );
    assert!(
        !labels_listing_carries_our_label(&format!("someone-else {LOCKDOWN_PF_LABEL} 0 0\n")),
        "the label is the FIRST field; a counter column that happens to match is not it"
    );
}

#[skuld::test]
fn pf_label_answer_maps_a_failed_pfctl_to_none() {
    // The wiring a fold table cannot reach: mapping a spawn failure or a
    // non-success exit to `Some(false)` would collapse the two-source design to
    // file-only and let a live cover read as absent.
    assert_eq!(
        pf_label_answer(Err(RoutingError::RouteSetup("pfctl spawn failed".into()))),
        None
    );
    assert_eq!(pf_label_answer(output_with_status(1)), None, "a non-success exit");

    let mut ok = output_with_status(0).unwrap();
    ok.stdout = format!("{LOCKDOWN_PF_LABEL} 0 0 0 0\n").into_bytes();
    assert_eq!(pf_label_answer(Ok(ok)), Some(true));

    let mut clean = output_with_status(0).unwrap();
    clean.stdout = b"com.apple.something 0 0\n".to_vec();
    assert_eq!(pf_label_answer(Ok(clean)), Some(false));
}

// Self-capture guard ==================================================================================================

#[skuld::test]
fn self_capture_persists_no_baseline_but_keeps_the_nat_rules() {
    // Presence Live at capture time means the ruleset `pfctl -sr` would return
    // is OUR OWN cover, so there is no host baseline to record. The NAT rules
    // are a different matter: they are the host's own translation rules, fed
    // verbatim into the ruleset engage loads, so zeroing them would flush a
    // live host NAT (Internet Sharing, a VM bridge) the moment the cover
    // engages, with nothing on disk to restore it from.
    let tmp = tempfile::tempdir().unwrap();
    let nat = "nat on en0 from any to any -> (en0)\n";
    let returned = persist_baseline(
        "tok",
        tmp.path(),
        None,
        CoverPresence::Live,
        "block drop out quick all label \"hole-lockdown\"\n".into(),
        nat.into(),
    )
    .expect("the persist must succeed");

    assert_eq!(
        returned, nat,
        "the nat snapshot must reach the ruleset builder unchanged"
    );
    let st = lockdown_state::load(tmp.path()).expect("state must be persisted");
    assert!(!st.main_snapshot_captured, "no host baseline was captured");
    assert!(st.main_snapshot.is_empty(), "our own ruleset must not be recorded");
    assert_eq!(st.nat_snapshot, nat, "the host NAT rules must be persisted verbatim");
}

#[skuld::test]
fn a_measured_clean_host_captures_its_baseline() {
    let tmp = tempfile::tempdir().unwrap();
    let main = "scrub-anchor \"com.apple/*\" all fragment reassemble\n";
    let nat = "nat-anchor \"com.apple/*\" all\n";
    persist_baseline("tok", tmp.path(), None, CoverPresence::Absent, main.into(), nat.into()).unwrap();

    let st = lockdown_state::load(tmp.path()).unwrap();
    assert!(st.main_snapshot_captured);
    assert_eq!(st.main_snapshot, main);
    assert_eq!(st.nat_snapshot, nat);
}

#[skuld::test]
fn an_uncaptured_baseline_restores_the_default_ruleset() {
    let mut st = standing_state();
    st.main_snapshot_captured = false;
    st.main_snapshot = String::new();
    let mut ops = RecordingPfOps::default();
    release_all_with(StateFile::Absent, StateFile::Present(st), &mut ops).unwrap();

    assert!(
        ops.log.contains(&"reload_default"),
        "with no captured baseline, /etc/pf.conf IS the restore target: {:?}",
        ops.log
    );
    assert!(
        !ops.log.contains(&"load_ruleset"),
        "an empty snapshot must never be loaded as a ruleset — that is a pass-all host: {:?}",
        ops.log
    );
    assert!(ops.log.contains(&"clear_standing"));
}

#[skuld::test]
fn an_empty_but_captured_baseline_still_restores_the_snapshot() {
    // The discriminating case for the bool sentinel: a host really can have an
    // empty filter ruleset, and that IS its policy. Keying on `main_snapshot
    // .is_empty()` instead of the flag would silently reload /etc/pf.conf over it.
    let mut st = standing_state();
    st.main_snapshot = String::new();
    assert!(st.main_snapshot_captured, "sample state is a captured baseline");
    let mut ops = RecordingPfOps::default();
    release_all_with(StateFile::Absent, StateFile::Present(st), &mut ops).unwrap();

    assert!(
        ops.log.contains(&"load_ruleset"),
        "a captured baseline is restored from the snapshot even when empty: {:?}",
        ops.log
    );
}

// cover transition (bindreams/hole#997) ===============================================================================

/// Proves a transient-cover TRANSITION — a second real `engage()` replacing a
/// still-live cover, with no intervening `disengage` — never admits a flow the
/// OLD cover was blocking. This is the scenario `-Fa` broke: `pfctl -Fa -f -`
/// is two separate kernel transactions (flush, then load), so a host between
/// them briefly runs with no pf rules at all — a pass-all window between two
/// rulesets that both block `NON_PERMITTED`. Dropping `-Fa` makes the load a
/// single `pfctl -f -`, one atomic pf transaction under the kernel's
/// DIOCADDRULE/DIOCXCOMMIT ticket discipline (see `crates/tun-engine/src/
/// routing/failclosed/macos.rs`'s module doc), so no such window should exist.
///
/// The prober pool below starts before the loop's very first `engage()`, so
/// this test also exercises a COLD engage (pf disabled at entry — the
/// `global_net_state` test group runs each privileged test in its own
/// process, but pf's enable bit is host-global kernel state that outlives any
/// one process, and an earlier test's normal `disengage` can leave it off).
/// `pfctl -E` (enable) and `pfctl -f -` (load) are always two separate
/// `pfctl` invocations, so enabling before loading opens the same shape of
/// pass-all-window bug as `-Fa` did, just triggered by cold-start ordering
/// instead: pf would start filtering with whatever ruleset already happened
/// to be loaded, before the intended one committed. `engage`/`engage_lockdown`
/// close this by loading before enabling specifically when pf starts
/// disabled (loading is a documented no-op while pf is off), so this test's
/// iteration 0 covers that path and every later iteration covers the warm
/// transition path.
///
/// Lives here (not `lockdown_privileged_tests.rs`) because it must retire an
/// intermediate cover's pf enable refcount WITHOUT running its normal
/// `Drop`/`disengage` — that disengage reloads `/etc/pf.conf`, which is
/// exactly the open-host state this test must never let onto the wire — and
/// doing that needs `Cover`'s private `token` field plus the private `pfctl`
/// helper, both visible only inside `platform`'s own module tree.
///
/// EVIDENTIARY SCOPE (the #997 caveat): pf has no programmatic API and no
/// published kernel source this repo can read, so "a single `pfctl -f -` is
/// one atomic transaction" is an inference from `pfctl`'s documented ticket
/// behaviour, not a fact read out of the kernel. This test does not prove
/// that inference — it runs 25 real transitions against a pool of concurrent
/// background probers spanning the whole loop, so IF the inference were wrong
/// (an `-Fa`-shaped gap still existed, or reappeared some other way), the
/// prober pool has many overlapping, independent real chances to catch a SYN
/// that got out during an open window and would very likely observe at least
/// one. A pass here is strong empirical evidence of atomicity across real
/// transitions on this kernel, not a mathematical proof — a race narrower
/// than the prober pool's combined polling resolution could in principle
/// still slip through undetected. The pool (not a single serial prober) is
/// load-bearing here: pf's `block-policy drop` (silent drop, no RST) means a
/// blocked connect blocks for its *entire* timeout before the same thread can
/// probe again, so one thread alone could be parked inside a single blocked
/// `connect_timeout` call for the whole duration of a given `engage()` (a few
/// subprocess `pfctl` calls, plausibly a handful of milliseconds) and never
/// overlap that transition at all. `PROBER_THREADS` concurrent, short-timeout
/// probers keep the number of in-flight SYNs high at every instant instead of
/// only between a single thread's timeouts.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN_LABEL, GLOBAL_NET_STATE], serial = TUN_LABEL)]
fn macos_failclosed_cover_transition_never_admits_blocked_flow() {
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    // Two real, reachable hosts on the same reliable anycast network the
    // neighbouring privileged tests use (see `lockdown_privileged_tests.rs`'s
    // `PERMITTED`/`RESOLVER` doc for why real routable IPs, not loopback, are
    // required here). Alternating the permitted server between them forces
    // every `engage()` in the loop to load a ruleset whose TEXT actually
    // differs from the one it replaces. `NON_PERMITTED` is blocked by EVERY
    // ruleset in the loop, so any successful connect to it during the loop is
    // a leak, full stop — it can never be explained by which server happens
    // to be permitted at that moment.
    const SERVER_A: &str = "1.1.1.1";
    const SERVER_B: &str = "1.0.0.1";
    const NON_PERMITTED: &str = "8.8.8.8:443";
    const ITERATIONS: usize = 25;
    // See the doc comment above: `block-policy drop` parks a single prober
    // thread inside one blocked `connect_timeout` call for the whole timeout,
    // so a lone prober could miss an entire fast transition. A pool of short-
    // timeout probers keeps several SYNs in flight at every instant instead.
    const PROBER_THREADS: usize = 16;
    const PROBER_TIMEOUT: Duration = Duration::from_millis(20);

    // External-event probe with a graceful failure bound: the timeout is the
    // failure-to-human signal for a remote host that might not respond, not a
    // sync sleep or a poll on state this test controls.
    let connect = |addr: &str, timeout: Duration| TcpStream::connect_timeout(&addr.parse().unwrap(), timeout);

    let baseline = connect(NON_PERMITTED, Duration::from_secs(5));
    assert!(
        baseline.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): pre-cover baseline egress must reach \
         {NON_PERMITTED}: {:?}",
        baseline.err().map(|e| e.kind()),
    );

    let leaked = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));

    // Continuous prober POOL spanning the WHOLE transition loop below, each on
    // its own thread with a short timeout, so many SYNs are in flight at every
    // instant and the pool overlaps every one of the loop's real `pfctl` calls
    // rather than only sampling between iterations (see the doc comment above
    // for why a single serial prober is not enough under `block-policy drop`).
    let probers: Vec<_> = (0..PROBER_THREADS)
        .map(|_| {
            let (leaked_prober, stop_prober) = (leaked.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut attempts = 0usize;
                while !stop_prober.load(Ordering::SeqCst) {
                    attempts += 1;
                    if connect(NON_PERMITTED, PROBER_TIMEOUT).is_ok() {
                        leaked_prober.store(true, Ordering::SeqCst);
                    }
                }
                attempts
            })
        })
        .collect();

    // One `state_dir` for the whole loop: each engage's persist-before-mutate
    // save overwrites the previous cover's state file with its own token
    // before loading its ruleset, exactly as a real re-engage-without-
    // disengage would.
    let dir = tempfile::tempdir().unwrap();
    let addrs = [SERVER_A, SERVER_B];
    let mut held: Option<Cover> = None;
    for i in 0..ITERATIONS {
        let server_ip: IpAddr = addrs[i % addrs.len()].parse().unwrap();
        let new_cover = engage(server_ip, None, dir.path(), None).expect("engage real pf transient cover");
        if let Some(old) = held.take() {
            // Retire the OLD cover's pf enable refcount only — never its
            // normal Drop, which would reload /etc/pf.conf (a pass-all host)
            // over the ruleset the NEW cover (already engaged above) just
            // loaded. The refcount stays balanced: this engage's own `-E`
            // already ran, so this `-X` brings it back down by exactly one.
            let _ = pfctl(&["-X", &old.token], None, BestEffortPhase::RecoverCover);
            std::mem::forget(old);
        }
        held = Some(new_cover);
    }

    stop.store(true, Ordering::SeqCst);
    let attempts: usize = probers
        .into_iter()
        .map(|p| p.join().expect("prober thread panicked"))
        .sum();
    assert!(
        attempts > 0,
        "prober pool made no attempts at all — this test is vacuous"
    );

    assert!(
        !leaked.load(Ordering::SeqCst),
        "a cover engage (cold at iteration 0, a transition replacing a still-live cover at every \
         later iteration) admitted a connection to {NON_PERMITTED}, which every ruleset in the \
         {ITERATIONS}-iteration loop blocks — pfctl's enable/load are not behaving as one atomic \
         transaction"
    );

    // The last cover's normal Drop restores /etc/pf.conf.
    drop(held.take());
    let restored = connect(NON_PERMITTED, Duration::from_secs(5));
    assert!(
        restored.is_ok(),
        "final disengage must restore egress: {NON_PERMITTED}={:?}",
        restored.err().map(|e| e.kind()),
    );
}
