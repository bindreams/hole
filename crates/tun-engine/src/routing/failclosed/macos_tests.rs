use super::*;
use std::net::IpAddr;

use crate::{GLOBAL_NET_STATE, TUN};

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
fn pfctl_cmd_uses_the_absolute_path() {
    // Pins the hardening PFCTL's doc claims: reverting to a bare "pfctl"
    // (PATH-resolved, spoofable by an earlier writable directory since this
    // runs as root) must fail this test, not silently stay green.
    let cmd = pfctl_cmd(&["-X", "12345"]);
    assert_eq!(
        cmd[0], "/sbin/pfctl",
        "pfctl must be invoked by its absolute path: {cmd:?}"
    );
    assert_eq!(
        cmd[1..],
        ["-X", "12345"],
        "pfctl_cmd must forward args unchanged after the binary: {cmd:?}"
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

/// The interface-name fixture. Named `TUN_IF`, not `TUN`: `TUN` is the crate's
/// skuld label, and `#[skuld::test(serial = ...)]` takes a bare `Ident` that it
/// stringifies rather than resolves, so shadowing or aliasing that name yields a
/// serial filter matching nothing — silently unserialized, not a compile error.
const TUN_IF: &str = "hole-tun";

fn lockdown(ip: IpAddr, nat: &str) -> String {
    build_lockdown_main_ruleset(TUN_IF, ip, nat)
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

// engage_with =========================================================================================================

/// [`EngageOps`] test double: records every call by method name and returns a
/// per-method injectable result, so an engage's ordering, its state purge and
/// its unwind on a failed persist are asserted without shelling out to
/// `pfctl`. `token` is what `enable_capture_token` hands back, so the unwind
/// assertions can check the refcount that was dropped is the one that was
/// taken.
#[derive(Default)]
struct RecordingEngageOps {
    log: Vec<&'static str>,
    pf_enabled: bool,
    token: String,
    dropped: Vec<String>,
    restored: Vec<String>,
    fail_pf_enabled: bool,
    fail_enable_capture_token: bool,
    fail_save_transient: bool,
    fail_load_ruleset: bool,
    fail_flush_states: bool,
    fail_drop_token: bool,
}

impl CoverRulesetOps for RecordingEngageOps {
    fn load_ruleset(&mut self, _text: &str) -> Result<(), RoutingError> {
        self.log.push("load_ruleset");
        if self.fail_load_ruleset {
            Err(RoutingError::RouteSetup("mock load_ruleset failure".into()))
        } else {
            Ok(())
        }
    }

    fn flush_states(&mut self) -> Result<(), RoutingError> {
        self.log.push("flush_states");
        if self.fail_flush_states {
            Err(RoutingError::RouteSetup("mock flush_states failure".into()))
        } else {
            Ok(())
        }
    }
}

impl EngageOps for RecordingEngageOps {
    fn pf_enabled(&mut self) -> Result<bool, RoutingError> {
        self.log.push("pf_enabled");
        if self.fail_pf_enabled {
            Err(RoutingError::RouteSetup("mock pf_enabled failure".into()))
        } else {
            Ok(self.pf_enabled)
        }
    }

    fn enable_capture_token(&mut self) -> Result<String, RoutingError> {
        self.log.push("enable_capture_token");
        if self.fail_enable_capture_token {
            Err(RoutingError::RouteSetup("mock enable_capture_token failure".into()))
        } else {
            Ok(self.token.clone())
        }
    }

    fn save_transient(&mut self, _st: &state::FailClosedState) -> Result<(), RoutingError> {
        self.log.push("save_transient");
        if self.fail_save_transient {
            Err(RoutingError::RouteSetup("mock save_transient failure".into()))
        } else {
            Ok(())
        }
    }

    fn drop_token(&mut self, token: &str) -> Result<(), RoutingError> {
        self.log.push("drop_token");
        self.dropped.push(token.to_owned());
        if self.fail_drop_token {
            Err(RoutingError::RouteSetup("mock drop_token failure".into()))
        } else {
            Ok(())
        }
    }

    fn transient_restore(&mut self, token: &str) {
        self.log.push("transient_restore");
        self.restored.push(token.to_owned());
    }
}

fn recording_engage_ops() -> RecordingEngageOps {
    RecordingEngageOps {
        token: "424242".into(),
        ..Default::default()
    }
}

#[skuld::test]
fn the_state_purge_is_decided_per_cover_kind() {
    // The transient cover engages in `hold_pending`, BEFORE `start_inner`, so a
    // host-wide flush has no tunnel of ours to kill. `engage_lockdown` runs with
    // the tunnel live and `DIOCCLRSTATES` is host-wide, so it must not purge
    // until a targeted kill is reachable (bindreams/hole#1015 / #1002).
    assert!(
        purges_state(CoverKind::Transient),
        "the transient cover must purge pf state: pf matches state before rules, so a flow \
         established before it engages otherwise keeps flowing past `block out all`"
    );
    assert!(
        !purges_state(CoverKind::Lockdown),
        "the standing lockdown must NOT purge pf state: the flush is host-wide and the tunnel \
         it protects is already live"
    );
}

#[skuld::test]
fn a_transient_engage_purges_pf_state_after_loading_its_ruleset() {
    // Order is the assertion, not just presence. Purging BEFORE the load leaves
    // a window where state is gone but the permissive ruleset being replaced is
    // still live, so packets simply re-create their state under it.
    let mut ops = recording_engage_ops();
    let token = engage_with(v4(), None, &mut ops).expect("engage_with");

    assert_eq!(token, "424242");
    assert_eq!(
        ops.log,
        vec![
            "pf_enabled",
            "enable_capture_token",
            "save_transient",
            "load_ruleset",
            "flush_states",
        ],
        "the transient engage must read, enable, persist, load, THEN purge: {:?}",
        ops.log
    );
}

#[skuld::test]
fn a_lockdown_engage_loads_its_ruleset_without_purging_pf_state() {
    // The negative half of the same rule, on the code both engages share.
    let mut ops = recording_engage_ops();
    load_cover_ruleset(CoverKind::Lockdown, "block drop out quick all\n", &mut ops).expect("load");
    assert_eq!(
        ops.log,
        vec!["load_ruleset"],
        "the standing lockdown must load and stop — a host-wide purge there kills the live \
         tunnel (bindreams/hole#1015, deferred to #1002): {:?}",
        ops.log
    );
}

#[skuld::test]
fn a_failed_ruleset_load_never_purges_pf_state() {
    // A failed load never committed, so there is no new policy for a purge to
    // enforce — and the engage is about to reload /etc/pf.conf, under which the
    // flows a purge would have killed are permitted anyway.
    let mut ops = RecordingEngageOps {
        fail_load_ruleset: true,
        ..recording_engage_ops()
    };
    let err = engage_with(v4(), None, &mut ops).expect_err("a failed load must fail the engage");
    assert!(err.to_string().contains("load_ruleset"), "{err}");
    assert!(
        !ops.log.contains(&"flush_states"),
        "a load that never committed must not be followed by a purge: {:?}",
        ops.log
    );
    assert_eq!(
        ops.restored,
        vec!["424242".to_string()],
        "the failed engage must still restore the host"
    );
}

#[skuld::test]
fn a_failed_state_purge_does_not_fail_the_engage() {
    // The cover is already live and blocking. Failing here would unwind to a
    // fully open host — strictly worse than the #1015 residue the failed purge
    // leaves behind.
    let mut ops = RecordingEngageOps {
        fail_flush_states: true,
        ..recording_engage_ops()
    };
    let result = engage_with(v4(), None, &mut ops);
    assert!(
        result.is_ok(),
        "a failed purge must not unwind a live, blocking cover into an open host: {result:?}"
    );
    assert!(ops.restored.is_empty(), "nothing to restore: {:?}", ops.restored);
}

#[skuld::test]
fn a_failed_persist_unwinds_the_pf_enable_refcount() {
    // `enable_capture_token` has already taken a refcount. `state::save` fails
    // on a real, enumerated set of causes — unwritable state dir, full disk,
    // failed chown — and without this unwind pf stays ENABLED under an
    // unreferenced token until reboot, with no `bridge-failclosed.json` for
    // `recover_cover` to return it from. `engage_lockdown`'s FreshEnable and
    // Reenable arms already unwind on exactly this failure; this is the
    // transient path's half of that symmetry.
    let mut ops = RecordingEngageOps {
        fail_save_transient: true,
        ..recording_engage_ops()
    };
    let err = engage_with(v4(), None, &mut ops).expect_err("a failed persist must fail the engage");
    assert!(err.to_string().contains("save_transient"), "{err}");
    assert_eq!(
        ops.dropped,
        vec!["424242".to_string()],
        "the refcount taken by `pfctl -E` must be dropped again: {:?}",
        ops.log
    );
    assert!(
        !ops.log.contains(&"load_ruleset"),
        "persist-before-mutate: nothing may load once the persist failed: {:?}",
        ops.log
    );
}

#[skuld::test]
fn a_failed_unwind_of_a_failed_persist_still_returns_the_original_error_and_logs() {
    // The unwind-of-an-unwind branch: `save_transient` fails, and the
    // `drop_token` call that should undo the `-E` refcount ALSO fails. The
    // refcount now genuinely leaks with no state file to recover it from
    // (see `engage_with`'s doc) — that must be logged, not silently dropped —
    // and the caller must still see the ORIGINAL failure (`save_transient`'s),
    // not the unwind's, since that is the actionable one.
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let writer = garter::test_utils::WaitableWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    let err = {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        let mut ops = RecordingEngageOps {
            fail_save_transient: true,
            fail_drop_token: true,
            ..recording_engage_ops()
        };
        engage_with(v4(), None, &mut ops).expect_err("a failed persist must fail the engage")
    };
    assert!(
        err.to_string().contains("save_transient"),
        "the ORIGINAL failure must be returned, not the unwind's: {err}"
    );
    let log = writer.snapshot();
    assert!(
        log.contains("pfctl -X failed unwinding a failed transient engage"),
        "the failed unwind must be logged, not silently dropped: {log}"
    );
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
/// TWO DIFFERENT ASSERTIONS, and the difference is structural. Do NOT unify
/// them — the strict one is deliberately not applied to the cold engage, and
/// widening it there does not make this test stricter, it makes it
/// unconditionally red:
///
/// - **Cold engage** (the first one, over a host carrying no cover at all —
///   pf's enable bit is host-global kernel state that outlives the
///   per-test process, so an earlier test's normal `disengage` leaves this
///   the state nearly every real CI run starts in). Asserted on its
///   POST-CONDITION only: once `engage()` has RETURNED, `NON_PERMITTED` must
///   be unreachable. Nothing is asserted about the window before or during
///   that call, because there is no property to assert there — an uncovered
///   host is *supposed* to be open, and this test's own `baseline` below
///   REQUIRES it to be open before anything starts. A prober spanning that
///   window observes exactly the open host the baseline demanded and reports
///   a "leak" on every run: the instrumented CI run that produced this split
///   latched `leaked_at_phase=0` (the cold engage). It cannot support "all 24
///   transitions passed clean" — `leaked_at_phase` is a `compare_exchange`
///   from `usize::MAX`, so once phase 0 latched, a leak in any later
///   transition was invisible to it. Mechanically the window cannot be closed
///   either, in any ordering: `pfctl -E` (enable) and `pfctl -f -` (load) are
///   separate process invocations, and while pf is disabled nothing is
///   filtered regardless of what is loaded.
/// - **Every transition** (each later `engage()`, replacing a still-live
///   cover). Asserted STRICTLY: the prober pool runs continuously across all
///   of them and not one probe may succeed. This is the actual #997 property.
///   The pool starts only after the cold engage's post-condition has been
///   verified, so from the instant the first prober SYN goes out the host is
///   KNOWN blocked and any success at all is a leak — no phase filtering, no
///   carve-outs.
///
/// The cold post-condition is not a formality: the failure mode it catches is
/// the INERT cover — `engage` returning Ok with the ruleset loaded but pf never
/// actually enabled, reported armed while egress runs in the clear. A load that
/// outright fails already surfaces as an Err from `engage`; only a settled
/// connect catches the silent half.
///
/// Lives here (not `lockdown_privileged_tests.rs`) because it must retire an
/// intermediate cover's pf enable refcount WITHOUT running its normal
/// `Drop`/`disengage` — that disengage reloads `/etc/pf.conf`, which is
/// exactly the open-host state this test must never let onto the wire — and
/// doing that needs `Cover`'s private `token` field plus the private `pfctl`
/// helper, both visible only inside `platform`'s own module tree.
///
/// EVIDENTIARY SCOPE (the #997 caveat, module doc has the ticket-discipline
/// argument in full): a pass here is strong empirical evidence, not a
/// mathematical proof, of atomicity across `TRANSITIONS` real transitions —
/// `PROBER_THREADS` concurrent short-timeout probers give an `-Fa`-shaped
/// regression many overlapping, independent chances to be caught. The pool
/// (not a single serial prober) is load-bearing specifically because
/// `block-policy drop` silently blocks a connect for its *entire* timeout, so
/// one thread alone could be parked inside a single blocked `connect_timeout`
/// call for a whole transition and never overlap it at all.
///
/// SENSITIVITY IS PRINTED, NOT ASSUMED — every real failure this guard has
/// caught was the cold `-E`→load window (tens of ms), which is orders of
/// magnitude wider than the sub-millisecond `-Fa` window it exists for, so a
/// green here is not a bound on the narrowest window that would still be
/// caught. The run therefore prints its own numbers (the control's
/// completed-connect ratio and the pool's aggregate probe rate) rather than
/// leaving a green uninformative; `.config/nextest.toml` gives this test
/// `success-output` so that line survives a PASS. See the printed line itself
/// for what it means and its own caveats — this comment does not restate them.
///
/// A MEASURED number, not a hypothetical one — AWAITING RE-MEASUREMENT. The
/// darwin/amd64 CI run (2026-09-10, job 102969439298) previously cited here
/// reported 7/31 (22.6%), but that denominator counted every alternating
/// control attempt, not just the ones targeting the currently-permitted
/// server — roughly half of the 31 targeted the server the loop was actively
/// blocking at that moment and, under `block-policy drop`, could never
/// complete regardless of budget health. Fixed above
/// (`control_permitted_attempts` excludes the blocked-target arm), which
/// retires the 22.6%/"under a quarter" figure as an artefact of the old
/// miscount rather than a fact about this guard's power. A corrected figure
/// needs a fresh privileged darwin run against the fixed counter; record it
/// here (and in `CONTRIBUTING.md`) once one is available.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_failclosed_cover_transition_never_admits_blocked_flow() {
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    // Two real, reachable hosts on the same reliable anycast network the
    // neighbouring privileged tests use (see `lockdown_privileged_tests.rs`'s
    // `PERMITTED`/`RESOLVER` doc for why real routable IPs, not loopback, are
    // required here). Alternating the permitted server between them forces
    // every `engage()` here to load a ruleset whose TEXT actually differs from
    // the one it replaces. `NON_PERMITTED` is blocked by EVERY ruleset in the
    // run, so any successful connect to it while a cover is live is a leak,
    // full stop — it can never be explained by which server happens to be
    // permitted at that moment.
    const SERVER_A: &str = "1.1.1.1";
    const SERVER_B: &str = "1.0.0.1";
    const NON_PERMITTED: &str = "8.8.8.8:443";
    // Transitions after the cold engage, so `TRANSITIONS + 1` real `engage()`
    // calls in total.
    const TRANSITIONS: usize = 24;
    // See the doc comment above: `block-policy drop` parks a single prober
    // thread inside one blocked `connect_timeout` call for the whole timeout,
    // so a lone prober could miss an entire fast transition. A pool of short-
    // timeout probers keeps several SYNs in flight at every instant instead.
    const PROBER_THREADS: usize = 16;
    const PROBER_TIMEOUT: Duration = Duration::from_millis(20);
    // The bound for the three one-shot verdicts that must be SETTLED rather
    // than sampled (reachable baseline, cold-engage post-condition, restored
    // egress). The same value both ways round on purpose: "blocked" means the
    // host stayed silent for the very bound it cleared when open. It is the
    // 5s the neighbouring privileged cover tests already use.
    const SETTLED_TIMEOUT: Duration = Duration::from_secs(5);

    // External-event probe with a graceful failure bound: the timeout is the
    // failure-to-human signal for a remote host that might not respond, not a
    // sync sleep or a poll on state this test controls.
    let connect = |addr: &str, timeout: Duration| TcpStream::connect_timeout(&addr.parse().unwrap(), timeout);

    let baseline = connect(NON_PERMITTED, SETTLED_TIMEOUT);
    assert!(
        baseline.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): pre-cover baseline egress must reach \
         {NON_PERMITTED}: {:?}",
        baseline.err().map(|e| e.kind()),
    );

    // One `state_dir` for the whole run: each engage's persist-before-mutate
    // save overwrites the previous cover's state file with its own token
    // before loading its ruleset, exactly as a real re-engage-without-
    // disengage would.
    let dir = tempfile::tempdir().unwrap();
    let addrs = [SERVER_A, SERVER_B];

    // COLD engage — its POST-CONDITION is the whole of its assertion (doc
    // comment above: the pre/mid-engage window is the open host `baseline`
    // just required, so there is nothing there to assert). Settling that
    // post-condition here is also what licenses the strict rule for everything
    // after it: the host is KNOWN blocked from this point on, so the prober
    // pool spawned below needs no phase carve-out.
    let mut held: Option<Cover> =
        Some(engage(addrs[0].parse().unwrap(), None, dir.path(), None).expect("cold engage real pf transient cover"));
    let cold = connect(NON_PERMITTED, SETTLED_TIMEOUT);
    assert!(
        cold.is_err(),
        "a cold engage that returned Ok must already block {NON_PERMITTED} — the cover is INERT: \
         reported armed while egress runs in the clear (pf never enabled, or enabled under a \
         ruleset that is not ours)",
    );

    let leaked = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));

    // `phase` names which transition is in flight at any instant (0 = the cold
    // cover is live and steady, no transition started yet), and
    // `leaked_at_phase` latches the phase of the FIRST leak, so a failure says
    // WHICH engage admitted the flow instead of only THAT one did. Every value
    // it can report is a real leak — the cold engage's own window is not
    // probed at all.
    let phase = Arc::new(AtomicUsize::new(0));
    let leaked_at_phase = Arc::new(AtomicUsize::new(usize::MAX));

    // Continuous prober POOL spanning the WHOLE transition loop below, each on
    // its own thread with a short timeout, so many SYNs are in flight at every
    // instant and the pool overlaps every one of the loop's real `pfctl` calls
    // rather than only sampling between iterations (see the doc comment above
    // for why a single serial prober is not enough under `block-policy drop`).
    let probers: Vec<_> = (0..PROBER_THREADS)
        .map(|_| {
            let (leaked_prober, stop_prober, phase_prober, leaked_at_phase_prober) =
                (leaked.clone(), stop.clone(), phase.clone(), leaked_at_phase.clone());
            std::thread::spawn(move || {
                let mut attempts = 0usize;
                while !stop_prober.load(Ordering::SeqCst) {
                    attempts += 1;
                    if connect(NON_PERMITTED, PROBER_TIMEOUT).is_ok() {
                        leaked_prober.store(true, Ordering::SeqCst);
                        let _ = leaked_at_phase_prober.compare_exchange(
                            usize::MAX,
                            phase_prober.load(Ordering::SeqCst),
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        );
                    }
                }
                attempts
            })
        })
        .collect();

    // POSITIVE CONTROL for `PROBER_TIMEOUT`. The strict assertion below is "no
    // prober ever connected" — which is equally what a timeout too short to
    // complete ANY handshake on this runner would produce, silently. One extra
    // thread probes, at the same timeout over the same run, the servers the
    // covers PERMIT: a single success anywhere proves the budget is live, so
    // the silence next door is the cover's doing and not the clock's. It
    // alternates its two targets instead of reading `phase` to pick WHERE to
    // connect, so it needs no synchronization with the loop to decide that.
    //
    // But `phase` IS read for what gets COUNTED: at any instant the transition
    // loop permits exactly one of the two addresses (`addrs[i % addrs.len()]`)
    // and `set block-policy drop` means a connect to the OTHER one silently
    // burns the entire `PROBER_TIMEOUT` rather than completing — so on
    // alternation alone, roughly half of every attempt targets the currently-
    // blocked server and can never land. Counting those in the denominator
    // caps the printed rate at ~50% regardless of how healthy the runner is.
    // Each attempt still fires exactly as before (the alternation itself is
    // unchanged — only the arm matching the currently-permitted address, read
    // off `phase`, is added to `control_permitted_attempts`/`control_hits`).
    //
    // It also RETURNS its total attempt count (both arms), so the pass can
    // report `hits/permitted_attempts` — that ratio is this guard's stated
    // sensitivity — alongside how many of the run's attempts targeted the
    // permitted server at all.
    let control_hits = Arc::new(AtomicUsize::new(0));
    let control_permitted_attempts = Arc::new(AtomicUsize::new(0));
    let control = {
        let (control_hits, control_permitted_attempts, stop_control, phase_control) = (
            control_hits.clone(),
            control_permitted_attempts.clone(),
            stop.clone(),
            phase.clone(),
        );
        std::thread::spawn(move || {
            let mut attempts = 0usize;
            while !stop_control.load(Ordering::SeqCst) {
                let target_idx = attempts % 2;
                let target = format!("{}:443", [SERVER_A, SERVER_B][target_idx]);
                attempts += 1;
                let ok = connect(&target, PROBER_TIMEOUT).is_ok();
                // addrs[phase % addrs.len()] is the transition loop's own rule
                // for which address is currently permitted (see the loop
                // below); only an attempt against that address belongs in the
                // sensitivity denominator.
                if target_idx == phase_control.load(Ordering::SeqCst) % 2 {
                    control_permitted_attempts.fetch_add(1, Ordering::SeqCst);
                    if ok {
                        control_hits.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
            attempts
        })
    };

    // Wall clock spanning exactly the window the pool covers, so the printed
    // probe rate is probes-per-second of the run the assertions are about.
    let pool_started = std::time::Instant::now();

    // Counts (not just logs) a failed `-X` retiring the OLD cover's refcount
    // below — production code in this module never swallows a `pfctl` result
    // without at least logging it, and a refcount that fails to drop here is
    // a real leak, not a benign no-op.
    let mut old_x_failures = 0usize;

    for i in 1..=TRANSITIONS {
        phase.store(i, Ordering::SeqCst);
        let server_ip: IpAddr = addrs[i % addrs.len()].parse().unwrap();
        let new_cover = engage(server_ip, None, dir.path(), None).expect("engage real pf transient cover");
        if let Some(old) = held.take() {
            // Retire the OLD cover's pf enable refcount only — never its
            // normal Drop, which would reload /etc/pf.conf (a pass-all host)
            // over the ruleset the NEW cover (already engaged above) just
            // loaded. The refcount stays balanced: this engage's own `-E`
            // already ran, so this `-X` brings it back down by exactly one.
            if let Err(e) = pfctl_status(
                pfctl(&["-X", &old.token], None, BestEffortPhase::RecoverCover),
                "pfctl -X",
            ) {
                tracing::warn!(error = %e, iteration = i, "pfctl -X failed retiring the old cover's refcount mid-transition");
                old_x_failures += 1;
            }
            old.detach();
        }
        held = Some(new_cover);
    }

    stop.store(true, Ordering::SeqCst);
    let elapsed = pool_started.elapsed();
    let attempts: usize = probers
        .into_iter()
        .map(|p| p.join().expect("prober thread panicked"))
        .sum();
    let control_total_attempts = control.join().expect("control prober thread panicked");
    assert!(
        attempts > 0,
        "prober pool made no attempts at all — this test is vacuous"
    );
    assert_eq!(
        old_x_failures, 0,
        "pfctl -X failed retiring the old cover's refcount on {old_x_failures}/{TRANSITIONS} \
         transitions — each failure leaks a pf enable refcount (see the warn logged above for \
         which iteration and why)"
    );

    // The guard stating its own sensitivity. Printed unconditionally (see the
    // doc comment): a green with no number attached says only that nothing was
    // caught, not that anything would have been. The denominator here is
    // `permitted_attempts`, NOT the control's total attempt count: half of the
    // latter targets whichever server the loop currently blocks and can never
    // complete under `block-policy drop`, so counting it would understate the
    // budget's real hit rate by roughly half (see the control thread's doc
    // comment above).
    let hits = control_hits.load(Ordering::SeqCst);
    let permitted_attempts = control_permitted_attempts.load(Ordering::SeqCst);
    let control_rate = 100.0 * hits as f64 / permitted_attempts as f64;
    let per_probe_us = elapsed.as_micros() as f64 / attempts as f64;
    eprintln!(
        "[sensitivity] macos_failclosed_cover_transition: control completed {hits}/{permitted_attempts} \
         connects ({control_rate:.1}%) to a PERMITTED server within {PROBER_TIMEOUT:?} ({control_total_attempts} \
         total alternating attempts, half of which target the currently-blocked server and are excluded); \
         the pool emitted {attempts} probes across {PROBER_THREADS} threads over {elapsed:?} = one probe \
         per {per_probe_us:.0} us of wall clock. That interval bounds probe COVERAGE, not detection: a \
         leak must still complete the WHOLE handshake — SYN, SYN/ACK across the RTT, and the client's \
         outbound ACK — before the next `pfctl -f -` commit can cut it off, so a leak window shorter than \
         that interval, or too short to fit a full handshake at all, is likelier to be missed than caught; \
         compare it against the ~sub-millisecond `pfctl -f -` commit this test guards."
    );

    assert!(
        !leaked.load(Ordering::SeqCst),
        "a connection to {NON_PERMITTED} got out while a cover was live — every ruleset across \
         the {TRANSITIONS} transitions blocks it, and the cold engage was verified blocking \
         before the first prober started, so `pfctl -f -` is not behaving as one atomic \
         transaction; leaked_at_phase={} (0 = the cold cover, steady, before any transition \
         began; >=1 = that transition)",
        leaked_at_phase.load(Ordering::SeqCst),
    );

    assert!(
        hits > 0,
        "positive control: not one of {permitted_attempts} connects to a PERMITTED server \
         ({SERVER_A}/{SERVER_B}) completed within {PROBER_TIMEOUT:?} across the whole run, so that \
         budget cannot complete a handshake on this runner at all and the never-admitted assertion \
         above held vacuously — raise PROBER_TIMEOUT rather than trusting the green"
    );

    // The last cover's normal Drop restores /etc/pf.conf.
    drop(held.take());
    let restored = connect(NON_PERMITTED, SETTLED_TIMEOUT);
    assert!(
        restored.is_ok(),
        "final disengage must restore egress: {NON_PERMITTED}={:?}",
        restored.err().map(|e| e.kind()),
    );
}

// pf state purge on a transient engage (bindreams/hole#1015, transient half) ==========================================

/// Proves the behavioural half of [`purges_state`]: a flow that already holds
/// a pf state entry when the transient cover engages does **not** survive it.
///
/// pf matches the state table before the ruleset, so without the purge this
/// flow keeps running past `block out all` for as long as its entry lives —
/// `tcp.established` defaults to 86400s and every packet refreshes it, so a
/// long-lived upload, an SSH session or a WebSocket never expires at all. The
/// unit tests next door assert the `pfctl` sequence; this one asserts the
/// kernel consequence, which is the property that actually matters.
///
/// **Staging the precondition is the whole setup.** A state entry exists only
/// if pf saw the packet while pf was ENABLED (`pf_af_hook` bails on
/// `!pf_is_enabled`), and stock macOS ships pf loaded but never enabled. So the
/// test stands in for the third party that enabled it — Internet Sharing,
/// another VPN, a hand-run `pfctl -e` — with its own `pfctl -E` plus a
/// permissive keep-state ruleset, exactly the case #1015 calls its case 2. The
/// `-E` refcount this takes is returned at the end; the cover's own `-E`/`-X`
/// pair nests inside it, so pf's enable state is exactly as this test found it
/// once both are released.
///
/// Asserted on the STATE TABLE (`pfctl -s state`) rather than on whether the
/// held socket still carries traffic: the state entry is the thing pf consults
/// before the ruleset, so its absence is the property directly, with no
/// dependence on a remote peer choosing to answer.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_failclosed_cover_state_purge_kills_a_flow_established_before_engage() {
    use std::net::TcpStream;
    use std::time::Duration;

    // Same reliable anycast pair the transition test above uses, and for the
    // same reason (see its doc): the cover's permits are IP-based, so the flow
    // that must die has to be a real routable destination the cover blocks.
    const PERMITTED: &str = "1.1.1.1";
    const NON_PERMITTED_IP: &str = "8.8.8.8";
    const NON_PERMITTED: &str = "8.8.8.8:443";
    // External-event bound: a remote host that might not answer, surfaced to a
    // human — not a sync sleep. Same 5s the neighbouring cover tests use.
    const SETTLED_TIMEOUT: Duration = Duration::from_secs(5);

    let states = || {
        pfctl_stdout(
            pfctl(&["-s", "state"], None, BestEffortPhase::RecoverCover),
            "pfctl -s state",
        )
        .expect("pfctl -s state")
    };

    // 1. Stand in for the third party that already enabled pf, under a ruleset
    //    that creates state for everything. RAII, so EVERY exit path — a failed
    //    assertion included — reloads /etc/pf.conf and returns the refcount;
    //    otherwise a red run leaves the runner with pf enabled under a pass-all
    //    ruleset and an unreferenced token until reboot. Declared first, so it
    //    unwinds after the cover and the socket below.
    struct HostPfStandIn(String);
    impl Drop for HostPfStandIn {
        fn drop(&mut self) {
            // Mirrors `disengage`'s warn-on-failure pattern (macos.rs): a red
            // run must not ALSO leave a silently-stranded pf ruleset or an
            // unreferenced enable token with no logged trace of why the
            // restore failed.
            if let Err(e) = pfctl_status(pfctl(&["-f", PFCONF], None, BestEffortPhase::RecoverCover), "pfctl -f") {
                tracing::warn!(error = %e, "pf ruleset restore failed unwinding the HostPfStandIn test fixture");
            }
            if let Err(e) = pfctl_status(pfctl(&["-X", &self.0], None, BestEffortPhase::RecoverCover), "pfctl -X") {
                tracing::warn!(error = %e, "pfctl -X failed unwinding the HostPfStandIn test fixture");
            }
        }
    }
    let enabled = pfctl(&["-E"], None, BestEffortPhase::RecoverCover).expect("pfctl -E");
    let _host_pf = HostPfStandIn(
        parse_enable_token(&String::from_utf8_lossy(&enabled.stderr))
            .or_else(|| parse_enable_token(&String::from_utf8_lossy(&enabled.stdout)))
            .expect("pfctl -E must print an enable token"),
    );
    let permissive = pfctl(
        &["-f", "-"],
        Some(b"pass out all keep state\npass in all keep state\n"),
        BestEffortPhase::RecoverCover,
    )
    .expect("load the permissive pre-cover ruleset");
    assert!(
        permissive.status.success(),
        "the permissive pre-cover ruleset must load: {}",
        String::from_utf8_lossy(&permissive.stderr).trim()
    );

    // 2. Establish the flow the cover must kill, and HOLD it open — a closed
    //    socket's state would drain on its own and prove nothing.
    let _flow = TcpStream::connect_timeout(&NON_PERMITTED.parse().unwrap(), SETTLED_TIMEOUT)
        .unwrap_or_else(|e| panic!("NETWORK/ENVIRONMENT problem (not the cover): must reach {NON_PERMITTED}: {e:?}"));
    assert!(
        states().contains(NON_PERMITTED_IP),
        "PRECONDITION: pf must hold a state entry for the flow before the cover engages, or this \
         test proves nothing — pf enabled and a keep-state ruleset loaded, yet `pfctl -s state` \
         does not name {NON_PERMITTED_IP}"
    );

    // 3. Engage the transient cover over that live flow, and read the state
    //    table back while the cover is still the loaded ruleset.
    let dir = tempfile::tempdir().unwrap();
    let cover = engage(PERMITTED.parse().unwrap(), None, dir.path(), None).expect("engage the transient cover");
    let after = states();
    // Restore before asserting: a failure must not leave the machine behind a
    // block-all cover while the panic unwinds.
    drop(cover);

    assert!(
        !after.contains(NON_PERMITTED_IP),
        "a flow to {NON_PERMITTED_IP} still held a pf state entry after the transient cover \
         engaged — pf matches state BEFORE rules, so it keeps flowing past `block out all` until \
         the entry expires (`tcp.established` default 86400s, refreshed per packet). \
         `pfctl -s state` after engage:\n{after}"
    );
}
