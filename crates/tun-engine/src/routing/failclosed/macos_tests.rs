use super::*;
use std::net::IpAddr;

use crate::GLOBAL_NET_STATE;

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

/// Every lo0 `pass` line in `r`, by direction, asserting each is `quick` and
/// `no state`. Shared by the transient and the lockdown builder's case so the
/// two-exemption rule (see [`loopback_is_exempted_twice_over`]) has one
/// statement, not two that can drift.
fn assert_stateless_loopback_passes(r: &str) {
    let lo_passes: Vec<&str> = r
        .lines()
        .filter(|l| l.trim_start().starts_with("pass") && l.contains("lo0"))
        .collect();
    for dir in ["out", "in"] {
        let rule = lo_passes
            .iter()
            .find(|l| l.trim_start().starts_with(&format!("pass {dir} ")))
            .unwrap_or_else(|| panic!("no `pass {dir}` rule on lo0 — loopback is unprotected across the next load's skip-flag-clear window:\n{r}"));
        assert!(rule.contains("quick"), "lo0 pass must be quick: {rule}");
        assert!(
            rule.contains("no state"),
            "a lo0 pass WITHOUT `no state` is defaulted to `flags S/SA keep state` by pfctl, so it \
             matches only a SYN and creates an entry the state purge flushes — it cannot carry a \
             mid-stream segment: {rule}"
        );
    }
}

/// Loopback needs BOTH exemptions, because they cover two different failures.
///
/// `set skip on lo0` is the steady-state one: it passes loopback "as if pf was
/// disabled", with no state entry for this cover's own `pfctl -F states` purge
/// (`purges_state(Transient) == true`) to flush.
///
/// The `pass` rules cover the window `set skip` cannot cover for itself.
/// `pfctl` clears every interface's skip flag in `main()` — BEFORE it parses
/// and BEFORE `DIOCXBEGIN` — so from that clear until this ruleset's own
/// `set skip` ioctl lands, lo0 is filtered again while the PREVIOUS ruleset is
/// still the authoritative one. Rules live inside the ticket and stay
/// authoritative to `DIOCXCOMMIT`, so it is the lo0 `pass` in the OUTGOING
/// ruleset that carries loopback across the next load's flag-clear window — on
/// a cover transition, on the `/etc/pf.conf` restore, and on lockdown
/// engage/disengage alike.
///
/// `no state` is load-bearing: `pfctl -vn -f -` normalizes a bare
/// `pass out quick on lo0 all` to `... flags S/SA keep state`, which matches
/// only a SYN. A mid-stream segment would fall through to the block and be
/// silently discarded under `block-policy drop` — bindreams/hole#1015 again, by
/// a different route.
#[skuld::test]
fn loopback_is_exempted_twice_over() {
    let r = build_pf_ruleset(v4(), None);
    assert!(r.contains("set skip on lo0"), "transient cover must skip lo0:\n{r}");
    assert_stateless_loopback_passes(&r);
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
fn lockdown_main_exempts_loopback_twice_over() {
    // Same two-exemption rule as the transient cover — see
    // [`loopback_is_exempted_twice_over`]. The lockdown ruleset engages and
    // disengages over a still-live blocking ruleset just as the transient one
    // does, so its skip-flag-clear window is the same window.
    let r = lockdown(v4(), "");
    assert!(r.contains("set skip on lo0"), "lockdown main must skip lo0:\n{r}");
    assert_stateless_loopback_passes(&r);
}

#[skuld::test]
fn lockdown_main_passes_loopback_before_it_blocks_inet6() {
    // `block drop out quick inet6 all` is `quick`, so it would terminate
    // evaluation on a `::1` packet before any later lo0 pass could match. The
    // lo0 passes are only an exemption if they LEAD it.
    let r = lockdown(v4(), "");
    let lo = r.find("pass out quick on lo0").expect("lo0 pass out rule");
    let inet6 = r.find("block drop out quick inet6 all").expect("inet6 block");
    assert!(
        lo < inet6,
        "lo0 must be passed before the quick inet6 block, or ::1 is dropped during the \
         skip-flag-clear window:\n{r}"
    );
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

// recover_cover_with ==================================================================================================

/// [`RecoverOps`] test double: records the token each `restore` was handed
/// (`None` = "no token on record"), so what the sweep DOES is assertable, not
/// merely that it did something.
#[derive(Default)]
struct RecordingRecoverOps {
    restores: Vec<(Option<String>, bool)>,
}

impl RecoverOps for RecordingRecoverOps {
    fn restore(&mut self, token: Option<&str>, adopting: bool) {
        self.restores.push((token.map(str::to_owned), adopting));
    }
}

/// A record whose `pf_was_enabled` is the tri-state `None` a failed
/// `pfctl -s info` read persists — the exact shape an older binary cannot
/// parse.
fn unknown_pf_cover(token: &str) -> state::FailClosedState {
    state::FailClosedState {
        version: state::SCHEMA_VERSION,
        pf_token: token.to_owned(),
        pf_was_enabled: None,
    }
}

#[skuld::test]
fn recover_cover_with_no_state_file_does_nothing() {
    let mut ops = RecordingRecoverOps::default();
    recover_cover_with(StateFile::Absent, false, &mut ops);
    assert!(
        ops.restores.is_empty(),
        "an absent file means no cover was ever engaged; a sweep must spawn nothing: {:?}",
        ops.restores
    );
}

#[skuld::test]
fn recover_cover_with_a_recorded_cover_restores_and_drops_its_token() {
    let mut ops = RecordingRecoverOps::default();
    recover_cover_with(StateFile::Present(unknown_pf_cover("42")), true, &mut ops);
    assert_eq!(ops.restores, vec![(Some("42".to_owned()), true)]);
}

/// An UNREADABLE record is a cover to clear, not an absence.
///
/// `Absent` and `Unusable` are opposite facts for a sweep: the first says no
/// cover was ever engaged, the second is Hole's own unreconciled record that
/// one WAS and was never confirmed released. The reachable production cause is
/// a ROLLBACK — a newer bridge persists `"pf_was_enabled": null` for a failed
/// `pfctl -s info` read, and an older binary's `bool` field cannot read it, so
/// its whole sweep sees "nothing to recover" while the crashed run's
/// `block out all` still holds the host. Only the manual `bridge unlock` would
/// escape it.
#[skuld::test]
fn recover_cover_with_an_unreadable_state_file_still_restores_the_host() {
    let mut ops = RecordingRecoverOps::default();
    recover_cover_with(StateFile::Unusable, false, &mut ops);
    assert_eq!(
        ops.restores,
        vec![(None, false)],
        "an unreadable failclosed-state file must still drive a restore — with no token to drop, \
         but never as a no-op"
    );
}

/// The rollback payload itself, through the REAL `load_presence`: this is the
/// byte sequence a newer bridge writes and an older one cannot parse, so the
/// test pins the actual cause rather than standing in for it with arbitrary
/// corruption.
#[skuld::test]
fn a_null_pf_was_enabled_is_unreadable_to_a_bool_schema_and_reads_as_a_cover() {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct OlderFailClosedState {
        version: u32,
        pf_token: String,
        /// The pre-tri-state shape a released binary still carries.
        pf_was_enabled: bool,
    }

    let dir = tempfile::tempdir().unwrap();
    state::save(dir.path(), &unknown_pf_cover("7"), None).expect("persist the newer shape");
    let bytes = std::fs::read(dir.path().join(state::STATE_FILE_NAME)).unwrap();

    assert!(
        serde_json::from_slice::<OlderFailClosedState>(&bytes).is_err(),
        "this test's premise: an older bridge's `bool` schema must reject the `null` a newer one \
         writes — {}",
        String::from_utf8_lossy(&bytes)
    );

    // What that older bridge's own sweep would then see, and what it must do.
    let mut ops = RecordingRecoverOps::default();
    recover_cover_with(StateFile::Unusable, false, &mut ops);
    assert_eq!(ops.restores, vec![(None, false)]);
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
    /// Every state handed to `save_transient`, so what the engage RECORDS is
    /// assertable, not just that it recorded something.
    saved: Vec<state::FailClosedState>,
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

    fn save_transient(&mut self, st: &state::FailClosedState) -> Result<(), RoutingError> {
        self.log.push("save_transient");
        self.saved.push(st.clone());
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
    // on a real, enumerated set of causes — unwritable state dir, full disk;
    // NOT a failed chown, which `util::ownership::chown_if_some` logs and
    // swallows. Without this unwind pf stays ENABLED under an unreferenced
    // token until reboot, with no `bridge-failclosed.json` for
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

#[skuld::test]
fn a_failed_pf_enabled_read_records_unknown_and_still_engages() {
    // Step 1 (`pf_enabled`) is DIAGNOSTIC ONLY — `pf_was_enabled`'s single
    // reader is a `tracing::info!` field in `recover_cover`. Aborting the
    // engage on it fails the cover OPEN: `install_failclosed_cover`'s caller
    // logs "host NOT blocked, proceeding open" and starts the session
    // uncovered, even though every step that actually establishes the cover
    // (`-E`, persist, `-f -`) would have succeeded. Only the
    // cover-ESTABLISHING steps may be fatal.
    let mut ops = RecordingEngageOps {
        fail_pf_enabled: true,
        ..recording_engage_ops()
    };
    let token = engage_with(v4(), None, &mut ops).expect("a diagnostic read must not fail the engage");

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
        "a failed diagnostic read must not stop the engage sequence: {:?}",
        ops.log
    );
    assert_eq!(
        ops.saved.iter().map(|st| st.pf_was_enabled).collect::<Vec<_>>(),
        vec![None],
        "the record must say UNKNOWN, not assert a value that was never read: {:?}",
        ops.saved
    );
    assert!(
        ops.dropped.is_empty(),
        "a successful engage unwinds nothing: {:?}",
        ops.dropped
    );
}

#[skuld::test]
fn a_successful_pf_enabled_read_is_recorded_as_read() {
    // The positive half of the tri-state: `None` must mean "could not be read",
    // never "read as false", or the honest record is indistinguishable from a
    // measured one.
    let mut ops = RecordingEngageOps {
        pf_enabled: true,
        ..recording_engage_ops()
    };
    engage_with(v4(), None, &mut ops).expect("engage_with");
    assert_eq!(
        ops.saved.iter().map(|st| st.pf_was_enabled).collect::<Vec<_>>(),
        vec![Some(true)],
        "a read that succeeded must be recorded as the value it read: {:?}",
        ops.saved
    );
}

#[skuld::test]
fn a_failed_enable_capture_token_fails_the_engage_without_a_spurious_unwind() {
    // Step 2 (`enable_capture_token`, the `pfctl -E` call) is what takes the
    // refcount `drop_token` would later undo. When taking it fails outright,
    // there is nothing to unwind — a `drop_token` call here would be dropping
    // a refcount that was never actually acquired (the same shape as
    // `engage_lockdown`'s `FreshEnable`/`Reenable` arms, which only unwind
    // AFTER `enable_pf_capture_token` returns `Ok`).
    let mut ops = RecordingEngageOps {
        fail_enable_capture_token: true,
        ..recording_engage_ops()
    };
    let err = engage_with(v4(), None, &mut ops).expect_err("a failed enable_capture_token must fail the engage");
    assert!(err.to_string().contains("enable_capture_token"), "{err}");
    assert_eq!(
        ops.log,
        vec!["pf_enabled", "enable_capture_token"],
        "step 2 failing must stop the sequence before step 3 (`save_transient`) ever runs: {:?}",
        ops.log
    );
    assert!(
        ops.dropped.is_empty(),
        "an `enable_capture_token` failure must NOT attempt a `drop_token` unwind — there is no \
         refcount to undo: {:?}",
        ops.dropped
    );
}

// drop_refcount_or_warn (pfctl -X exit status must not be silently swallowed) =========================================

/// [`drop_refcount_or_warn`] routes `pfctl -X` through [`pfctl_status`] so a
/// non-zero EXIT is caught, not just a spawn failure: a spawn succeeds even
/// when `pfctl` itself rejects the call (e.g. a token that is already gone),
/// so reading the spawn `Result` alone leaks the refcount while the log claims
/// nothing happened. This pins THAT check with a REAL (unmocked) failing
/// `pfctl -X`, root-free.
///
/// The operative reason it fails is the TOKEN, not the privilege: `pfctl`
/// rejects a non-numeric `-X` argument while parsing arguments, before it ever
/// opens `/dev/pf` (confirmed: `/sbin/pfctl -X not-a-real-token` prints
/// `pfctl: Invalid token value 'not-a-real-token'` plus usage, exit 1, spawn
/// itself succeeds). A *numeric* token would instead reach the open and fail
/// there — `/sbin/pfctl -X 12345` prints `pfctl: /dev/pf: Permission denied`,
/// which is the privilege-dependent failure this test deliberately does not
/// rely on. Since the parse precedes the open, the failure here is identical
/// under root: the test cannot go vacuous if it is ever run elevated, and it
/// needs no `TUN`/`GLOBAL_NET_STATE` label and no root.
#[skuld::test]
fn drop_refcount_or_warn_logs_a_pfctl_x_that_spawned_but_exited_non_zero() {
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let writer = garter::test_utils::WaitableWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        // Not a real pf token, and not even a well-formed one: `pfctl` rejects
        // it while parsing arguments, before `/dev/pf` is opened, so the
        // non-zero exit does not depend on this process being unprivileged
        // (see the doc comment above).
        drop_refcount_or_warn(
            "not-a-real-token",
            BestEffortPhase::RecoverCover,
            "test sentinel: drop_refcount_or_warn pin",
        );
    }
    let log = writer.snapshot();
    assert!(
        log.contains("test sentinel: drop_refcount_or_warn pin"),
        "a `pfctl -X` with an invalid token exits non-zero (spawn succeeds, status fails) — that \
         must be logged via pfctl_status's exit-code check, not read as an `Ok` spawn result and \
         silently swallowed: {log}"
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
    fail_drop_token: bool,
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
        if self.fail_drop_token {
            Err(RoutingError::RouteSetup("mock drop_token failure".into()))
        } else {
            Ok(())
        }
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
        pf_was_enabled: Some(false),
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

#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn release_all_logs_every_failed_token_drop_instead_of_discarding_it() {
    // `release_all` is the emergency clear-every-cover path (`bridge unlock`,
    // the crash-recovery sweep), so a pf enable refcount that fails to drop
    // here leaks exactly as it would anywhere else. Non-propagation is the
    // documented contract (`PfOps::drop_token`); silence is not — a `let _ =`
    // leaves the operator no trace that pf stayed enabled. All THREE drop
    // sites are covered, each with its own message so a warn in the log still
    // says which one it came from.
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let writer = garter::test_utils::WaitableWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        // Sites 1 and 3: the transient cover, and the standing cover restored
        // from its captured snapshot.
        let mut ops = RecordingPfOps {
            fail_drop_token: true,
            ..Default::default()
        };
        let _ = release_all_with(
            StateFile::Present(transient_state()),
            StateFile::Present(standing_state()),
            &mut ops,
        );
        // Site 2: the standing cover with no captured baseline, which restores
        // the default ruleset instead of a snapshot.
        let mut ops = RecordingPfOps {
            fail_drop_token: true,
            ..Default::default()
        };
        let _ = release_all_with(
            StateFile::Absent,
            StateFile::Present(lockdown_state::LockdownPfState {
                main_snapshot_captured: false,
                ..standing_state()
            }),
            &mut ops,
        );
    }
    let log = writer.snapshot();
    for site in [
        "pfctl -X failed releasing the transient cover's pf refcount during release_all",
        "pfctl -X failed releasing the standing cover's pf refcount during release_all after a snapshot restore",
        "pfctl -X failed releasing the standing cover's pf refcount during release_all after a default-ruleset restore",
    ] {
        assert!(
            log.contains(site),
            "a failed `pfctl -X` must be logged, not discarded by a `let _ =`; missing {site:?} in: {log}"
        );
    }
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
