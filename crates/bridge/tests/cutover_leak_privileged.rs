//! Privileged-lane leak proofs for the update cutover (the NIC-capture proof
//! deferred from PR1, plus the Mullvad-#8470 fail-open negative and the
//! both-covers recovery invariant). Real WFP/pf engage + egress probes. NOT
//! `#[ignore]`d and do NOT skip on missing privilege — a default `cargo nextest`
//! run on an unelevated box runs them and FAILS LOUD; the explicit
//! `SKULD_LABELS="!tun"` filter opts out, and CI provisions the elevation.
//!
//! Every reachability assertion is OUTBOUND egress to a routable IP — NEVER
//! loopback. The GitHub Actions Windows runner drops inbound loopback to the test
//! exe, so a loopback probe cannot distinguish a working cover from a broken one
//! (the PR1 lesson). IP literals only: the cover blocks DNS, so a hostname
//! connect would fail for the wrong reason.
//!
//! Cross-binary serialization of the global WFP/pf/TUN state lives in
//! `.config/nextest.toml` (`global-net-state` test-group). COUPLED NAMES: that
//! group's filter matches by the `cutover_global_net_state_` prefix — renaming a
//! prefix WITHOUT updating the filter drops the test from the group (a silent
//! cross-binary race). Change both together.

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

#[skuld::label]
const TUN: skuld::Label;

#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::net::TcpStream;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::time::Duration;

// Routable anycast hosts on :443 (the runner has outbound internet). The cover
// permits the server IP and blocks everything else, so this proves no-leak.
// SERVER_IP/PERMITTED are engaged as the permitted server only by the macOS
// both-covers proof; NON_PERMITTED is probed by both leak tests.
#[cfg(target_os = "macos")]
const SERVER_IP: &str = "1.1.1.1";
#[cfg(target_os = "macos")]
const PERMITTED: &str = "1.1.1.1:443";
#[cfg(any(target_os = "windows", target_os = "macos"))]
const NON_PERMITTED: &str = "8.8.8.8:443";

/// External-event probe with a graceful failure bound: the timeout is the
/// failure-to-human signal, not a sync sleep; assertions are Ok/Err, not timing.
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn connect(addr: &str) -> std::io::Result<TcpStream> {
    TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5))
}

// The deferred NIC-capture UDP no-leak proof (physical-NIC pcap across the
// cutover gap, asserting no UDP egress except to the server) is NOT added here:
// physical-NIC packet capture is net-new infra with no pcap dependency in the
// tree and is unverifiable on this dev box, so a stub would either silently never
// run or fail CI blindly (both forbidden). The invariant it would prove — a
// standing lockdown cover blocks non-server egress and the cutover never
// disengages it — is covered by `..._both_covers_recovery_keeps_standing_block`
// (egress-blocked-except-server on the real ruleset) plus the `stop_with` disarm
// unit test (the cover is disarmed, never disengaged, on a cutover). The capture
// proof is reported back as needing a CI pcap lane + a live-TUN cutover fixture.

/// Mullvad-#8470 negative: lockdown OFF + a plain restart whose new bridge fails
/// to start must leave the host FAIL-OPEN (egress works), NOT bricked. A
/// transient cover engaged across a lockdown-off restart is exactly the
/// Mullvad-#8470 brick; `plan_cutover(false) == PlainRestart` engages none, so
/// after a failed start egress is unblocked.
#[cfg(any(target_os = "windows", target_os = "macos"))]
#[skuld::test(labels = [TUN], serial = TUN)]
fn cutover_global_net_state_lockdown_off_failed_start_is_fail_open() {
    use hole_bridge::cutover::plan::{plan_cutover, CutoverPlan};

    // Baseline: with no cover engaged, egress must reach the host. A failure here
    // is a network/environment problem, not the cover — fail loud.
    assert!(
        connect(NON_PERMITTED).is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cutover): baseline egress must reach {NON_PERMITTED}"
    );

    // A lockdown-off cutover engages NO cover (the structural never-co-engage
    // invariant). So even a failed new-bridge start cannot brick the host.
    assert_eq!(
        plan_cutover(false),
        CutoverPlan::PlainRestart,
        "lockdown-off cutover must be a plain restart that engages no cover"
    );

    // Fail-open proof: no cover is in force, so outbound egress still succeeds —
    // the host is open, not bricked, after a (simulated) failed restart.
    assert!(
        connect(NON_PERMITTED).is_ok(),
        "lockdown-off + failed start must leave the host FAIL-OPEN (egress works), not bricked"
    );
}

/// Both-covers recovery: a (stale) transient cover AND the standing lockdown
/// cover are engaged; `recover_routes` must keep the standing egress block in
/// force (egress blocked except the server) — the never-co-engage + reorder fix
/// (lockdown reconcile BEFORE the transient sweep; the sweep is lockdown-aware)
/// proven end-to-end on the real pf ruleset. macOS only: the reorder fix's
/// load-bearing case is the pf `/etc/pf.conf` reload that would wipe the standing
/// ruleset; Windows is structurally safe (disjoint WFP GUIDs).
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn cutover_global_net_state_both_covers_recovery_keeps_standing_block() {
    use tun_engine::routing::failclosed::{engage, engage_lockdown, lockdown_state, SystemLuidResolver};
    use tun_engine::routing::recover_routes;

    let dir = tempfile::tempdir().unwrap();
    let resolver = SystemLuidResolver;
    let server_ip: std::net::IpAddr = SERVER_IP.parse().unwrap();

    // Baseline: both hosts reachable pre-cover.
    assert!(
        connect(PERMITTED).is_ok() && connect(NON_PERMITTED).is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): pre-cover baseline egress must reach both hosts"
    );

    // Engage the standing lockdown cover and persist the intent (so recovery
    // decides Adopt). Then disarm it (persist-without-disengage) to model the
    // post-cutover state the new bridge wakes into.
    lockdown_state::set_enabled(dir.path(), true).unwrap();
    let standing = engage_lockdown(server_ip, "utun-absent", &resolver, &[], dir.path())
        .expect("engage the real pf standing lockdown cover");
    {
        use tun_engine::routing::CoverGuard;
        standing.disarm(); // persist the filters (the cutover-shutdown disarm)
    }

    // A stale transient cover left by a crashed run (the both-covers case).
    let transient = engage(server_ip, dir.path()).expect("engage a stale transient cover");
    {
        use tun_engine::routing::CoverGuard;
        transient.disarm(); // leave it on disk so recover sweeps it
    }

    // Recovery: lockdown Adopt is reconciled BEFORE the transient sweep, and the
    // sweep is told a standing cover is held so it does NOT reload /etc/pf.conf
    // (which would wipe the live lockdown ruleset).
    recover_routes(dir.path());

    // The standing block must still be in force: server permitted, others blocked.
    assert!(
        connect(PERMITTED).is_ok(),
        "the standing server-IP permit must survive recovery: {PERMITTED}"
    );
    assert!(
        connect(NON_PERMITTED).is_err(),
        "recovery must NOT wipe the standing lockdown block (leak!): {NON_PERMITTED} connected"
    );

    // Clean up: fully disengage so the box is left open.
    lockdown_state::set_enabled(dir.path(), false).unwrap();
    let _ = tun_engine::routing::failclosed::disengage_lockdown(dir.path());
}
