//! Privileged-lane leak proofs for the update cutover. Real WFP/pf engage +
//! egress probes. NOT `#[ignore]`d and do NOT skip on missing privilege -- a
//! default `cargo nextest` run on an unelevated box runs them and FAILS LOUD; the
//! explicit `SKULD_LABELS="!tun"` filter opts out, and CI provisions the
//! elevation.
//!
//! Every reachability assertion is OUTBOUND egress to a routable IP -- NEVER
//! loopback. The GitHub Actions Windows runner drops inbound loopback to the test
//! exe, so a loopback probe cannot distinguish a working cover from a broken one
//! (the PR1 lesson). IP literals only: the cover blocks DNS, so a hostname
//! connect would fail for the wrong reason.
//!
//! Cross-binary serialization of the global WFP/pf/TUN state lives in
//! `.config/nextest.toml` (`global-net-state` test-group). COUPLED NAMES: that
//! group's filter matches by the `cutover_global_net_state_` prefix -- renaming a
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
#[cfg(any(target_os = "windows", target_os = "macos"))]
const SERVER_IP: &str = "1.1.1.1";
#[cfg(any(target_os = "windows", target_os = "macos"))]
const PERMITTED: &str = "1.1.1.1:443";
#[cfg(any(target_os = "windows", target_os = "macos"))]
const NON_PERMITTED: &str = "8.8.8.8:443";

/// External-event probe with a graceful failure bound: the timeout is the
/// failure-to-human signal, not a sync sleep; assertions are Ok/Err, not timing.
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn connect(addr: &str) -> std::io::Result<TcpStream> {
    TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5))
}

// The wire-level NIC-capture UDP no-leak proof lives in
// `cutover_nic_capture_privileged.rs` (Windows in-box pktmon — no pcap crate /
// Npcap). macOS has no NIC arm there by design: its BPF tap is upstream of pf,
// so an en0 capture would record packets pf later drops (unsound); macOS keeps
// the connect()-probe in tun-engine's `lockdown_privileged_tests.rs`.

// The Mullvad-#8470 fail-open negative (a failed lockdown-off restart leaves the
// host fail-open, not bricked) is NOT a faithful privileged-lane test without a
// real failed-new-bridge-start harness: a lockdown-off cutover engages no cover,
// so with nothing engaged an egress probe is a tautology (baseline reachability,
// independent of any cutover code path). The load-bearing invariant -- a cutover
// engages no transient cover, so a failed start cannot brick the host (the
// Mullvad-#8470 class) -- is enforced STRUCTURALLY: the `cutover::os::CutoverOs`
// effects trait exposes no cover-mutating method. The privileged version is
// reported back as needing a real failed-start fixture.

/// The standing lockdown cover's egress block must SURVIVE a `disarm` -- that is
/// the cutover leak invariant on the real ruleset. The bridge's marker-
/// conditional shutdown `disarm`s the cover (persist-without-disengage via
/// `std::mem::forget`) instead of dropping it, so the WFP/pf filters hold across
/// the restart gap and the new bridge re-adopts them. A `disarm` that actually
/// disengaged would open the host mid-cutover (a leak).
///
/// Proven end-to-end on the real cover: engage it, confirm it blocks a
/// non-permitted host, `disarm` it, and confirm the block STILL holds (and the
/// server permit too). Cleanup fully disengages via the persisted state so the
/// box is left open.
///
/// (This replaces the originally-planned both-covers recovery egress test, which
/// could not be made faithful: the macOS transient `engage` does `pfctl -Fa`,
/// flushing the standing ruleset, and `recover_lockdown(Adopt)` deliberately does
/// not reload it -- so post-recovery the live ruleset is the transient leftover,
/// and with a shared permit IP the egress assertions pass regardless of whether
/// standing-adopt works. The Task-4 reorder invariant it targeted -- lockdown
/// reconcile BEFORE the transient sweep, the sweep told `standing_held` so it
/// skips the `/etc/pf.conf` reload -- is proven at the unit level by
/// `routing_tests::recover_orders_lockdown_before_transient_sweep_and_passes_adopting`.)
#[cfg(any(target_os = "windows", target_os = "macos"))]
#[skuld::test(labels = [TUN], serial = TUN)]
fn cutover_global_net_state_disarm_preserves_the_standing_egress_block() {
    use tun_engine::routing::failclosed::{disengage_lockdown, engage_lockdown, lockdown_state, SystemLuidResolver};
    use tun_engine::routing::CoverGuard;

    #[cfg(target_os = "windows")]
    let tun_name = "Loopback Pseudo-Interface 1"; // always-present LUID source
    #[cfg(target_os = "macos")]
    let tun_name = "utun-absent"; // a never-matching pass rule; the block governs

    let dir = tempfile::tempdir().unwrap();
    let resolver = SystemLuidResolver;
    let server_ip: std::net::IpAddr = SERVER_IP.parse().unwrap();

    // Baseline (PRE-cover): both hosts reachable. A failure here is a network/
    // environment problem, not the cover -- fail loud and self-validate the probe.
    assert!(
        connect(PERMITTED).is_ok() && connect(NON_PERMITTED).is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): pre-cover baseline egress must reach both hosts"
    );

    lockdown_state::set_enabled(dir.path(), true).unwrap();
    let cover = engage_lockdown(server_ip, tun_name, &resolver, &[], dir.path())
        .expect("engage the real standing lockdown cover");

    // Engaged: server permitted (permit beats block-all), others blocked (no leak).
    assert!(
        connect(PERMITTED).is_ok(),
        "server-IP permit must hold while engaged: {PERMITTED}"
    );
    assert!(
        connect(NON_PERMITTED).is_err(),
        "non-permitted egress must be blocked: {NON_PERMITTED}"
    );

    // The cutover-shutdown action: disarm (persist-without-disengage), NOT drop.
    cover.disarm();

    // THE INVARIANT: the block survives disarm -- the filters persist across the
    // restart gap (server still permitted, others still blocked). A disarm that
    // disengaged would let NON_PERMITTED through here (the leak this guards).
    assert!(
        connect(PERMITTED).is_ok(),
        "server-IP permit must survive disarm: {PERMITTED}"
    );
    assert!(
        connect(NON_PERMITTED).is_err(),
        "disarm must NOT disengage the cover (leak!): {NON_PERMITTED} connected after disarm"
    );

    // Cleanup: fully disengage via the persisted state (no live guard remains
    // after disarm), restoring egress so the box is left open.
    lockdown_state::set_enabled(dir.path(), false).unwrap();
    disengage_lockdown(dir.path()).expect("disengage the persisted cover to restore egress");
    assert!(
        connect(NON_PERMITTED).is_ok(),
        "cleanup disengage must restore egress: {NON_PERMITTED}"
    );
}
