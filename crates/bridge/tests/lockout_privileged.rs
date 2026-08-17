//! Privileged-lane proof that a kill-switch lockout is escapable end to end
//! (bindreams/hole#825). Real WFP/pf cover + real egress probes, driven through
//! the production `ProxyManager` + `SystemRouting` so the user's actual remedy —
//! turning the kill switch off — is on the tested path.
//!
//! NOT `#[ignore]`d and does NOT skip on missing privilege: a default
//! `cargo nextest` run on an unelevated box runs these and FAILS LOUD; the
//! explicit `SKULD_LABELS="!tun"` filter opts out, and CI provisions the
//! elevation.
//!
//! Lives here rather than in `tun-engine` because the assertion the whole issue
//! rests on is that `ProxyManager::set_lockdown_intent(false)` opens the host.
//! `tun-engine` sits below `hole-bridge` and cannot reach it, so a test placed
//! there could only call `failclosed::disengage_lockdown` directly and would be
//! blind to every decision the manager makes.
//!
//! The unclean exit is `CoverGuard::disarm` — `std::mem::forget` of the platform
//! guard, so its Drop never runs and the OS is left in exactly the state a crash
//! leaves: persistent WFP filters on Windows, a persisted pf token + snapshot
//! with the ruleset loaded on macOS. That is the production cutover path's own
//! crash-equivalent primitive, not a stand-in for one. What it does NOT reproduce
//! is the process boundary itself; `hole bridge unlock` is the only binary entry
//! point to a release and it resolves the real service state dir, which a test
//! must not clobber.
//!
//! Every reachability assertion is OUTBOUND egress to a routable IP, never
//! loopback: the GitHub Actions Windows runner drops inbound loopback to the test
//! exe, so a loopback probe cannot tell a working cover from a broken one. IP
//! literals only — the cover blocks DNS.
//!
//! Cross-binary serialization of the global WFP/pf state lives in
//! `.config/nextest.toml` (`global-net-state` test-group). COUPLED NAMES: that
//! group's filter matches by the `lockdown_lockout_` prefix — renaming it WITHOUT
//! updating the filter drops the test from the group (a silent cross-binary
//! race). Change both together.

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

/// An always-present interface used only as a LUID/name source, so the real
/// resolve path runs; no assertion depends on it.
#[cfg(target_os = "windows")]
const TUN_NAME: &str = "Loopback Pseudo-Interface 1";
#[cfg(target_os = "macos")]
const TUN_NAME: &str = "utun-absent";

/// The whole lockout, start to finish: a crash leaves the cover holding, the
/// bridge reports it truthfully with nothing running, and turning the kill switch
/// off actually opens the host.
///
/// Phase 5 is the posture guard — recovery must KEEP the host closed. Phase 8 is
/// the one rule #0 rests on: the user's action restores their network.
#[cfg(any(target_os = "windows", target_os = "macos"))]
#[skuld::test(labels = [TUN], serial = TUN)]
fn lockdown_lockout_survives_unclean_exit_and_release_opens_the_host() {
    use hole_bridge::proxy_manager::ProxyManager;
    use tun_engine::routing::failclosed::{engage_lockdown, lockdown_cover_state, lockdown_state, CoverState};
    use tun_engine::routing::failclosed::{lockdown_cover_present, SystemLuidResolver};
    use tun_engine::routing::{decide_cover_recovery, recover_routes, CoverGuard, CoverRecovery, SystemRouting};

    let dir = tempfile::tempdir().unwrap();
    let resolver = SystemLuidResolver;
    let server_ip: std::net::IpAddr = SERVER_IP.parse().unwrap();

    // 1. Baseline. A failure here is the network, not the cover.
    assert!(
        connect(PERMITTED).is_ok() && connect(NON_PERMITTED).is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): pre-cover baseline egress must reach both hosts"
    );

    // 2. A connected session with the kill switch armed.
    lockdown_state::set_enabled(dir.path(), true, None).unwrap();
    let cover = engage_lockdown(server_ip, TUN_NAME, &resolver, &[], dir.path(), None)
        .expect("engage the real standing lockdown cover");

    // 3. The unclean exit: the guard is forgotten, so nothing disengages.
    CoverGuard::disarm(cover);

    // 4. The lockout. This is the state #825 reported as "not engaged".
    assert_eq!(
        lockdown_cover_state(dir.path()),
        CoverState::Engaged,
        "the cover survives an unclean exit and is still holding the host"
    );
    assert!(
        connect(NON_PERMITTED).is_err(),
        "and it really is blocking: {NON_PERMITTED} must not connect"
    );

    // 5. Recovery keeps the host closed. A crash is when a leak is least
    //    acceptable, so pin the posture against a future change loosening it.
    assert_eq!(
        decide_cover_recovery(true, lockdown_cover_present(dir.path())),
        CoverRecovery::Adopt,
        "intent on + a cover present must Adopt"
    );
    recover_routes(dir.path());
    assert_eq!(
        lockdown_cover_state(dir.path()),
        CoverState::Engaged,
        "Adopt must keep the host fail-closed across the restart"
    );
    assert!(
        connect(NON_PERMITTED).is_err(),
        "the adopted cover still blocks: {NON_PERMITTED}"
    );

    // 6. The bridge reports the truth with nothing running — the tray's inputs.
    let pm = ProxyManager::new(
        hole_bridge::proxy::ShadowsocksProxy,
        SystemRouting::new(dir.path().to_path_buf(), None),
    )
    .with_state_dir(dir.path().to_path_buf());
    assert!(pm.lockdown_active(), "an adopted cover IS engaged");
    assert!(pm.held_closed(), "and no session owns it");

    // 7. The user's remedy.
    pm.set_lockdown_intent(false)
        .expect("turning the kill switch off must release the cover");

    // 8. It actually opened the host. The assertion rule #0 rests on.
    assert_eq!(
        lockdown_cover_state(dir.path()),
        CoverState::Absent,
        "the release must leave no cover engaged"
    );
    assert!(
        !lockdown_state::load_enabled(dir.path()),
        "and the intent is recorded off only because the release succeeded"
    );
    assert!(
        connect(NON_PERMITTED).is_ok(),
        "the user's network must be back: {NON_PERMITTED} must connect again"
    );
    assert!(!pm.lockdown_active(), "and the bridge agrees nothing is engaged");
    assert!(!pm.held_closed());
}
