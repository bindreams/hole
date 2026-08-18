//! Privileged-lane real-firewall proof that `release_all` clears every cover
//! Hole can install, unconditionally, and never touches a clean host's live
//! ruleset. Follows `lockdown_privileged_tests.rs`'s conventions closely (the
//! elevated TUN lane, the two-address reachability probe, baseline
//! self-validation) rather than re-deriving their rationale — see that
//! module's doc.
//!
//! Every test drives the PRODUCTION `Routing` impl (`SystemRouting`), engaging
//! through `Routing::install_lockdown` / `Routing::install_failclosed_cover`
//! and clearing through `Routing::release_all_covers` — proving both the
//! `failclosed::release_all` facade and the trait delegation in one pass.
//!
//! `CoverGuard::disarm` is `mem::forget`: after it there is no guard anywhere
//! to remove what a test installed, so a failing assertion between `disarm`
//! and the `release_all_covers` call under test would leave a system-wide
//! block-all in force with nothing to remove it. Every test that calls
//! `disarm` installs [`ReleaseOnDrop`] FIRST, so a panic (or an early return
//! from a failed assertion) during an unwind still clears the host.
//!
//! These tests share the `global-net-state` test-group with the bridge's
//! live-egress e2e and with `lockdown_privileged_tests`
//! (`.config/nextest.toml`) — a poisoned runner takes the rest of the job
//! down and reads as an unrelated network flake.
//!
//! COUPLED NAMES: every test name here contains the substring `release_all_`;
//! `.config/nextest.toml`'s `global-net-state` filter matches on it. Renaming
//! a test WITHOUT updating that filter silently drops it from the group.

use crate::routing::{CoverGuard, Routing, SystemRouting};

// `skuld` requires each label to be declared exactly once per test binary;
// both this module and `lockdown_privileged_tests` compile into the SAME
// `tun-engine` test binary, so this reuses that module's `TUN` label rather
// than redeclaring it (a second `#[skuld::label] const TUN` in one binary
// panics at test-runner startup with "label declared multiple times").
use super::lockdown_privileged_tests::TUN;

// Two routable anycast hosts on :443 (the runner has outbound internet), as
// `lockdown_privileged_tests` uses — see that module's doc for why these two
// addresses specifically.
#[cfg(any(target_os = "windows", target_os = "macos"))]
const PERMITTED: &str = "1.1.1.1:443";
#[cfg(any(target_os = "windows", target_os = "macos"))]
const NON_PERMITTED: &str = "8.8.8.8:443";

/// Removes anything the test stranded, on every exit path including an
/// unwind. `disarm` leaves no guard, so without this a failed assertion
/// leaves the runner globally fail-closed.
struct ReleaseOnDrop(std::path::PathBuf);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        // Must not panic during an unwind.
        let _ = crate::routing::failclosed::release_all(&self.0);
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn connect(addr: &str) -> std::io::Result<std::net::TcpStream> {
    std::net::TcpStream::connect_timeout(&addr.parse().unwrap(), std::time::Duration::from_secs(5))
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn assert_baseline_reachable() {
    let base_permitted = connect(PERMITTED);
    let base_non = connect(NON_PERMITTED);
    assert!(
        base_permitted.is_ok() && base_non.is_ok(),
        "NETWORK/ENVIRONMENT problem (not the cover): pre-cover baseline egress must reach both hosts; \
         {PERMITTED}={:?} {NON_PERMITTED}={:?}",
        base_permitted.err().map(|e| e.kind()),
        base_non.err().map(|e| e.kind()),
    );
}

// windows_release_all_clears_a_stranded_lockdown_cover / macos counterpart ============================================

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn windows_release_all_clears_a_stranded_lockdown_cover() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable();

    let cover = routing
        .install_lockdown(server_ip, "Loopback Pseudo-Interface 1", &[])
        .expect("engage real WFP lockdown cover");
    cover.disarm(); // strand it — no guard remains to remove it

    assert!(
        connect(NON_PERMITTED).is_err(),
        "the stranded lockdown cover must still be blocking egress"
    );

    routing
        .release_all_covers()
        .expect("release_all_covers must clear the stranded lockdown cover");

    assert!(
        connect(NON_PERMITTED).is_ok(),
        "release_all_covers must restore egress: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
}

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_release_all_clears_a_stranded_lockdown_cover() {
    use std::process::Command;

    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable();

    let cover = routing
        .install_lockdown(server_ip, "utun-absent", &[])
        .expect("engage real pf lockdown cover");
    cover.disarm();

    assert!(
        connect(NON_PERMITTED).is_err(),
        "the stranded lockdown cover must still be blocking egress"
    );

    routing
        .release_all_covers()
        .expect("release_all_covers must clear the stranded lockdown cover");

    assert!(
        connect(NON_PERMITTED).is_ok(),
        "release_all_covers must restore egress: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
    let sr = Command::new("pfctl").args(["-sr"]).output().unwrap();
    assert!(
        !String::from_utf8_lossy(&sr.stdout).contains("block drop out quick all"),
        "the lockdown block rule must be gone from the live ruleset"
    );
    assert!(
        !dir.path().join(super::lockdown_pf_state::STATE_FILE_NAME).exists(),
        "the lockdown state file must be cleared on a confirmed release"
    );
}

// windows_release_all_clears_a_stranded_transient_cover / macos counterpart ===========================================

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn windows_release_all_clears_a_stranded_transient_cover() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable();

    let cover = routing
        .install_failclosed_cover(server_ip, None)
        .expect("engage real WFP transient cover");
    cover.disarm();

    assert!(
        connect(NON_PERMITTED).is_err(),
        "the stranded transient cover must still be blocking egress"
    );

    routing
        .release_all_covers()
        .expect("release_all_covers must clear the stranded transient cover");

    assert!(
        connect(NON_PERMITTED).is_ok(),
        "release_all_covers must restore egress: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
}

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_release_all_clears_a_stranded_transient_cover() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable();

    let cover = routing
        .install_failclosed_cover(server_ip, None)
        .expect("engage real pf transient cover");
    cover.disarm();

    assert!(
        connect(NON_PERMITTED).is_err(),
        "the stranded transient cover must still be blocking egress"
    );

    routing
        .release_all_covers()
        .expect("release_all_covers must clear the stranded transient cover");

    assert!(
        connect(NON_PERMITTED).is_ok(),
        "release_all_covers must restore egress: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
    assert!(
        !dir.path().join(super::failclosed_state::STATE_FILE_NAME).exists(),
        "the transient state file must be cleared on a confirmed release"
    );
}

// windows_release_all_clears_both_stranded_covers / macos counterpart =================================================

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn windows_release_all_clears_both_stranded_covers() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable();

    let lockdown = routing
        .install_lockdown(server_ip, "Loopback Pseudo-Interface 1", &[])
        .expect("engage real WFP lockdown cover");
    lockdown.disarm();
    let transient = routing
        .install_failclosed_cover(server_ip, None)
        .expect("engage real WFP transient cover");
    transient.disarm();

    assert!(
        connect(NON_PERMITTED).is_err(),
        "both stranded covers must still be blocking egress"
    );

    routing
        .release_all_covers()
        .expect("release_all_covers must clear both stranded covers in one call");

    assert!(
        connect(NON_PERMITTED).is_ok(),
        "release_all_covers must restore egress: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
}

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_release_all_clears_both_stranded_covers() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable();

    let lockdown = routing
        .install_lockdown(server_ip, "utun-absent", &[])
        .expect("engage real pf lockdown cover");
    lockdown.disarm();
    let transient = routing
        .install_failclosed_cover(server_ip, None)
        .expect("engage real pf transient cover");
    transient.disarm();

    assert!(
        connect(NON_PERMITTED).is_err(),
        "both stranded covers must still be blocking egress"
    );

    routing
        .release_all_covers()
        .expect("release_all_covers must clear both stranded covers in one call");

    assert!(
        connect(NON_PERMITTED).is_ok(),
        "release_all_covers must restore egress: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
    assert!(!dir.path().join(super::lockdown_pf_state::STATE_FILE_NAME).exists());
    assert!(!dir.path().join(super::failclosed_state::STATE_FILE_NAME).exists());
}

// windows_release_all_on_a_clean_host_is_ok / macos counterpart =======================================================

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn windows_release_all_on_a_clean_host_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);

    assert_baseline_reachable();

    // Windows has no host-wide ruleset to compare (fixed compiled-in GUIDs, no
    // ambient policy): reachability is the only local signal available.
    routing.release_all_covers().expect("a clean host must return Ok");

    assert!(
        connect(NON_PERMITTED).is_ok(),
        "a clean host's reachability must be unaffected: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
}

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_release_all_on_a_clean_host_is_ok() {
    use std::process::Command;

    let dir = tempfile::tempdir().unwrap();
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);

    assert_baseline_reachable();

    // Compare only -sr / -sn (the RULES) and the enabled flag — `-s info`'s
    // counters move on their own and would make this test flaky for reasons
    // unrelated to the cover.
    let sr_before = Command::new("pfctl").args(["-sr"]).output().unwrap().stdout;
    let sn_before = Command::new("pfctl").args(["-sn"]).output().unwrap().stdout;
    let info_before = Command::new("pfctl").args(["-s", "info"]).output().unwrap().stdout;
    let enabled_before = super::platform::parse_pf_enabled(&String::from_utf8_lossy(&info_before));

    routing.release_all_covers().expect("a clean host must return Ok");

    let sr_after = Command::new("pfctl").args(["-sr"]).output().unwrap().stdout;
    let sn_after = Command::new("pfctl").args(["-sn"]).output().unwrap().stdout;
    let info_after = Command::new("pfctl").args(["-s", "info"]).output().unwrap().stdout;
    let enabled_after = super::platform::parse_pf_enabled(&String::from_utf8_lossy(&info_after));

    assert_eq!(
        sr_before, sr_after,
        "a clean host's live filter ruleset must be byte-identical afterward"
    );
    assert_eq!(
        sn_before, sn_after,
        "a clean host's live translation ruleset must be byte-identical afterward"
    );
    assert_eq!(
        enabled_before, enabled_after,
        "a clean host's pf-enabled flag must be unaffected"
    );
    assert!(
        connect(NON_PERMITTED).is_ok(),
        "a clean host's reachability must be unaffected: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
}

// macOS-only fault injections through Hole's own state file, touching no system file ==================================

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_release_all_clears_a_cover_whose_state_file_is_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable();

    let cover = routing
        .install_lockdown(server_ip, "utun-absent", &[])
        .expect("engage real pf lockdown cover");
    cover.disarm();

    // Corrupt Hole's own state file — not a system file — so the real
    // `load_presence` reads it as `Unusable`, not `Present`.
    std::fs::write(dir.path().join(super::lockdown_pf_state::STATE_FILE_NAME), b"not json").unwrap();

    routing
        .release_all_covers()
        .expect("an unreadable state file must still be treated as a cover to clear");

    assert!(
        connect(NON_PERMITTED).is_ok(),
        "release_all_covers must restore egress even with an unreadable state file: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
}

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn macos_release_all_falls_back_when_the_snapshot_will_not_load() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable();

    let cover = routing
        .install_lockdown(server_ip, "utun-absent", &[])
        .expect("engage real pf lockdown cover");
    cover.disarm();

    // Rewrite the state file as valid JSON at the current schema version, but
    // with a `main_snapshot` that is not something `pfctl -f -` will accept —
    // a REAL `pfctl` failure driving the real fallback, not a mock.
    let existing = super::lockdown_pf_state::load(dir.path()).expect("state file must exist after engage");
    let broken = super::lockdown_pf_state::LockdownPfState {
        main_snapshot: "this is not a valid pf ruleset {{{".into(),
        ..existing
    };
    super::lockdown_pf_state::save(dir.path(), &broken, None).unwrap();

    routing
        .release_all_covers()
        .expect("a snapshot that will not load must fall back to the default ruleset");

    assert!(
        connect(NON_PERMITTED).is_ok(),
        "release_all_covers must restore egress via the fallback: {NON_PERMITTED}={:?}",
        connect(NON_PERMITTED).err().map(|e| e.kind()),
    );
}
