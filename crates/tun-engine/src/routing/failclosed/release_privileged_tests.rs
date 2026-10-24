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
//! These tests share the `global_net_state` test-group with the bridge's
//! live-egress e2e and with `lockdown_privileged_tests`
//! (`.config/nextest.toml`) — a poisoned runner takes the rest of the job
//! down and reads as an unrelated network flake.
//!
//! COUPLED NAMES: every test name here contains the substring `release_all_`,
//! except `macos_recover_cover_clears_a_cover_whose_state_file_is_unreadable`
//! (the automatic sweep rather than the manual escape), which carries
//! `macos_recover_cover_`. `.config/nextest.toml`'s `global_net_state` filter
//! matches on both. Renaming a test WITHOUT updating that filter silently
//! drops it from the group.

#[cfg(any(target_os = "windows", target_os = "macos"))]
use super::cover_oracle::{held_covers, permit_scenario};
use crate::device::TunIdentity;
use crate::routing::{CoverGuard, Routing, SystemRouting};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use hole_test_observability::egress::InCover;

// `skuld` requires each label to be declared exactly once per test binary;
// every module under this crate compiles into the SAME `tun-engine` test
// binary, so both labels are declared once at the crate root and reused here
// rather than redeclared (a second `#[skuld::label] const TUN` — or
// `GLOBAL_NET_STATE` — in one binary panics at test-runner startup with
// "label declared multiple times").
#[cfg(target_os = "macos")]
use crate::test_utils::describe_output;
use crate::{GLOBAL_NET_STATE, TUN};
#[cfg(target_os = "macos")]
use util::system_tool::SystemTool;

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
///
/// It does NOT discard the release's verdict. This guard clears a system-wide
/// block-all it may be the last thing able to clear, and it runs on the exit
/// path of a test that had *already* decided something was wrong — so a
/// failure here is the difference between a host that was tidied up and a host
/// left with no egress. Swallowing it made "the sweep silently removed
/// nothing" and "the sweep worked" the same observation, which is the exact
/// failure class `release_all`'s "never a false success" clause exists to rule
/// out. It panics (failing the test) when it can, and prints when it cannot —
/// a panic during an unwind aborts the process, taking every other verdict in
/// this serialized lane with it.
struct ReleaseOnDrop(std::path::PathBuf);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        let Err(e) = crate::routing::failclosed::release_all(&self.0) else {
            return;
        };
        let msg = format!(
            "CLEANUP FAILED: release_all could not clear this test's cover ({e}); this host may still \
             be blocking all egress. Clear it with `hole bridge unlock`, elevated; `netsh wfp` \
             cannot — it is diagnostics-only and has no delete verb."
        );
        if std::thread::panicking() {
            eprintln!("{msg}");
        } else {
            panic!("{msg}");
        }
    }
}

/// The precondition every test starts from: egress is open and no cover is installed. A cover left by
/// an earlier test fails here at once instead of reading as a lost network.
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn assert_baseline_reachable(state_dir: &std::path::Path) {
    hole_test_observability::egress::wait_for_egress("pre-cover baseline", &[PERMITTED, NON_PERMITTED], &|| {
        held_covers(state_dir)
    });
}

/// `targets` answer again: a lost network is waited out, a cover that is still installed (or a block
/// with the network up) fails at once.
#[cfg(any(target_os = "windows", target_os = "macos"))]
#[track_caller]
fn assert_restored(what: &str, targets: &[&str], state_dir: &std::path::Path) {
    if let Err(why) = check_restored(what, targets, state_dir) {
        panic!("{why}");
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn check_restored(what: &str, targets: &[&str], state_dir: &std::path::Path) -> Result<(), String> {
    hole_test_observability::egress::check_egress_restored(what, targets, PERMITTED, &|| held_covers(state_dir))
}

/// Strands `what` with `engage`, probes that it still blocks (the server permit answers, `NON_PERMITTED`
/// does not), then clears it with `release_all_covers`. The cover is gone when the verdict is judged, as
/// the egress window requires; a lost network reruns the whole engage.
#[cfg(any(target_os = "windows", target_os = "macos"))]
#[track_caller]
fn release_stranded(what: &str, routing: &SystemRouting, state_dir: &std::path::Path, mut engage: impl FnMut()) {
    let claim = format!("{what} must still be blocking egress (leak!)");
    permit_scenario(
        "release_all of a stranded cover",
        state_dir,
        PERMITTED,
        &[NON_PERMITTED],
        || {
            engage();
            let verdict = InCover::new(PERMITTED, "the server-IP permit must beat the stranded block-all")
                .blocked(NON_PERMITTED, &claim)
                .run();
            routing
                .release_all_covers()
                .unwrap_or_else(|e| panic!("release_all_covers must clear {what}: {e}"));
            verdict
        },
    );
}

// windows_release_all_clears_a_stranded_lockdown_cover / macos counterpart ============================================

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn windows_release_all_clears_a_stranded_lockdown_cover() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable(dir.path());

    release_stranded("the stranded lockdown cover", &routing, dir.path(), || {
        let cover = routing
            .install_lockdown(
                server_ip,
                &TunIdentity::synthetic(0, "Loopback Pseudo-Interface 1"),
                &[],
            )
            .expect("engage real WFP lockdown cover");
        cover.disarm(); // strand it — no guard remains to remove it
    });

    assert_restored("release_all_covers must restore egress", &[NON_PERMITTED], dir.path());
}

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_release_all_clears_a_stranded_lockdown_cover() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable(dir.path());

    release_stranded("the stranded lockdown cover", &routing, dir.path(), || {
        let cover = routing
            .install_lockdown(server_ip, &TunIdentity::synthetic(0, "utun-absent"), &[])
            .expect("engage real pf lockdown cover");
        cover.disarm();
    });

    assert_restored("release_all_covers must restore egress", &[NON_PERMITTED], dir.path());
    let sr = SystemTool::Pfctl.command().unwrap().args(["-sr"]).output().unwrap();
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
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn windows_release_all_clears_a_stranded_transient_cover() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable(dir.path());

    release_stranded("the stranded transient cover", &routing, dir.path(), || {
        let cover = routing
            .install_failclosed_cover(server_ip, None)
            .expect("engage real WFP transient cover");
        cover.disarm();
    });

    assert_restored("release_all_covers must restore egress", &[NON_PERMITTED], dir.path());
}

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_release_all_clears_a_stranded_transient_cover() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable(dir.path());

    release_stranded("the stranded transient cover", &routing, dir.path(), || {
        let cover = routing
            .install_failclosed_cover(server_ip, None)
            .expect("engage real pf transient cover");
        cover.disarm();
    });

    assert_restored("release_all_covers must restore egress", &[NON_PERMITTED], dir.path());
    assert!(
        !dir.path().join(super::failclosed_state::STATE_FILE_NAME).exists(),
        "the transient state file must be cleared on a confirmed release"
    );
}

// windows_release_all_clears_both_stranded_covers / macos counterpart =================================================

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn windows_release_all_clears_both_stranded_covers() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable(dir.path());

    release_stranded("both stranded covers", &routing, dir.path(), || {
        let lockdown = routing
            .install_lockdown(
                server_ip,
                &TunIdentity::synthetic(0, "Loopback Pseudo-Interface 1"),
                &[],
            )
            .expect("engage real WFP lockdown cover");
        lockdown.disarm();
        let transient = routing
            .install_failclosed_cover(server_ip, None)
            .expect("engage real WFP transient cover");
        transient.disarm();
    });

    assert_restored("release_all_covers must restore egress", &[NON_PERMITTED], dir.path());
}

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_release_all_clears_both_stranded_covers() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable(dir.path());

    release_stranded("both stranded covers", &routing, dir.path(), || {
        let lockdown = routing
            .install_lockdown(server_ip, &TunIdentity::synthetic(0, "utun-absent"), &[])
            .expect("engage real pf lockdown cover");
        lockdown.disarm();
        let transient = routing
            .install_failclosed_cover(server_ip, None)
            .expect("engage real pf transient cover");
        transient.disarm();
    });

    assert_restored("release_all_covers must restore egress", &[NON_PERMITTED], dir.path());
    assert!(!dir.path().join(super::lockdown_pf_state::STATE_FILE_NAME).exists());
    assert!(!dir.path().join(super::failclosed_state::STATE_FILE_NAME).exists());
}

// release_all_leaves_nothing_the_oracle_can_see =======================================================================

/// The TUN the lockdown cover is engaged against: absent from the host, so the cover blocks everything
/// but its server permit.
#[cfg(any(target_os = "windows", target_os = "macos"))]
const COVER_TUN: &str = if cfg!(windows) {
    "Loopback Pseudo-Interface 1"
} else {
    "utun-absent"
};

/// The oracle the egress waits take as `HoleState` reads the OS, not the engaging test's records: a
/// cover stranded under one state directory is seen from another, and a confirmed release leaves
/// nothing to see. Without this, a leaked cover from an earlier test reads as a lost network.
#[cfg(any(target_os = "windows", target_os = "macos"))]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn release_all_leaves_nothing_the_oracle_can_see() {
    let dir = tempfile::tempdir().unwrap();
    let stranger = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable(stranger.path());

    let lockdown = routing
        .install_lockdown(server_ip, &TunIdentity::synthetic(0, COVER_TUN), &[])
        .expect("engage the real lockdown cover");
    lockdown.disarm();
    assert!(
        held_covers(stranger.path()).is_some(),
        "a stranded lockdown cover must be visible from a state directory that never engaged it"
    );
    routing
        .release_all_covers()
        .expect("release_all_covers must clear the stranded lockdown cover");
    assert_eq!(
        held_covers(stranger.path()),
        None,
        "nothing may be left after the lockdown cover is released"
    );

    let transient = routing
        .install_failclosed_cover(server_ip, None)
        .expect("engage the real transient cover");
    transient.disarm();
    assert!(
        held_covers(stranger.path()).is_some(),
        "a stranded transient cover must be visible from a state directory that never engaged it"
    );
    routing
        .release_all_covers()
        .expect("release_all_covers must clear the stranded transient cover");
    assert_eq!(
        held_covers(stranger.path()),
        None,
        "nothing may be left after the transient cover is released"
    );
}

/// A release that cleared the record but left pf blocking: the record is the only thing the engaging
/// directory can show, so the oracle must read the live ruleset.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_release_all_sees_a_transient_cover_whose_record_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable(dir.path());

    let cover = routing
        .install_failclosed_cover(server_ip, None)
        .expect("engage the real pf transient cover");
    cover.disarm();
    let record_path = dir.path().join(super::failclosed_state::STATE_FILE_NAME);
    let record = std::fs::read(&record_path).expect("the engage must have written its record");
    std::fs::remove_file(&record_path).unwrap();

    let held = held_covers(dir.path());

    // Put the record back first: the release reads it for the pf enable token it must drop.
    std::fs::write(&record_path, record).unwrap();
    routing
        .release_all_covers()
        .expect("release_all_covers must clear the stranded transient cover");

    let held = held.expect("pf still blocks with the record gone, so the oracle must still report the cover");
    // The answer must come from the live ruleset: not from a record (there is none) and not from a pf
    // that could not be asked, which would also read as held.
    assert!(held.contains("the live pf ruleset has a block rule"), "{held}");
    assert!(!held.contains("its state record exists"), "{held}");
    assert!(!held.contains("pf could not be asked"), "{held}");
}

// windows_release_all_on_a_clean_host_is_ok / macos counterpart =======================================================

#[cfg(target_os = "windows")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn windows_release_all_on_a_clean_host_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);

    assert_baseline_reachable(dir.path());

    // Windows has no host-wide ruleset to compare (fixed compiled-in GUIDs, no
    // ambient policy): reachability is the only local signal available.
    routing.release_all_covers().expect("a clean host must return Ok");

    assert_restored(
        "a clean host's reachability must be unaffected",
        &[NON_PERMITTED],
        dir.path(),
    );
    assert_eq!(
        super::lockdown_cover_presence(dir.path()),
        crate::routing::CoverPresence::Absent,
        "the firewall must report no lockdown cover after a clean-host release"
    );
}

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_release_all_on_a_clean_host_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);

    assert_baseline_reachable(dir.path());

    // Compare only -sr / -sn (the RULES) and the enabled flag — `-s info`'s
    // counters move on their own and would make this test flaky for reasons
    // unrelated to the cover.
    let sr_before = SystemTool::Pfctl
        .command()
        .unwrap()
        .args(["-sr"])
        .output()
        .unwrap()
        .stdout;
    let sn_before = SystemTool::Pfctl
        .command()
        .unwrap()
        .args(["-sn"])
        .output()
        .unwrap()
        .stdout;
    let info_before = SystemTool::Pfctl
        .command()
        .unwrap()
        .args(["-s", "info"])
        .output()
        .unwrap()
        .stdout;
    let enabled_before = super::platform::parse_pf_enabled(&String::from_utf8_lossy(&info_before));

    routing.release_all_covers().expect("a clean host must return Ok");

    let sr_after = SystemTool::Pfctl
        .command()
        .unwrap()
        .args(["-sr"])
        .output()
        .unwrap()
        .stdout;
    let sn_after = SystemTool::Pfctl
        .command()
        .unwrap()
        .args(["-sn"])
        .output()
        .unwrap()
        .stdout;
    let info_after = SystemTool::Pfctl
        .command()
        .unwrap()
        .args(["-s", "info"])
        .output()
        .unwrap()
        .stdout;
    let enabled_after = super::platform::parse_pf_enabled(&String::from_utf8_lossy(&info_after));

    assert_eq!(
        super::lockdown_cover_presence(dir.path()),
        crate::routing::CoverPresence::Absent,
        "pf must report no lockdown cover after a clean-host release"
    );
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
    assert_restored(
        "a clean host's reachability must be unaffected",
        &[NON_PERMITTED],
        dir.path(),
    );
}

// macOS-only fault injections through Hole's own state file, touching no system file ==================================

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_release_all_clears_a_cover_whose_state_file_is_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable(dir.path());

    let cover = routing
        .install_lockdown(server_ip, &TunIdentity::synthetic(0, "utun-absent"), &[])
        .expect("engage real pf lockdown cover");
    cover.disarm();

    // Corrupt Hole's own state file — not a system file — so the real
    // `load_presence` reads it as `Unusable`, not `Present`.
    std::fs::write(dir.path().join(super::lockdown_pf_state::STATE_FILE_NAME), b"not json").unwrap();

    routing
        .release_all_covers()
        .expect("an unreadable state file must still be treated as a cover to clear");

    assert_restored(
        "release_all_covers must restore egress even with an unreadable state file",
        &[NON_PERMITTED],
        dir.path(),
    );
}

/// The automatic sweep's half of the same rule the test above proves for the
/// manual escape: an UNREADABLE record is a cover to clear, not an absence.
///
/// `recover_cover` used to go through `failclosed_state::load`, which collapses
/// `Unusable` into `None` alongside `Absent`, and then logged "no
/// failclosed-state file, nothing to recover" over a host still behind
/// `block out all`. The reachable production cause is a ROLLBACK, and the
/// payload below is the vector of it THIS binary classifies as `Unusable`: a
/// record one schema version ahead, as a newer bridge writes and a rolled-back
/// one reads.
///
/// The classification is asserted, not assumed: a payload that quietly parses
/// takes the `Present` arm, which `recover_cover` handled identically before
/// `Unusable` existed, and this test would then pass against the very
/// regression it exists to catch.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_recover_cover_clears_a_cover_whose_state_file_is_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable(dir.path());

    // Best-effort and AFTER the sweep: the sweep salvages the `pf_token` out of the unusable record
    // itself and drops it, so this normally finds the refcount already released and fails harmlessly.
    // It stays so that a sweep whose own `-X` failed cannot leave the runner's pf enabled under an
    // unreferenced token until reboot; a `-X` that succeeds here is that case and is logged as one.
    let drop_token = |token: &str| match SystemTool::Pfctl.command().unwrap().args(["-X", token]).output() {
        Ok(out) if out.status.success() => {
            tracing::warn!(
                "recover_cover left pf token {token} held: the test dropped it ({})",
                describe_output(&out)
            );
        }
        Ok(out) => tracing::debug!("pfctl -X {token} after the sweep: {}", describe_output(&out)),
        Err(e) => tracing::warn!("pfctl -X {token} could not be spawned: {e}"),
    };

    let token = permit_scenario(
        "recover_cover of an unreadable record",
        dir.path(),
        PERMITTED,
        &[NON_PERMITTED],
        || {
            // The TRANSIENT cover — `recover_cover`'s subject.
            let cover = routing
                .install_failclosed_cover(server_ip, None)
                .expect("engage real pf transient cover");
            // Read the real enable token back BEFORE overwriting the file, so the rolled-back payload
            // below carries the REAL token and the safety net has one to fall back on.
            let token = super::failclosed_state::load(dir.path())
                .expect("the engage must have persisted a state file")
                .pf_token;
            cover.disarm(); // stand in for the crash: no guard remains

            let rolled_back = format!(
                r#"{{"version":{},"pf_token":"{token}","pf_was_enabled":false}}"#,
                super::failclosed_state::SCHEMA_VERSION + 1
            );
            std::fs::write(dir.path().join(super::failclosed_state::STATE_FILE_NAME), &rolled_back).unwrap();
            let presence = super::failclosed_state::load_presence(dir.path());
            assert!(
                matches!(presence, super::StateFile::Unusable { .. }),
                "this test's premise: the payload must be UNREADABLE to this binary. On `Present` the \
             sweep takes the arm it handled before this fix and proves nothing: {rolled_back} -> \
             {presence:?}"
            );

            let verdict = InCover::new(PERMITTED, "the server-IP permit must beat the stranded block-all")
                .blocked(
                    NON_PERMITTED,
                    "the stranded transient cover must still be blocking egress before the sweep runs (leak!)",
                )
                .run();

            crate::routing::failclosed::recover_cover(dir.path(), false);

            // The cover is gone before the verdict is judged; a rerun engages a new token.
            verdict.inspect_err(|_| drop_token(&token)).map(|()| token)
        },
    );

    let restored = check_restored(
        "recover_cover must restore egress even with an unreadable state file",
        &[NON_PERMITTED],
        dir.path(),
    );
    drop_token(&token);

    if let Err(why) = restored {
        panic!("{why}");
    }
}

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn macos_release_all_falls_back_when_the_snapshot_will_not_load() {
    let dir = tempfile::tempdir().unwrap();
    let _release_guard = ReleaseOnDrop(dir.path().to_path_buf());
    let routing = SystemRouting::new(dir.path().to_path_buf(), None);
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    assert_baseline_reachable(dir.path());

    let cover = routing
        .install_lockdown(server_ip, &TunIdentity::synthetic(0, "utun-absent"), &[])
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

    assert_restored(
        "release_all_covers must restore egress via the fallback",
        &[NON_PERMITTED],
        dir.path(),
    );
}
