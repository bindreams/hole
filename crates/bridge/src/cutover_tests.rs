use super::*;

#[skuld::test]
fn service_state_dir_matches_install_convention() {
    let d = service_state_dir();
    #[cfg(target_os = "windows")]
    assert!(
        d.ends_with("hole\\state") || d.ends_with("hole/state"),
        "windows service state dir under ProgramData\\hole\\state: {d:?}"
    );
    #[cfg(not(target_os = "windows"))]
    assert_eq!(d, std::path::PathBuf::from("/var/db/hole/state"));
}

// `bridge unlock` ordering: the escape hatch must actually disengage the cover
// before flipping intent off, or fail loud. A swallowed disengage failure would
// leave the cover engaged (egress blocked) while intent reads off — misleading.
use tun_engine::routing::failclosed::lockdown_state;

#[skuld::test]
fn unlock_failing_disengage_does_not_flip_intent() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::set_enabled(dir.path(), true, None).unwrap();

    let result = unlock_with(dir.path(), || {
        Err(std::io::Error::other("cannot disengage / not elevated"))
    });

    assert!(result.is_err(), "unlock must fail loud when it cannot disengage");
    assert!(
        lockdown_state::load_enabled(dir.path()),
        "intent must stay ON when the cover could not be disengaged"
    );
}

#[skuld::test]
fn unlock_successful_disengage_flips_intent_off() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::set_enabled(dir.path(), true, None).unwrap();

    let result = unlock_with(dir.path(), || Ok(()));

    assert!(result.is_ok());
    assert!(
        !lockdown_state::load_enabled(dir.path()),
        "intent flips off only after a confirmed disengage"
    );
}

// `bridge unlock` vs. a live bridge (#840): the CLI escape and the in-app
// "Unblock Network" action must not race each other over the same cover. A
// live bridge already owns reconciliation (and will reconcile the target
// itself); `unlock` must refuse rather than race it, and name the in-app
// action as the alternative.

#[skuld::test]
fn unlock_refuses_against_a_live_bridge() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::set_enabled(dir.path(), true, None).unwrap();

    // Simulate a live bridge with the same lock a running bridge holds for
    // its whole lifetime — real contention, not a mocked probe.
    let _bridge = crate::liveness::BridgeLiveness::acquire(dir.path(), None).unwrap();

    let result = unlock_with(dir.path(), || {
        panic!("disengage must never run while a bridge instance is live")
    });

    let err = result.expect_err("unlock must refuse while a bridge instance is running");
    assert!(
        err.to_string().contains("Unblock Network"),
        "must name the in-app action as the alternative: {err}"
    );
    assert!(
        lockdown_state::load_enabled(dir.path()),
        "a refused unlock must not touch the persisted intent"
    );
}

#[skuld::test]
fn unlock_records_the_target_off_before_releasing() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::set_enabled(dir.path(), true, None).unwrap();

    let result = unlock_with(dir.path(), || {
        assert_eq!(
            crate::target::load(dir.path()),
            crate::target::Target::Off,
            "target must already be recorded off before the release call"
        );
        Ok(())
    });

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(crate::target::load(dir.path()), crate::target::Target::Off);
}

// #986: the liveness exclusion is structural (a lock held across the whole
// sequence), not a point-in-time probe — a bridge that would start mid-unlock
// must observe the lock as held throughout, not just at the initial check.

#[skuld::test]
fn unlock_holds_the_liveness_lock_across_the_whole_sequence() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::set_enabled(dir.path(), true, None).unwrap();

    let result = unlock_with(dir.path(), || {
        // A bridge "starting" here — anywhere between the initial check and
        // the intent flip — must see the lock held, never a window where it
        // could acquire it and race the disengage/intent-flip below.
        assert!(
            crate::liveness::BridgeLiveness::try_acquire(dir.path(), None)
                .unwrap()
                .is_none(),
            "a bridge starting mid-unlock must contend on the same lock, not observe it free"
        );
        Ok(())
    });

    assert!(result.is_ok(), "{result:?}");
    // Released once `unlock_with` returns.
    assert!(crate::liveness::BridgeLiveness::try_acquire(dir.path(), None)
        .unwrap()
        .is_some());
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn clear_marker_on_failure_clears_only_on_err() {
    let dir = tempfile::tempdir().unwrap();
    let m = hole_common::update_marker::MarkerInfo {
        version: hole_common::update_marker::MARKER_VERSION,
        driver: cosca::identity::ProcessId::current()
            .to_record()
            .expect("persist this process's identity"),
    };
    hole_common::update_marker::write(dir.path(), &m, None).unwrap();
    clear_marker_on_cutover_failure(&Ok(()), dir.path());
    assert!(hole_common::update_marker::is_present(dir.path()));
    clear_marker_on_cutover_failure(&Err(std::io::Error::other("boom")), dir.path());
    assert!(!hole_common::update_marker::is_present(dir.path()));
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn find_staged_exe_locates_hole_exe_in_nested_tree() {
    // The payload is a flat archive; the recursive walk is defense-in-depth
    // against a non-flat layout, so the finder must recurse rather than look at a
    // fixed depth. Nest the exe to exercise that recursion.
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("PFiles").join("hole");
    std::fs::create_dir_all(&nested).unwrap();
    let exe = nested.join("hole.exe");
    std::fs::write(&exe, b"stub").unwrap();
    let found = extract::find_staged_exe(dir.path()).unwrap();
    assert_eq!(found, exe);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn find_staged_exe_errs_when_absent() {
    let dir = tempfile::tempdir().unwrap();
    assert!(extract::find_staged_exe(dir.path()).is_err());
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn find_staged_terminates_through_a_directory_symlink_cycle() {
    // Integration smoke test: a self-referential directory symlink must not
    // recurse forever. Search for an absent name so the search is FORCED to
    // traverse the whole cyclic tree.
    let root = tempfile::tempdir().unwrap();
    let sub = root.path().join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    // sub/loop -> root: descending into `loop` re-enters root → a cycle.
    std::os::windows::fs::symlink_dir(root.path(), sub.join("loop")).unwrap();

    let missing = extract::find_staged(root.path(), "does-not-exist.exe");
    assert!(missing.is_err(), "absent name must error (not recurse forever)");
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn find_file_inner_skips_an_already_visited_canonical_dir() {
    use std::collections::HashSet;

    // Deterministic proof the guard is load-bearing: a directory whose canonical
    // path is already in `visited` is NOT traversed, so the file it contains is
    // NOT found. This is the cycle break (revisiting a canonical path is a no-op),
    // independent of OS path-length limits.
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::write(real.join("hole.exe"), b"stub").unwrap();
    let canon = std::fs::canonicalize(&real).unwrap();

    let mut visited = HashSet::new();
    // Not yet visited: the file is found.
    let found = extract::find_file_inner(&real, "hole.exe", &mut visited).unwrap();
    assert!(found.is_some(), "first visit finds the file");

    // Already visited (canonical path present): the dir is skipped, not re-walked.
    let mut seeded = HashSet::from([canon]);
    let skipped = extract::find_file_inner(&real, "hole.exe", &mut seeded).unwrap();
    assert!(skipped.is_none(), "an already-visited canonical dir is not traversed");
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn plan_windows_images_covers_full_bindir_set() {
    use std::collections::BTreeSet;

    // The Windows cutover must swap EVERY bundled binary (a release that updates
    // the plugin/driver must not leave them stale), keyed on the single source
    // of truth — NOT a hand-listed copy.
    let names = xtask_lib::bindir::bindir_dest_names(xtask_lib::bindir::Os::Windows);

    // The payload is a flat archive; the recursive walk is defense-in-depth
    // against a non-flat layout, so stage every file under nested dirs to
    // exercise that recursion.
    let staging = tempfile::tempdir().unwrap();
    let nested = staging.path().join("PFiles").join("hole");
    std::fs::create_dir_all(&nested).unwrap();
    for name in &names {
        std::fs::write(nested.join(name), b"stub").unwrap();
    }

    let install_dir = Path::new(r"C:\Program Files\hole");
    let images = plan_windows_images(install_dir, staging.path(), &names).unwrap();

    let installed_names: BTreeSet<String> = images
        .iter()
        .map(|img| img.installed.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    let expected: BTreeSet<String> = names.iter().cloned().collect();
    assert_eq!(
        installed_names, expected,
        "swap set must cover the full bindir-names set"
    );

    for img in &images {
        assert!(
            img.installed.starts_with(install_dir),
            "installed under the install dir"
        );
        assert!(img.staged.exists(), "staged source resolved: {:?}", img.staged);
    }
}

// `bridge release-covers` (the uninstaller's escape) shares `unlock`'s
// ordering over a wider reach — both cover kinds. It records the target off
// FIRST, so a release that never lands still converges: a later start
// reconciles toward `Off` and sweeps. And it refuses against a live bridge for
// the same reason `unlock` does — an out-of-process clear would leave the
// bridge's posture claiming a cover that no longer exists (#1003).

/// `release_covers_with` with no peer dirs, for the assertions about the
/// sequencing around the release itself.
fn release_covers_probe(dir: &std::path::Path, release: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> {
    // These probes are about the sequencing around the release (liveness,
    // target write), not about what the sweep proved — so they hand it
    // the fully-proven clearance and drop it again. The propagation itself is
    // pinned by `release_covers_reports_what_the_sweep_could_not_prove`.
    release_covers_with(dir, &[], || release().map(|()| Clearance::proven())).map(|_| ())
}

#[skuld::test]
fn release_covers_refuses_against_a_live_bridge() {
    let dir = tempfile::tempdir().unwrap();

    let _bridge = crate::liveness::BridgeLiveness::acquire(dir.path(), None).unwrap();

    let result = release_covers_probe(dir.path(), || {
        panic!("the release must never run while a bridge instance is live")
    });

    result.expect_err("release-covers must refuse while a bridge instance is running");
}

/// The covers `release_all` sweeps are machine-wide (Windows keys them on
/// compile-time GUIDs), but the liveness lock is per-state-dir. A bridge run
/// with a different `--state-dir` — which is what `cli.rs` gives every
/// foreground and elevated non-`--service` run — holds a lock the service dir
/// knows nothing about, and clearing its filters out from under it leaves its
/// posture claiming covers that no longer exist.
#[skuld::test]
fn release_covers_refuses_against_a_bridge_live_in_a_peer_state_dir() {
    let service = tempfile::tempdir().unwrap();
    let peer = tempfile::tempdir().unwrap();

    let _bridge = crate::liveness::BridgeLiveness::acquire(peer.path(), None).unwrap();

    let result = release_covers_with(service.path(), &[peer.path().to_path_buf()], || {
        panic!("the release must never run while a bridge instance is live")
    });

    result.expect_err("a bridge alive in a peer state dir must refuse the release too");
}

/// The exclusion is what this function IS, so it is taken over every peer
/// unconditionally — a peer whose dir is not there yet is the one an absent
/// lock hurts most. `release_all` sweeps Windows' covers machine-wide, so a
/// bridge that starts under that account mid-release engages a cover, records
/// the posture, has the filters deleted underneath it, and skips
/// re-engagement on its next covered start: a VPN running uncovered.
#[skuld::test]
fn release_covers_locks_a_peer_state_dir_that_is_not_there_yet() {
    let service = tempfile::tempdir().unwrap();
    let absent = service.path().join("no-such-user").join("state");

    let result = release_covers_with(service.path(), std::slice::from_ref(&absent), || {
        assert!(
            crate::liveness::BridgeLiveness::try_acquire(&absent, None)
                .unwrap()
                .is_none(),
            "a bridge starting under an account with no state dir yet must contend on the \
                 same lock, not find it free"
        );
        Ok(Clearance::proven())
    });

    assert!(result.is_ok(), "{result:?}");
}

/// The litter the lock above costs, and why it is kept. The peer locks are
/// released when this call returns, and every bridge takes its own with the
/// BLOCKING `BridgeLiveness::acquire` — so the bridge this exclusion exists to
/// keep out is woken by that release and writes `bridge-lockdown.json` into the
/// very tree a cleanup would then remove. A cover with no record is the end
/// state the whole uninstall path exists to prevent, so nothing under a peer
/// dir is removed: an empty dir holding a lock file is litter, a stranded
/// persistent cover is not recoverable in-band.
#[skuld::test]
fn release_covers_leaves_every_peer_tree_it_provisioned() {
    let service = tempfile::tempdir().unwrap();
    let profile = service.path().join("no-such-user");
    let peer = profile.join("state");

    let result = release_covers_with(service.path(), std::slice::from_ref(&peer), || Ok(Clearance::proven()));

    assert!(result.is_ok(), "{result:?}");
    assert!(
        peer.join("bridge-liveness.lock").exists(),
        "the release must remove nothing under a peer dir: the lock it took there is released \
         before it returns, so anything it deleted afterwards could belong to the bridge that \
         woke on that release"
    );
}

/// A peer path can run through a symlink — a state dir relocated onto a volume
/// that is not mounted at uninstall time, or a redirected Windows profile.
///
/// A tripwire, by construction: there is no removal code for it to reach, and
/// that is the property. It catches the shape that was there before — an
/// existence probe that follows links (`try_exists`) reads a dangling one as
/// absent, names it as a level this call is about to create, and hands it to a
/// `remove_dir_all` that does NOT follow links and so removes the link itself,
/// one level above anything Hole owns.
#[cfg(unix)]
#[skuld::test]
fn release_covers_never_removes_a_symlink_on_a_peer_path() {
    let service = tempfile::tempdir().unwrap();
    let base = tempfile::tempdir().unwrap();
    let link = base.path().join("profile");
    std::os::unix::fs::symlink(base.path().join("volume-not-mounted"), &link).unwrap();

    let result = release_covers_with(service.path(), &[link.join("hole").join("state")], || {
        Ok(Clearance::proven())
    });

    assert!(result.is_ok(), "{result:?}");
    assert!(
        std::fs::symlink_metadata(&link).is_ok(),
        "a dangling symlink on a peer path reads absent to anything that follows links; \
         removing it takes out a user's relocation, one level above anything Hole owns"
    );
}

/// The same rule from the other side, and the one that was never in doubt: a
/// peer dir that was already there belongs to the account that owns it, and its
/// crash-recovery records are that bridge's, not this call's to delete.
#[skuld::test]
fn release_covers_leaves_a_peer_state_dir_that_was_already_there() {
    let service = tempfile::tempdir().unwrap();
    let peer = tempfile::tempdir().unwrap();
    let record = peer.path().join("bridge-routes.json");
    std::fs::write(&record, b"{}").unwrap();

    let result = release_covers_with(service.path(), &[peer.path().to_path_buf()], || Ok(Clearance::proven()));

    assert!(result.is_ok(), "{result:?}");
    assert!(
        record.exists(),
        "a pre-existing peer state dir is not this call's to remove"
    );
}

/// The liveness lock contends per open handle, not per owning process, so a
/// path probed twice would refuse against this call's OWN guard. Duplicates are
/// ordinary: an un-elevated run resolves `default_state_dir` and the real
/// user's dir to one and the same path, and the service dir can appear in the
/// peer list too.
#[skuld::test]
fn release_covers_does_not_refuse_against_its_own_guard() {
    let service = tempfile::tempdir().unwrap();
    let peer = tempfile::tempdir().unwrap();
    let peers = vec![
        service.path().to_path_buf(),
        peer.path().to_path_buf(),
        peer.path().to_path_buf(),
    ];

    let result = release_covers_with(service.path(), &peers, || Ok(Clearance::proven()));

    assert!(
        result.is_ok(),
        "a repeated peer path must not read as a live bridge: {result:?}"
    );
}

#[skuld::test]
fn release_covers_records_the_target_off_before_releasing() {
    let dir = tempfile::tempdir().unwrap();

    let result = release_covers_probe(dir.path(), || {
        assert_eq!(
            crate::target::load(dir.path()),
            crate::target::Target::Off,
            "target must already be recorded off before the release call"
        );
        Ok(())
    });

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(crate::target::load(dir.path()), crate::target::Target::Off);
}

#[skuld::test]
fn release_covers_fails_loud_when_it_cannot_release() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::set_enabled(dir.path(), true, None).unwrap();

    let result = release_covers_probe(dir.path(), || Err(std::io::Error::other("not elevated")));

    assert!(
        result.is_err(),
        "a failed release must abort before RemoveFiles deletes the only binary that could retry it"
    );
    assert!(
        lockdown_state::load_enabled(dir.path()),
        "the legacy intent must not read disarmed over a host still covered"
    );
}

#[skuld::test]
fn release_covers_disarms_the_kill_switch_on_a_confirmed_release() {
    let dir = tempfile::tempdir().unwrap();
    lockdown_state::set_enabled(dir.path(), true, None).unwrap();

    let result = release_covers_probe(dir.path(), || Ok(()));

    assert!(result.is_ok());
    assert!(
        !lockdown_state::load_enabled(dir.path()),
        "a confirmed release must disarm, not leave the switch armed over an open host"
    );
}

/// The release writes records; it deletes none. `scripts/network-reset.py` —
/// the out-of-band escape, whose whole reason to exist is a host with no
/// working bridge — reads `bridge-routes.json` and `bridge-dns{,.superseded}
/// .json` straight out of `service_state_dir()`, and `plugin_recovery`'s record
/// may be deleted only by something that has accounted for every plugin in it.
/// An uninstall is the one moment the in-band escapes are already gone:
/// deleting these would leave a leaked bypass route, a rewritten adapter's DNS
/// and orphaned plugin processes on the host with the only record of how to
/// undo them destroyed by the uninstall itself.
#[skuld::test]
fn release_covers_deletes_no_crash_recovery_record() {
    const ESCAPE_RECORDS: [&str; 4] = [
        "bridge-routes.json",
        "bridge-dns.json",
        "bridge-dns.superseded.json",
        "bridge-plugins.json",
    ];
    let dir = tempfile::tempdir().unwrap();
    for name in ESCAPE_RECORDS {
        std::fs::write(dir.path().join(name), b"{}").unwrap();
    }

    let result = release_covers_with(dir.path(), &[], || Ok(Clearance::proven()));

    assert!(result.is_ok(), "{result:?}");
    for name in ESCAPE_RECORDS {
        assert!(
            dir.path().join(name).exists(),
            "{name} is what the out-of-band escape reads; the uninstall that makes it the only \
             escape left must not be what deletes it"
        );
    }
}

// Peer state dirs -----------------------------------------------------------------------------------------------------
//
// The liveness probe's reach. A peer set that resolves to nothing is not a
// quiet degradation: `release_covers_with` reads "no lock held anywhere" and
// clears machine-wide WFP filters out from under a live bridge whose posture
// still claims them. The whole check silently passes.

#[skuld::test]
fn the_windows_profile_mapping_is_the_local_appdata_layout() {
    // `%LOCALAPPDATA%` is `<profile>\AppData\Local`, so a profile maps to the
    // same leaf `default_state_dir()` builds for the account that owns it.
    // Compiled everywhere — it is a pure join, and pinning it only on Windows
    // would put the proof on the one lane that already has the platform test
    // below.
    let mapped = hole_common::paths::windows_profile_state_dir(std::path::Path::new("C:/Users/alice"));
    assert_eq!(
        mapped,
        std::path::PathBuf::from("C:/Users/alice")
            .join("AppData")
            .join("Local")
            .join("hole")
            .join("state")
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn the_windows_peer_mapping_matches_what_a_bridge_resolves() {
    // Falsifies the mapping against the real resolver rather than restating
    // it: a bridge started by this account resolves its state dir through
    // `default_state_dir()` (i.e. `dirs::data_local_dir`), and the peer probe
    // has to arrive at the same path from the profile directory alone. If the
    // two ever diverge the probe looks in the wrong place and always passes.
    let profile = std::path::PathBuf::from(std::env::var("USERPROFILE").expect("USERPROFILE"));
    assert_eq!(
        hole_common::paths::windows_profile_state_dir(&profile),
        hole_common::paths::default_state_dir()
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn the_windows_peer_set_reaches_accounts_other_than_this_process() {
    // A peer set that resolves to only this process's own dir is
    // indistinguishable from `release_covers_with`'s already-probed skip, and
    // the probe reports no other bridges every time.
    let dirs = peer_state_dirs();
    let profile = std::path::PathBuf::from(std::env::var("USERPROFILE").expect("USERPROFILE"));
    assert!(
        dirs.contains(&hole_common::paths::windows_profile_state_dir(&profile)),
        "the profile enumeration must reach this host's real profiles: {dirs:?}"
    );
}

// Release clearance ---------------------------------------------------------------------------------------------------
//
// `bridge release-covers` is the last moment `hole.exe` exists on an
// uninstalling host. What it reports here is all that survives `RemoveFiles`.

use tun_engine::routing::failclosed::{KeyLifetime, KeyObservation, KeyOutcome};

fn unproven_clearance(keys: &[&'static str]) -> Clearance {
    let obs: Vec<KeyObservation> = keys
        .iter()
        .map(|&key| KeyObservation {
            key,
            lifetime: KeyLifetime::BootTime,
            outcome: KeyOutcome::NotFound,
        })
        .collect();
    Clearance::from_observations(&obs)
}

#[skuld::test]
fn release_covers_reports_what_the_sweep_could_not_prove() {
    // The propagation itself: `release_covers_with` must hand the caller the
    // sweep's verdict, not a bare `Ok`. Collapsing it here would put the
    // silent `Ok` of #1003 back one layer up from where it was removed.
    let dir = tempfile::tempdir().unwrap();
    let clearance = release_covers_with(dir.path(), &[], || {
        Ok(unproven_clearance(&["lockdown boot-time block-all V4"]))
    })
    .expect("an unproven clearance is not a failure");

    assert!(!clearance.is_proven());
    assert_eq!(clearance.unproven_keys(), ["lockdown boot-time block-all V4"]);
}

#[skuld::test]
fn a_proven_release_says_nothing_extra() {
    // The common case by far — no cover, or one this sweep watched go away. A
    // warning here would train operators to ignore the one that matters.
    assert_eq!(release_clearance_report(&Clearance::proven()), None);
}

#[skuld::test]
fn an_unproven_release_names_the_keys_and_a_command_that_exists() {
    // The diagnostic has to be a command the operator can actually run, and
    // the one that shows a surviving boot-time record specifically:
    // `netsh wfp show boottimepolicy` (learn.microsoft.com/windows-server/
    // administration/windows-commands/netsh-wfp). `show filters` lists what is
    // active NOW, which by definition excludes a boot-time filter after BFE
    // has started — the only moment this message is ever read.
    let report = release_clearance_report(&unproven_clearance(&["lockdown boot-time block-all V4"]))
        .expect("an unproven clearance must be reported");
    assert!(
        report.contains("lockdown boot-time block-all V4"),
        "the key must be named — with the binary gone, the label is all an operator can look it up by: {report}"
    );
    assert!(
        report.contains("netsh wfp show boottimepolicy"),
        "the diagnostic must name the one netsh command that shows a surviving boot-time record: {report}"
    );
}

#[skuld::test]
fn an_unproven_release_does_not_send_the_operator_to_a_command_that_cannot_help() {
    // `netsh wfp` is diagnostics-only — its verbs are capture, dump, help, set
    // and show; there is no delete. Telling a user in the one state where they
    // have no other tool that "`netsh wfp` can remove it" is a dead end
    // dressed as a remedy, and the previous test pinned that exact string.
    let report = release_clearance_report(&unproven_clearance(&["k"])).expect("reported");
    let lowered = report.to_lowercase();
    for claim in ["netsh wfp` can remove", "netsh wfp can remove", "netsh wfp delete"] {
        assert!(
            !lowered.contains(claim),
            "netsh wfp has no delete verb; the message must not imply otherwise ({claim}): {report}"
        );
    }
    assert!(
        lowered.contains("no delete verb"),
        "the message must say plainly that netsh cannot remove a filter, or the reader will try: {report}"
    );
}

#[skuld::test]
fn an_unproven_release_names_something_that_can_actually_remove_the_filter() {
    // Removing a WFP filter takes an FWPM call. Once `RemoveFiles` has run,
    // no such caller is left on the host — so the honest remedy is to put one
    // back, and the message must say so rather than trail off.
    let report = release_clearance_report(&unproven_clearance(&["k"])).expect("reported");
    assert!(
        report.contains("release-covers"),
        "the remedy must name the command that addresses these keys: {report}"
    );
    let lowered = report.to_lowercase();
    assert!(
        lowered.contains("reinstall"),
        "and must say how to get it back, since RemoveFiles just deleted it: {report}"
    );
}

#[skuld::test]
fn an_unproven_release_does_not_claim_a_cover_is_present() {
    // "Could not be proven absent" is not "is there". Asserting the latter
    // would send an operator hunting a filter that most likely never existed,
    // on every clean uninstall of a build that ships a boot-time key.
    let report = release_clearance_report(&unproven_clearance(&["k"])).expect("reported");
    let lowered = report.to_lowercase();
    assert!(
        !lowered.contains("still blocking") && !lowered.contains("is still installed"),
        "must not assert presence it did not measure: {report}"
    );
}

#[skuld::test]
fn an_unproven_release_names_every_key_not_just_the_first() {
    let report = release_clearance_report(&unproven_clearance(&["alpha-key", "beta-key"])).expect("reported");
    assert!(
        report.contains("alpha-key") && report.contains("beta-key"),
        "every unproven key must be named: {report}"
    );
}
