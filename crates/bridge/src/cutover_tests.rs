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

/// `release_covers_with` with no peer dirs and the purge stubbed out, so the
/// assertions below can still read the state dir afterwards.
fn release_covers_probe(dir: &std::path::Path, release: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> {
    // These probes are about the sequencing around the release (liveness,
    // target write, purge), not about what the sweep proved — so they hand it
    // the fully-proven clearance and drop it again. The propagation itself is
    // pinned by `release_covers_reports_what_the_sweep_could_not_prove`.
    release_covers_with(dir, &[], || release().map(|()| Clearance::proven()), || {}).map(|_| ())
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

    let result = release_covers_with(
        service.path(),
        &[peer.path().to_path_buf()],
        || panic!("the release must never run while a bridge instance is live"),
        || {},
    );

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

    let result = release_covers_with(
        service.path(),
        std::slice::from_ref(&absent),
        || {
            assert!(
                crate::liveness::BridgeLiveness::try_acquire(&absent, None)
                    .unwrap()
                    .is_none(),
                "a bridge starting under an account with no state dir yet must contend on the \
                 same lock, not find it free"
            );
            Ok(Clearance::proven())
        },
        || {},
    );

    assert!(result.is_ok(), "{result:?}");
}

/// The litter the lock above costs. `try_acquire` creates what it locks, so a
/// peer that was not there is provisioned to be locked — and removed again on
/// the way out, down to the shallowest level this call had to make.
#[skuld::test]
fn release_covers_removes_the_peer_state_dirs_it_had_to_create() {
    let service = tempfile::tempdir().unwrap();
    let profile = service.path().join("no-such-user");

    let result = release_covers_with(
        service.path(),
        &[profile.join("state")],
        || Ok(Clearance::proven()),
        || {},
    );

    assert!(result.is_ok(), "{result:?}");
    assert!(
        !profile.exists(),
        "a peer tree this call provisioned in order to lock it must not be left behind"
    );
}

#[skuld::test]
fn provisioned_root_names_only_what_is_missing_and_never_what_cannot_be_read() {
    let base = tempfile::tempdir().unwrap();
    assert_eq!(
        provisioned_root(base.path()),
        None,
        "a dir already there has nothing to provision"
    );

    let deep = base.path().join("profile").join("hole").join("state");
    assert_eq!(
        provisioned_root(&deep),
        Some(base.path().join("profile")),
        "the shallowest level `create_dir_all` would make is the root of what this call creates"
    );

    // An interior NUL makes every probe fail `InvalidInput` on both platforms.
    // Undeterminable is not absent: reading it as absent would put a path this
    // call never created onto the removal list.
    let unprobeable = base.path().join("pro\0file").join("state");
    assert_eq!(provisioned_root(&unprobeable), None);
}

/// The other side of that sweep: only what this call made goes. A peer dir
/// that was already there belongs to the account that owns it, and its
/// crash-recovery records are that bridge's, not this call's to delete.
#[skuld::test]
fn release_covers_leaves_a_peer_state_dir_that_was_already_there() {
    let service = tempfile::tempdir().unwrap();
    let peer = tempfile::tempdir().unwrap();
    let record = peer.path().join("bridge-routes.json");
    std::fs::write(&record, b"{}").unwrap();

    let result = release_covers_with(
        service.path(),
        &[peer.path().to_path_buf()],
        || Ok(Clearance::proven()),
        || {},
    );

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

    let result = release_covers_with(service.path(), &peers, || Ok(Clearance::proven()), || {});

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

/// The release provisions a state dir on a host that never ran a bridge (the
/// liveness lock and the target write both create what they touch), and neither
/// platform's `uninstall()` removes it. Purging is the last step and runs only
/// once nothing is left that needs the directory.
#[skuld::test]
fn release_covers_purges_the_state_dir_only_after_a_confirmed_release() {
    let dir = tempfile::tempdir().unwrap();
    let purged = std::cell::Cell::new(false);

    let refused = release_covers_with(
        dir.path(),
        &[],
        || Err(std::io::Error::other("not elevated")),
        || purged.set(true),
    );
    assert!(refused.is_err());
    assert!(!purged.get(), "a failed release must leave the state it recorded off");

    let released = release_covers_with(dir.path(), &[], || Ok(Clearance::proven()), || purged.set(true));
    assert!(released.is_ok(), "{released:?}");
    assert!(
        purged.get(),
        "a confirmed release owns the cleanup of the dir it created"
    );
}

/// The production purge, driven directly: `release_covers` hands it the real
/// `remove_dir_all`, and the lock the release held sits inside the directory it
/// removes.
#[skuld::test]
fn purge_state_dir_removes_the_tree_and_tolerates_its_absence() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir_all(state.join("nested")).unwrap();
    std::fs::write(state.join("bridge-target.json"), "{}").unwrap();

    purge_state_dir(&state);
    assert!(!state.exists());

    purge_state_dir(&state); // idempotent: a host that never had one
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
    let clearance = release_covers_with(
        dir.path(),
        &[],
        || Ok(unproven_clearance(&["lockdown boot-time block-all V4"])),
        || {},
    )
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
