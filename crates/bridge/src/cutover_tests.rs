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

#[skuld::test]
fn release_covers_refuses_against_a_live_bridge() {
    let dir = tempfile::tempdir().unwrap();

    let _bridge = crate::liveness::BridgeLiveness::acquire(dir.path(), None).unwrap();

    let result = release_covers_with(dir.path(), || {
        panic!("the release must never run while a bridge instance is live")
    });

    result.expect_err("release-covers must refuse while a bridge instance is running");
}

#[skuld::test]
fn release_covers_records_the_target_off_before_releasing() {
    let dir = tempfile::tempdir().unwrap();

    let result = release_covers_with(dir.path(), || {
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

    let result = release_covers_with(dir.path(), || Err(std::io::Error::other("not elevated")));

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

    let result = release_covers_with(dir.path(), || Ok(()));

    assert!(result.is_ok());
    assert!(
        !lockdown_state::load_enabled(dir.path()),
        "a confirmed release must disarm, not leave the switch armed over an open host"
    );
}
