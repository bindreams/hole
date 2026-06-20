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

#[cfg(target_os = "windows")]
#[skuld::test]
fn find_staged_exe_locates_hole_exe_in_nested_tree() {
    // An MSI admin-install lays the exe into a versioned subtree, so the finder
    // must recurse, not look at a fixed depth.
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

    // Stage a fake admin-install tree: an MSI lays the BINDIR component into a
    // versioned subtree, so place every file under nested dirs.
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
