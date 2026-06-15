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
