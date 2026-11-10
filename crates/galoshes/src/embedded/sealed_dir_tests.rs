use super::{check, Position, SealedDirRefusal};

const ME: u32 = 501;

#[skuld::test]
fn an_ancestor_is_sealed_when_the_user_or_root_owns_it_and_group_and_other_cannot_write() {
    for (uid, mode, sealed) in [
        (ME, 0o755, true),
        (ME, 0o700, true),
        (0, 0o755, true),
        (0, 0o775, false),
        (ME, 0o757, false),
        (ME, 0o720, false),
        (0, 0o1777, false),
        (502, 0o755, false),
        (502, 0o700, false),
    ] {
        assert_eq!(
            Position::Ancestor.is_sealed(uid, mode, ME),
            sealed,
            "uid {uid} mode {mode:o}"
        );
    }
}

#[skuld::test]
fn the_leaf_must_be_the_running_users_own() {
    for (uid, mode, sealed) in [
        (ME, 0o700, true),
        (ME, 0o755, true),
        (0, 0o755, false),
        (502, 0o700, false),
        (ME, 0o770, false),
    ] {
        assert_eq!(
            Position::Leaf.is_sealed(uid, mode, ME),
            sealed,
            "uid {uid} mode {mode:o}"
        );
    }
}

/// Under root, the running user is root: a root-owned path nobody else can write passes.
#[skuld::test]
fn a_root_owned_path_passes_for_root() {
    check(std::path::Path::new("/usr"), 0).unwrap();
}

/// A root-owned directory is not the leaf of a user's own runtime directory.
#[skuld::test]
fn a_root_owned_leaf_is_refused_for_a_user() {
    let err = check(std::path::Path::new("/usr"), ME).unwrap_err();
    assert!(
        matches!(err.downcast_ref(), Some(SealedDirRefusal::Changeable { .. })),
        "{err:#}"
    );
    assert!(err.to_string().contains("refusing to run the embedded binary"), "{err}");
}

/// The system temp directory is world-writable: anyone can add names to it, so a path through it is not sealed. It is
/// resolved first (`/tmp` is a link on macOS, and `check` takes a path with none), so the refusal is for `/tmp` itself.
#[skuld::test]
fn a_path_below_a_world_writable_directory_is_refused() {
    let tmp = std::fs::canonicalize("/tmp").unwrap();
    let dir = tempfile::tempdir_in(&tmp).unwrap();
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let err = check(dir.path(), euid).unwrap_err();
    assert!(
        matches!(err.downcast_ref(), Some(SealedDirRefusal::Changeable { .. })),
        "{err:#}"
    );
    assert!(err.to_string().contains(&format!("{} is a", tmp.display())), "{err}");
}

/// A volume mounted with `MNT_IGNORE_OWNERSHIP` reports every file as the running user's, so its owners prove nothing.
#[cfg(target_os = "macos")]
#[skuld::test]
fn a_volume_that_ignores_ownership_is_not_sealed() {
    use super::volume_ignores_ownership;
    assert!(volume_ignores_ownership(libc::MNT_IGNORE_OWNERSHIP as u32));
    assert!(volume_ignores_ownership(
        libc::MNT_IGNORE_OWNERSHIP as u32 | libc::MNT_RDONLY as u32
    ));
    assert!(!volume_ignores_ownership(0));
    assert!(!volume_ignores_ownership(libc::MNT_RDONLY as u32));
}

/// A directory made just now has the umask's mode, which `check` refuses where it applies: `prepare` gives what it made
/// `0o700`.
#[skuld::test]
fn a_directory_prepare_makes_is_the_users_alone() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let leaf = tmp.path().join("leaf");

    super::prepare(&leaf).unwrap();

    assert_eq!(std::fs::metadata(&leaf).unwrap().permissions().mode() & 0o7777, 0o700);
}

/// A directory the user cannot open fails the start with the OS's error and its path: it is another principal's, and is
/// neither moved nor repaired. Run as root it opens, and is used.
#[skuld::test]
fn a_directory_the_user_cannot_open_fails_the_start_naming_it() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let leaf = tmp.path().join("leaf");
    std::fs::create_dir(&leaf).unwrap();
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o000)).unwrap();

    let outcome = super::prepare(&leaf);

    let aside_exists = std::fs::read_dir(tmp.path()).unwrap().count() != 1;
    assert!(!aside_exists, "nothing is moved next to it");
    if euid() == 0 {
        outcome.unwrap();
        return;
    }
    let err = outcome.err().expect("a directory the user cannot open is an error");
    let chain = format!("{err:#}");
    assert!(chain.contains(&leaf.display().to_string()), "{chain}");
    let io = err.root_cause().downcast_ref::<std::io::Error>().expect("the OS error");
    assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied, "{chain}");
    assert_eq!(std::fs::metadata(&leaf).unwrap().permissions().mode() & 0o7777, 0o000);
}

/// Where the name is exec'd by path, a leaf others can write is not one the exec may trust: it is refused, with its
/// mode as it was. Where the descriptor is run the leaf is not judged and is used as it is. Either way it is never
/// repaired or moved.
#[skuld::test]
fn an_existing_directory_others_can_write_is_not_repaired() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let leaf = tmp.path().join("leaf");
    std::fs::create_dir(&leaf).unwrap();
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o777)).unwrap();

    let outcome = super::prepare(&leaf);

    match super::EXEC_BY_PATH {
        true => {
            let err = outcome.err().expect("a leaf others can write is refused");
            assert!(
                matches!(err.downcast_ref(), Some(SealedDirRefusal::Changeable { .. })),
                "{err:#}"
            );
        }
        false => {
            outcome.unwrap();
        }
    }
    assert_eq!(std::fs::metadata(&leaf).unwrap().permissions().mode() & 0o7777, 0o777);
    assert_eq!(
        std::fs::read_dir(tmp.path()).unwrap().count(),
        1,
        "nothing is moved next to it"
    );
}

fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}
