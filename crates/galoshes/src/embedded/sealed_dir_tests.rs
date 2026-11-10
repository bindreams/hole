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

/// A directory that is not the user's to use (a root-owned one `sudo -E` left; here one whose mode shuts the user out)
/// is moved aside and a fresh one made: the user owns what it is in, so it is theirs to name, as with a stale binary.
/// Run as root the directory opens, so nothing is unusable and it is used as it is.
#[skuld::test]
fn a_directory_the_user_cannot_open_is_moved_aside() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let leaf = tmp.path().join("leaf");
    std::fs::create_dir(&leaf).unwrap();
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o000)).unwrap();

    let outcome = super::prepare(&leaf);

    outcome.unwrap();
    let aside = tmp.path().join("leaf.unusable.0");
    if euid() == 0 {
        assert!(!aside.exists());
        return;
    }
    assert_eq!(std::fs::metadata(&leaf).unwrap().permissions().mode() & 0o7777, 0o700);
    assert_eq!(std::fs::metadata(&aside).unwrap().permissions().mode() & 0o7777, 0o000);
}

/// Each leftover is kept under a name of its own: a second one does not replace the first.
#[skuld::test]
fn a_second_leftover_is_moved_aside_under_another_name() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let leaf = tmp.path().join("leaf");
    for _ in 0..2 {
        std::fs::create_dir(&leaf).unwrap();
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o000)).unwrap();
        super::prepare(&leaf).unwrap();
        std::fs::remove_dir(&leaf).unwrap();
    }

    // As root nothing is shut out, so nothing is moved.
    let moved = euid() != 0;
    assert_eq!(tmp.path().join("leaf.unusable.0").is_dir(), moved);
    assert_eq!(tmp.path().join("leaf.unusable.1").is_dir(), moved);
}

/// Instances starting together on a leftover replace it once: one that lost its turn finds the directory the first
/// made and uses it, instead of moving that aside too (which would leave the first instance's path leading to an empty
/// directory).
#[skuld::test]
fn instances_starting_together_on_a_leftover_replace_it_once() {
    use std::os::unix::fs::PermissionsExt;

    const INSTANCES: usize = 4;
    let tmp = tempfile::tempdir().unwrap();
    let leaf = tmp.path().join("leaf");
    std::fs::create_dir(&leaf).unwrap();
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o000)).unwrap();
    let start = std::sync::Barrier::new(INSTANCES);

    let results: Vec<_> = std::thread::scope(|scope| {
        let starts: Vec<_> = (0..INSTANCES)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    super::prepare(&leaf).map(|_| ())
                })
            })
            .collect();
        starts.into_iter().map(|start| start.join().unwrap()).collect()
    });

    for result in results {
        result.unwrap_or_else(|err| panic!("an instance failed to start: {err:#}"));
    }
    let moved = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("leaf.unusable.")
        })
        .count();
    // As root nothing is shut out, so nothing is moved.
    assert_eq!(moved, usize::from(euid() != 0));
}

/// A link at the name is the user's own arrangement, not a leftover: it is not moved, and the refusal stands.
#[skuld::test]
fn a_link_to_a_directory_the_user_cannot_open_is_not_moved_aside() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000)).unwrap();
    let link = tmp.path().join("leaf");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let outcome = super::prepare(&link);

    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    // As root the target opens, so the link is used.
    assert_eq!(outcome.is_ok(), euid() == 0);
    assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
}

/// Where the name is exec'd by path, a leaf others can write is not one the exec may trust, and it is the user's to
/// replace like any leftover: it is moved aside with its mode as it was. Where the descriptor is run the leaf is not
/// judged and is used as it is.
#[skuld::test]
fn an_existing_directory_others_can_write_is_not_repaired() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let leaf = tmp.path().join("leaf");
    std::fs::create_dir(&leaf).unwrap();
    std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o777)).unwrap();
    let mode = |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o7777;

    super::prepare(&leaf).unwrap();

    let aside = tmp.path().join("leaf.unusable.0");
    match super::EXEC_BY_PATH {
        true => {
            assert_eq!(mode(&aside), 0o777, "the one others could write is left as it was");
            assert_eq!(mode(&leaf), 0o700);
        }
        false => assert_eq!(mode(&leaf), 0o777),
    }
}

/// Only a refusal of the directory itself is a leftover to replace; one of a directory on the way to it is not.
#[skuld::test]
fn only_a_refusal_of_the_leaf_names_a_leftover() {
    let leaf = std::path::PathBuf::from("/a/b");
    let changeable = |component: &str| SealedDirRefusal::Changeable {
        resolved: leaf.clone(),
        component: std::path::PathBuf::from(component),
        is_dir: true,
        uid: 0,
        mode: 0o755,
        euid: ME,
    };
    assert!(changeable("/a/b").names_the_leaf());
    assert!(!changeable("/a").names_the_leaf());
    let ignores = SealedDirRefusal::IgnoresOwnership {
        resolved: leaf.clone(),
        component: leaf.clone(),
    };
    assert!(!ignores.names_the_leaf());
}

fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}
