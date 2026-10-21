//! A link at the state path is an entry like any other: it is never read
//! through (so it is a file this release cannot read, and its role decides),
//! `remove` and `move_aside` act on the name, never on what it points at, and
//! none of them calls it absent while the name is taken.

use std::path::Path;

use super::{Removal, VersionedFile};
use crate::versioned_file::fixtures::{dir, put, DecisionFile};

const STATE: &[u8] = br#"{"version":1,"value":"v"}"#;

/// Symlinks need `SeCreateSymbolicLinkPrivilege` on Windows: an elevated token,
/// or Developer Mode.
fn make_symlink(target: &Path, at: &Path) {
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(target, at);
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(target, at);
    made.unwrap_or_else(|e| {
        panic!("this test needs the privilege to create symlinks (on Windows an elevated token or Developer Mode): {e}")
    });
}

#[skuld::test]
fn remove_of_a_dangling_symlink_state_path_moves_the_link_aside() {
    let dir = dir();
    let state = dir.path().join("decision.json");
    make_symlink(&dir.path().join("nowhere"), &state);

    let removal = VersionedFile::<DecisionFile>::new(dir.path()).remove().unwrap();

    let Removal::MovedAside(backup) = removal else {
        panic!("a link is a file the role moves aside, not an absent one: {removal:?}");
    };
    assert!(std::fs::symlink_metadata(&state).is_err(), "the link is still there");
    assert!(
        std::fs::symlink_metadata(&backup).unwrap().is_symlink(),
        "the backup is the link itself"
    );
}

#[skuld::test]
fn remove_of_a_symlink_state_path_leaves_the_file_it_points_at() {
    let dir = dir();
    let away = crate::versioned_file::fixtures::dir();
    let target = put(&away, "elsewhere.json", STATE);
    let state = dir.path().join("decision.json");
    make_symlink(&target, &state);

    let removal = VersionedFile::<DecisionFile>::new(dir.path()).remove().unwrap();

    assert!(matches!(removal, Removal::MovedAside(_)), "{removal:?}");
    assert!(std::fs::symlink_metadata(&state).is_err(), "the link is still there");
    assert_eq!(std::fs::read(&target).unwrap(), STATE);
}

#[skuld::test]
fn a_symlink_state_path_is_not_read_through() {
    let dir = dir();
    let away = crate::versioned_file::fixtures::dir();
    let target = put(&away, "elsewhere.json", STATE);
    make_symlink(&target, &dir.path().join("decision.json"));

    let loaded = VersionedFile::<DecisionFile>::new(dir.path()).load();

    assert!(
        matches!(loaded, crate::versioned_file::Loaded::Unreadable(_)),
        "{loaded:?}"
    );
}

#[skuld::test]
fn move_aside_of_a_dangling_symlink_state_path_moves_the_link() {
    let dir = dir();
    let state = dir.path().join("decision.json");
    make_symlink(&dir.path().join("nowhere"), &state);

    let backup = VersionedFile::<DecisionFile>::new(dir.path()).move_aside().unwrap();

    let backup = backup.expect("the name was taken, so something was moved");
    assert!(
        std::fs::symlink_metadata(&state).is_err(),
        "the link is still at its name"
    );
    assert!(
        std::fs::symlink_metadata(&backup).unwrap().is_symlink(),
        "the backup is the link itself"
    );
}
