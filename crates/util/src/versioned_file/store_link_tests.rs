//! A link at the state path is an entry like any other: for a system file it is never read
//! through (so it is a file this release cannot read, and its role decides),
//! `remove` and `move_aside` act on the name, never on what it points at, and
//! none of them calls it absent while the name is taken. A user's own file
//! ([`Role::Config`](crate::versioned_file::Role::Config)) is read through the link, and a store replaces the link.

use crate::versioned_file::fixtures::UpdateShortcuts;
use crate::versioned_file::UpdateOutcome;
use std::path::Path;

use super::VersionedFile;
use crate::dir::testing::{own, plant_link, SystemScratch};
use crate::dir::Principal;
use crate::versioned_file::fixtures::{dir, put, DecisionFile, NoteV3, UnversionedConfig};
use crate::versioned_file::{DefaultPlacement, Loaded};

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

    let UpdateOutcome::MovedAside(backup) = removal else {
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

    assert!(matches!(removal, UpdateOutcome::MovedAside(_)), "{removal:?}");
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
        matches!(loaded, crate::versioned_file::Loaded::Unreadable { .. }),
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

#[skuld::test]
fn store_over_a_symlink_state_path_backs_up_the_link_and_not_its_target() {
    let dir = dir();
    let away = crate::versioned_file::fixtures::dir();
    let target = put(&away, "elsewhere.json", STATE);
    let state = dir.path().join("decision.json");
    make_symlink(&target, &state);

    VersionedFile::<DecisionFile>::new(dir.path())
        .store(
            &DecisionFile { value: "new".into() },
            &crate::versioned_file::DefaultPlacement::default(),
        )
        .unwrap();

    let backup = dir.path().join("decision.json.unreadable.bak");
    assert!(
        std::fs::symlink_metadata(&backup).unwrap().is_symlink(),
        "the backup is the link itself"
    );
    assert_eq!(std::fs::read(&target).unwrap(), STATE, "the target was not touched");
    assert!(std::fs::read_to_string(&state).unwrap().contains("\"new\""));
}

// A user's own file ===================================================================================================

#[skuld::test]
fn a_users_own_file_is_read_through_a_symlink_at_its_name_and_a_store_replaces_the_link() {
    let dir = dir();
    let away = dir_with_target(br#"{"version":1,"value":"v"}"#);
    let state = dir.path().join("unversioned.json");
    make_symlink(&away.1, &state);
    let file = VersionedFile::<UnversionedConfig>::for_process(dir.path(), Principal::User);

    let Loaded::Current { value, .. } = file.load() else {
        panic!("a user's own file is read through a link at its name");
    };
    assert_eq!(value.value, "v");
    file.store(&UnversionedConfig { value: "new".into() }, &DefaultPlacement::default())
        .unwrap();

    assert!(
        !std::fs::symlink_metadata(&state).unwrap().is_symlink(),
        "the save replaces the link"
    );
    assert_eq!(std::fs::read(&away.1).unwrap(), br#"{"version":1,"value":"v"}"#);
    assert!(std::fs::read_to_string(&state).unwrap().contains("\"new\""));
}

/// A target file in a directory of its own, which lives as long as the returned guard.
fn dir_with_target(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let away = dir();
    let target = put(&away, "dotfiles.json", bytes);
    (away, target)
}

#[skuld::test]
fn a_users_own_file_is_read_and_saved_through_a_users_link_into_a_folder_the_system_owns() {
    let tmp = dir();
    let scratch = SystemScratch::new();
    let link = tmp.path().join("state");
    plant_link(scratch.root(), &link);
    let through = link.join(scratch.name());
    let file = VersionedFile::<UnversionedConfig>::for_process(&through, Principal::User);

    assert!(matches!(file.load(), Loaded::Absent));
    file.store(&UnversionedConfig { value: "v".into() }, &DefaultPlacement::default())
        .unwrap();

    let Loaded::Current { value, .. } = file.load() else {
        panic!("a user's own file is read through the user's link");
    };
    assert_eq!(value.value, "v");
    assert!(scratch.path().join("unversioned.json").is_file());
    // A system file's walk ends nowhere but in a folder the user owns, so the same link is refused to it.
    assert!(matches!(
        VersionedFile::<NoteV3>::new(&link).load(),
        Loaded::Unreadable { .. }
    ));
}

#[skuld::test]
fn a_file_a_user_owns_in_a_folder_the_system_owns_is_a_users_own_file_to_read() {
    // A test's folder is the system's when its runner is (an elevated first run made the folder); the file is the user's.
    let dir = dir();
    let state = put(&dir, "unversioned.json", br#"{"version":1,"value":"v"}"#);
    own(&state);

    let Loaded::Current { value, .. } =
        VersionedFile::<UnversionedConfig>::for_process(dir.path(), Principal::User).load()
    else {
        panic!("a user's file is the user's own to read");
    };

    assert_eq!(value.value, "v");
}
