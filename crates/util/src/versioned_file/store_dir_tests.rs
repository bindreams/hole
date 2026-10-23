//! The directory of a versioned file is the user's to swap: the type opens it once without following a symlink
//! and acts only inside that handle, never back through the path.

use std::path::Path;

use super::{DefaultPlacement, Loaded, Removal, VersionedFile};
use crate::dir::testing::{plant_link, user_dir, SystemScratch};
use crate::dir::Refusal;
use crate::versioned_file::fixtures::{dir, DecisionFile};

fn decision(value: &str) -> DecisionFile {
    DecisionFile {
        value: value.to_string(),
    }
}

/// A link to the folder the system owns at `root/state`, and where the record this test must never see written
/// (or removed) would be in it: the system's folder is shared, so what it held before is what it must hold after.
fn state_linked_to_the_system(root: &Path, scratch: &SystemScratch) -> (std::path::PathBuf, std::path::PathBuf) {
    let state = root.join("state");
    plant_link(scratch.root(), &state);
    (state, scratch.root().join("decision.json"))
}

#[skuld::test]
fn store_through_a_link_to_a_folder_the_system_owns_is_refused_and_writes_nothing_there() {
    let root = dir();
    let scratch = SystemScratch::new();
    let (state, record) = state_linked_to_the_system(root.path(), &scratch);
    let before = record.exists();

    let err = VersionedFile::<DecisionFile>::new(&state)
        .store(&decision("new"), &DefaultPlacement::default())
        .unwrap_err();

    let super::StoreError::Io(io) = &err else {
        panic!("{err:?}")
    };
    assert_eq!(Refusal::from_error(io), Some(&Refusal::Symlink), "{err:?}");
    assert_eq!(record.exists(), before, "a record was written in the system's folder");
}

#[skuld::test]
fn store_below_a_link_to_a_folder_the_system_owns_creates_nothing_there() {
    let root = dir();
    let scratch = SystemScratch::new();
    let link = root.path().join("hole");
    plant_link(scratch.root(), &link);

    let result = VersionedFile::<DecisionFile>::new(&link.join(scratch.name()).join("state"))
        .store(&decision("new"), &DefaultPlacement::default());

    assert!(result.is_err());
    assert!(!scratch.path().exists(), "something was made in the system's folder");
}

#[skuld::test]
fn store_through_a_users_link_to_the_users_folder_writes_there() {
    let root = dir();
    let real = root.path().join("real");
    user_dir(&real);
    let state = root.path().join("state");
    plant_link(&real, &state);

    VersionedFile::<DecisionFile>::new(&state)
        .store(&decision("new"), &DefaultPlacement::default())
        .unwrap();

    assert_eq!(names_in(&real), ["decision.json"]);
}

#[skuld::test]
fn load_remove_and_move_aside_through_a_link_to_a_folder_the_system_owns_touch_nothing_there() {
    let root = dir();
    let scratch = SystemScratch::new();
    let (state, record) = state_linked_to_the_system(root.path(), &scratch);
    let before = record.exists();
    let file = VersionedFile::<DecisionFile>::new(&state);

    assert!(
        matches!(file.load(), Loaded::Unreadable(_)),
        "the system's folder was read"
    );
    assert!(file.remove().is_err(), "a record in the system's folder was removed");
    assert!(file.move_aside().is_err(), "a record in the system's folder was moved");

    assert_eq!(record.exists(), before);
}

#[skuld::test]
fn a_directory_that_is_not_there_is_an_absent_file_and_is_not_made_by_a_read() {
    let root = dir();
    let missing = root.path().join("not-there");
    let file = VersionedFile::<DecisionFile>::new(&missing);

    assert!(matches!(file.load(), Loaded::Absent));
    assert_eq!(file.remove().unwrap(), Removal::Absent);
    assert_eq!(file.move_aside().unwrap(), None);
    assert!(!missing.exists());
}

/// The directory is replaced by a symlink to another one between the open and the last step: every step
/// after the open has to land in the directory that was opened.
#[cfg(unix)]
#[skuld::test]
fn a_directory_swapped_for_a_symlink_after_the_open_is_not_followed() {
    use std::io;

    use crate::dir::Dir;
    use crate::versioned_file::fixtures::OsRecordFile;

    struct Swaps<'a> {
        root: &'a Path,
    }
    impl super::Placement for Swaps<'_> {
        fn prepare_dir(&self, _dir: &Dir) -> io::Result<()> {
            std::fs::rename(self.root.join("state"), self.root.join("moved"))?;
            plant_link(&self.root.join("outside"), &self.root.join("state"));
            Ok(())
        }
    }

    let root = dir();
    std::fs::create_dir(root.path().join("state")).unwrap();
    std::fs::create_dir(root.path().join("outside")).unwrap();

    VersionedFile::<OsRecordFile>::new(&root.path().join("state"))
        .store(&OsRecordFile { value: "v".into() }, &Swaps { root: root.path() })
        .unwrap();

    assert!(
        names_in(&root.path().join("outside")).is_empty(),
        "a step followed the new link"
    );
    assert_eq!(names_in(&root.path().join("moved")), ["os-record.json"]);
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut found: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    found
}

/// A state directory owned by neither the placement's owner nor this process is refused, as the lock and the
/// state writers refuse it. The OS only lets root make one.
#[cfg(unix)]
#[skuld::test]
fn a_state_directory_owned_by_a_third_party_is_refused_only_when_the_caller_can_make_one() {
    use std::os::unix::fs::MetadataExt;

    let root = dir();
    let state = root.path().join("state");
    std::fs::create_dir(&state).unwrap();
    let mine = state.metadata().unwrap().uid();
    let third_party = mine + 7;
    let made = std::os::unix::fs::chown(&state, Some(third_party), None).is_ok();
    let placement = DefaultPlacement {
        owner: Some((mine + 3, mine + 3)),
    };

    let result = VersionedFile::<DecisionFile>::new(&state).store(&decision("new"), &placement);

    match made {
        true => {
            let super::StoreError::Io(err) = result.unwrap_err() else {
                panic!("not an io error")
            };
            assert_eq!(
                Refusal::from_error(&err),
                Some(&Refusal::ForeignOwner { uid: third_party })
            );
            assert!(names_in(&state).is_empty());
        }
        false => result.unwrap(),
    }
}

// A swap in the middle of each operation ------------------------------------------------------------------------------

/// Swaps `root/state` for a symlink to `root/outside` the first time the file is read, which every operation does
/// after it opened the directory and before it acts on the file: every later step has to land in the directory that
/// was opened (now `root/moved`).
#[cfg(unix)]
struct SwapsOnRead {
    root: std::path::PathBuf,
    swapped: std::sync::atomic::AtomicBool,
}

#[cfg(unix)]
impl super::Fs for SwapsOnRead {
    fn read(&self, dir: &crate::dir::ReadDir, name: &std::ffi::OsStr) -> std::io::Result<Vec<u8>> {
        if !self.swapped.swap(true, std::sync::atomic::Ordering::SeqCst) {
            std::fs::rename(self.root.join("state"), self.root.join("moved"))?;
            plant_link(&self.root.join("outside"), &self.root.join("state"));
        }
        dir.read(name)
    }
}

/// `root/state` and `root/outside`, each holding `decision.json` with the given bytes.
#[cfg(unix)]
fn two_directories(root: &Path, inside: &[u8], outside: &[u8]) {
    for (name, bytes) in [("state", inside), ("outside", outside)] {
        std::fs::create_dir(root.join(name)).unwrap();
        std::fs::write(root.join(name).join("decision.json"), bytes).unwrap();
    }
}

#[cfg(unix)]
fn assert_outside_untouched(root: &Path, outside: &[u8]) {
    assert_eq!(names_in(&root.join("outside")), ["decision.json"]);
    assert_eq!(
        std::fs::read(root.join("outside").join("decision.json")).unwrap(),
        outside
    );
}

#[cfg(unix)]
const CURRENT: &[u8] = br#"{"version":1,"value":"old"}"#;

#[cfg(unix)]
#[skuld::test]
fn a_remove_after_the_directory_is_swapped_removes_inside_the_opened_directory() {
    let root = dir();
    two_directories(root.path(), CURRENT, CURRENT);
    let fs = SwapsOnRead {
        root: root.path().to_path_buf(),
        swapped: Default::default(),
    };

    let removal = VersionedFile::<DecisionFile>::with_fs(&root.path().join("state"), std::sync::Arc::new(fs))
        .remove()
        .unwrap();

    assert_eq!(removal, Removal::Removed);
    assert_outside_untouched(root.path(), CURRENT);
    assert!(names_in(&root.path().join("moved")).is_empty());
}

#[cfg(unix)]
#[skuld::test]
fn a_move_aside_after_the_directory_is_swapped_moves_inside_the_opened_directory() {
    let root = dir();
    let corrupt = crate::versioned_file::fixtures::unreadable_bytes(crate::versioned_file::CannotRead::Corrupt);
    two_directories(root.path(), corrupt, corrupt);
    let fs = SwapsOnRead {
        root: root.path().to_path_buf(),
        swapped: Default::default(),
    };

    let removal = VersionedFile::<DecisionFile>::with_fs(&root.path().join("state"), std::sync::Arc::new(fs))
        .remove()
        .unwrap();

    assert!(matches!(removal, Removal::MovedAside(_)), "{removal:?}");
    assert_outside_untouched(root.path(), corrupt);
    assert_eq!(names_in(&root.path().join("moved")), ["decision.json.unreadable.bak"]);
}

#[cfg(unix)]
#[skuld::test]
fn a_store_with_a_backup_after_the_directory_is_swapped_writes_inside_the_opened_directory() {
    let root = dir();
    let newer = crate::versioned_file::fixtures::unreadable_bytes(crate::versioned_file::CannotRead::Newer);
    two_directories(root.path(), newer, newer);
    let fs = SwapsOnRead {
        root: root.path().to_path_buf(),
        swapped: Default::default(),
    };

    VersionedFile::<DecisionFile>::with_fs(&root.path().join("state"), std::sync::Arc::new(fs))
        .store(&decision("new"), &DefaultPlacement::default())
        .unwrap();

    assert_outside_untouched(root.path(), newer);
    assert_eq!(
        names_in(&root.path().join("moved")),
        ["decision.json", "decision.json.unreadable.bak"]
    );
    assert!(std::fs::read_to_string(root.path().join("moved").join("decision.json"))
        .unwrap()
        .contains("\"new\""));
}
