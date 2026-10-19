//! Windows-only properties of the stored file: its attributes, and a state
//! directory whose plain path is `MAX_PATH` or longer.

use std::os::windows::fs::MetadataExt;
use std::path::Path;

use super::{CannotRead, DefaultPlacement, Loaded, Removal, VersionedFile};
use crate::versioned_file::fixtures::{dir, long_dir, unreadable_bytes, DecisionFile, OsRecordFile};

const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn record(value: &str) -> OsRecordFile {
    OsRecordFile {
        value: value.to_owned(),
    }
}

fn is_temporary(path: &Path) -> bool {
    std::fs::metadata(path).unwrap().file_attributes() & FILE_ATTRIBUTE_TEMPORARY != 0
}

// Attributes ==========================================================================================================

#[skuld::test]
fn the_first_store_does_not_leave_the_file_marked_temporary() {
    let dir = dir();
    let file = VersionedFile::<OsRecordFile>::new(dir.path());

    file.store(&record("one"), &DefaultPlacement::default()).unwrap();

    assert!(!is_temporary(file.path()));
}

#[skuld::test]
fn a_store_over_an_existing_file_does_not_leave_it_marked_temporary() {
    let dir = dir();
    let file = VersionedFile::<OsRecordFile>::new(dir.path());
    file.store(&record("one"), &DefaultPlacement::default()).unwrap();

    file.store(&record("two"), &DefaultPlacement::default()).unwrap();

    assert!(!is_temporary(file.path()));
}

// Long paths ==========================================================================================================

#[skuld::test]
fn a_store_over_an_existing_file_works_in_a_directory_of_260_characters_or_more() {
    let root = dir();
    let long = long_dir(root.path());
    let file = VersionedFile::<OsRecordFile>::new(&long);
    file.store(&record("one"), &DefaultPlacement::default()).unwrap();

    file.store(&record("two"), &DefaultPlacement::default()).unwrap();

    assert!(matches!(file.load(), Loaded::Current { value, .. } if value == record("two")));
    assert_eq!(listing(&long), ["os-record.json"]);
}

#[skuld::test]
fn move_aside_moves_a_corrupt_file_in_a_directory_of_260_characters_or_more() {
    let root = dir();
    let long = long_dir(root.path());
    let file = VersionedFile::<DecisionFile>::new(&long);
    std::fs::write(file.path(), unreadable_bytes(CannotRead::Corrupt)).unwrap();

    let backup = file.move_aside().unwrap().expect("the file was there");

    assert_eq!(listing(&long), ["decision.json.unreadable.bak"]);
    assert_eq!(backup, long.join("decision.json.unreadable.bak"));
}

#[skuld::test]
fn remove_moves_a_corrupt_decision_file_aside_in_a_directory_of_260_characters_or_more() {
    let root = dir();
    let long = long_dir(root.path());
    let file = VersionedFile::<DecisionFile>::new(&long);
    std::fs::write(file.path(), unreadable_bytes(CannotRead::Corrupt)).unwrap();

    let removal = file.remove().unwrap();

    assert_eq!(removal, Removal::MovedAside(long.join("decision.json.unreadable.bak")));
    assert_eq!(listing(&long), ["decision.json.unreadable.bak"]);
}
