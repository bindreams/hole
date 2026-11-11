use super::*;
use std::fs;
use util::versioned_file::CannotRead;

util::assert_contiguous!(PluginLayout);

fn dir_with(stamp: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    if let Some(text) = stamp {
        fs::write(dir.path().join("layout.json"), text).unwrap();
    }
    dir
}

/// What a folder holding this stamp text (or none) reads as.
fn read_as(stamp: Option<&str>) -> StampState {
    let dir = dir_with(stamp);
    state(dir.path())
}

#[skuld::test]
fn state_maps_every_stamp_a_folder_can_hold_to_one_answer() {
    // Each row is its own expectation.
    assert_eq!(read_as(None), StampState::Nothing, "no file");
    assert_eq!(read_as(Some(r#"{"version": 1}"#)), StampState::Current, "version 1");
    // Layout 0 is no layout of any release: the floor is below the first version, so nothing can be obsolete.
    assert_eq!(
        read_as(Some(r#"{"version": 0}"#)),
        StampState::Unreadable(WhyUnreadable::CannotRead(CannotRead::Corrupt)),
        "version 0"
    );
    assert_eq!(
        read_as(Some(r#"{"version": 2}"#)),
        StampState::Unreadable(WhyUnreadable::CannotRead(CannotRead::Newer)),
        "newer"
    );
    assert_eq!(
        read_as(Some("not json")),
        StampState::Unreadable(WhyUnreadable::CannotRead(CannotRead::Corrupt)),
        "corrupt"
    );
}

#[skuld::test]
fn a_directory_at_the_stamp_name_is_unreadable_not_absent() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("layout.json")).unwrap();

    assert!(
        matches!(state(dir.path()), StampState::Unreadable(WhyUnreadable::ReadFailed(_))),
        "a name that holds something else is not an empty slot"
    );
}

#[skuld::test]
fn a_missing_folder_reads_as_nothing() {
    let tmp = tempfile::tempdir().unwrap();

    assert_eq!(state(&tmp.path().join("absent")), StampState::Nothing);
}

#[cfg(unix)]
#[skuld::test]
fn store_writes_exactly_version_one_and_nothing_else() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = crate::plugin_repair::PluginDirLayout::owned_by_this_process(tmp.path());

    store(&layout).unwrap();

    let text = fs::read_to_string(tmp.path().join("layout.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value, serde_json::json!({"version": 1}), "{text}");
    assert_eq!(state(tmp.path()), StampState::Current);
}

#[cfg(unix)]
#[skuld::test]
fn store_refuses_a_stamp_it_cannot_read_and_leaves_it_as_it_is() {
    let dir = dir_with(Some(r#"{"version": 2}"#));
    let layout = crate::plugin_repair::PluginDirLayout::owned_by_this_process(dir.path());

    assert!(store(&layout).is_err());

    assert_eq!(
        fs::read_to_string(dir.path().join("layout.json")).unwrap(),
        r#"{"version": 2}"#
    );
}
