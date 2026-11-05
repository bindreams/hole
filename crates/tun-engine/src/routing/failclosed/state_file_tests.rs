//! `StateFile::view(&Loaded)`, the one fold of a read into the sweep's trichotomy. Not platform-gated: the fold is
//! platform-free, and only macOS has a record that uses it.

use serde::{Deserialize, Serialize};
use util::versioned_file::{Obsolete, Role, Schema, VersionedFile, VersionedState};

use super::StateFile;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Probe {
    pf_token: String,
}

impl Schema for Probe {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;

    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for Probe {
    const FILE_NAME: &'static str = "probe.json";
    const ROLE: Role = Role::Cover;
}

util::assert_contiguous!(Probe);

fn read(dir: &std::path::Path) -> StateFile<Probe> {
    StateFile::view(&VersionedFile::<Probe>::new(dir).observe().loaded)
}

fn read_bytes(bytes: &[u8]) -> StateFile<Probe> {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(Probe::FILE_NAME), bytes).unwrap();
    read(tmp.path())
}

#[skuld::test]
fn a_record_at_the_current_version_is_present() {
    let found = read_bytes(br#"{"version":1,"pf_token":"7"}"#);

    assert!(
        matches!(&found, StateFile::Present(Probe { pf_token }) if pf_token == "7"),
        "{found:?}"
    );
}

#[skuld::test]
fn no_file_is_absent() {
    let tmp = tempfile::tempdir().unwrap();

    assert!(matches!(read(tmp.path()), StateFile::Absent));
}

/// A rolled-back release's sweep: the record is complete and only its version is ahead, and its token is the only
/// copy of the `pfctl -E` ticket.
#[skuld::test]
fn a_newer_record_is_unusable_and_gives_up_its_token() {
    let found = read_bytes(br#"{"version":2,"pf_token":"7","future_field":1}"#);

    assert!(
        matches!(&found, StateFile::Unusable { pf_token: Some(t) } if t == "7"),
        "{found:?}"
    );
}

#[skuld::test]
fn a_truncated_or_ill_typed_record_is_unusable_and_keeps_only_a_token_that_parses() {
    let found = read_bytes(br#"{"version":1,"pf_token":"7","extra":{"nested":1},"cut":"#);
    assert!(matches!(&found, StateFile::Unusable { pf_token: None }), "{found:?}");

    let found = read_bytes(br#"{"version":"one","pf_token":"7"}"#);
    assert!(
        matches!(&found, StateFile::Unusable { pf_token: Some(t) } if t == "7"),
        "{found:?}"
    );
}

#[skuld::test]
fn a_record_below_the_floor_is_unusable_and_gives_up_its_token() {
    let found = read_bytes(br#"{"version":0,"pf_token":"7"}"#);

    assert!(
        matches!(&found, StateFile::Unusable { pf_token: Some(t) } if t == "7"),
        "{found:?}"
    );
}

/// An I/O failure has no bytes to salvage from, and is neither a record nor an absent one.
#[skuld::test]
fn a_read_that_failed_is_unreadable() {
    let tmp = tempfile::tempdir().unwrap();
    // The state directory is a regular file: the directory does not open.
    let not_a_dir = tmp.path().join("a-file");
    std::fs::write(&not_a_dir, b"x").unwrap();

    let found = read(&not_a_dir);

    assert!(matches!(&found, StateFile::Unreadable), "{found:?}");
}
