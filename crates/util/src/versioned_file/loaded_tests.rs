use std::io;
use std::sync::Arc;

use garter::test_utils::WaitableWriter;
use garter::tracing_test::set_default_in_current_thread;

use super::{CannotRead, Loaded, Raw};
use crate::parse_error::ParseFailure;
use crate::versioned_file::fixtures::{dir, put, DroppedFile, NoteV3, OsRecordFile, UnversionedConfig};
use crate::versioned_file::store::Fs;
use crate::versioned_file::VersionedFile;

fn note(tags: &[&str], pinned: bool) -> NoteV3 {
    NoteV3 {
        title: "t".to_string(),
        tags: tags.iter().map(|s| s.to_string()).collect(),
        pinned,
    }
}

// The outcomes ========================================================================================================

#[skuld::test]
fn no_file_is_absent() {
    let dir = dir();
    assert!(matches!(
        VersionedFile::<NoteV3>::new(dir.path()).load(),
        Loaded::Absent
    ));
}

#[skuld::test]
fn a_file_at_the_current_version_is_current() {
    let dir = dir();
    put(
        &dir,
        "note.json",
        br#"{"version":3,"title":"t","tags":["a"],"pinned":true}"#,
    );
    match VersionedFile::<NoteV3>::new(dir.path()).load() {
        Loaded::Current { value, found } => {
            assert_eq!(found, 3);
            assert_eq!(value, note(&["a"], true));
        }
        other => panic!("{other:?}"),
    }
}

#[skuld::test]
fn an_older_file_is_migrated_in_memory_and_reports_the_version_it_had() {
    let dir = dir();
    put(&dir, "note.json", br#"{"version":1,"title":"t"}"#);
    match VersionedFile::<NoteV3>::new(dir.path()).load() {
        Loaded::Current { value, found } => {
            assert_eq!(found, 1);
            assert_eq!(value, note(&["imported"], false));
        }
        other => panic!("{other:?}"),
    }
}

#[skuld::test]
fn a_newer_file_is_never_interpreted() {
    let dir = dir();
    // Valid JSON whose shape no schema of this release could hold.
    let bytes = br#"{"version":99,"future":{"a":[1,2]}}"#;
    put(&dir, "note.json", bytes);
    match VersionedFile::<NoteV3>::new(dir.path()).load() {
        Loaded::Newer { found, raw } => {
            assert_eq!(found, 99);
            assert_eq!(raw.as_bytes(), bytes);
        }
        other => panic!("{other:?}"),
    }
}

#[skuld::test]
fn a_version_at_or_below_the_floor_is_obsolete_and_keeps_its_bytes() {
    let dir = dir();
    let bytes = br#"{"version":1,"value":7}"#;
    put(&dir, "dropped.json", bytes);
    match VersionedFile::<DroppedFile>::new(dir.path()).load() {
        Loaded::Obsolete { found, raw } => {
            assert_eq!(found, 1);
            assert_eq!(raw.as_bytes(), bytes);
        }
        other => panic!("{other:?}"),
    }
}

#[skuld::test]
fn corrupt_files_are_corrupt_whatever_way_they_are_broken() {
    for (why, bytes) in [
        ("not json", &b"not json"[..]),
        ("empty", b""),
        ("array", b"[1]"),
        ("no version", br#"{"title":"t"}"#),
        (
            "string version",
            br#"{"version":"3","title":"t","tags":[],"pinned":false}"#,
        ),
        ("zero version", br#"{"version":0,"title":"t"}"#),
        ("wrong shape", br#"{"version":3,"title":"t","tags":"x","pinned":false}"#),
        ("old wrong shape", br#"{"version":1,"title":7}"#),
        ("truncated", br#"{"version":3,"title":"t""#),
    ] {
        let dir = dir();
        put(&dir, "note.json", bytes);
        match VersionedFile::<NoteV3>::new(dir.path()).load() {
            Loaded::Corrupt { raw, .. } => assert_eq!(raw.as_bytes(), bytes, "{why}"),
            other => panic!("{why}: {other:?}"),
        }
    }
}

// Unknown fields ======================================================================================================

#[skuld::test]
fn unknown_fields_are_ignored_at_top_level_and_nested() {
    let dir = dir();
    put(
        &dir,
        "note.json",
        br#"{"version":3,"title":"t","tags":["a"],"pinned":false,"added_later":{"x":1},"also":[1]}"#,
    );
    assert!(matches!(
        VersionedFile::<NoteV3>::new(dir.path()).load(),
        Loaded::Current { found: 3, .. }
    ));
    // And on an older version, which is migrated through the chain.
    put(&dir, "note.json", br#"{"version":1,"title":"t","added_later":true}"#);
    assert!(matches!(
        VersionedFile::<NoteV3>::new(dir.path()).load(),
        Loaded::Current { found: 1, .. }
    ));
}

// Declared default version ============================================================================================

#[skuld::test]
fn an_unversioned_file_reads_as_the_declared_version() {
    let dir = dir();
    put(&dir, "unversioned.json", br#"{"value":"v"}"#);
    match VersionedFile::<UnversionedConfig>::new(dir.path()).load() {
        Loaded::Current { value, found } => {
            assert_eq!(found, 1);
            assert_eq!(value.value, "v");
        }
        other => panic!("{other:?}"),
    }
}

#[skuld::test]
fn a_file_that_declares_no_default_is_corrupt_without_a_version() {
    let dir = dir();
    put(&dir, "os-record.json", br#"{"value":"v"}"#);
    assert!(matches!(
        VersionedFile::<OsRecordFile>::new(dir.path()).load(),
        Loaded::Corrupt { .. }
    ));
}

// Load never writes ===================================================================================================

#[skuld::test]
fn load_never_rewrites() {
    let dir = dir();
    let bytes = br#"{"version":1,"title":"t"}"#;
    let path = put(&dir, "note.json", bytes);
    let before = std::fs::metadata(&path).unwrap().modified().unwrap();

    let file = VersionedFile::<NoteV3>::new(dir.path());
    assert!(matches!(file.load(), Loaded::Current { found: 1, .. }));
    assert!(matches!(file.load(), Loaded::Current { found: 1, .. }));

    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), before);
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        1,
        "load must not leave a temp or backup behind"
    );
}

// I/O failures ========================================================================================================

struct DeniedFs;

impl Fs for DeniedFs {
    fn read(&self, _path: &std::path::Path) -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

#[skuld::test]
fn load_maps_io_failure_to_unreadable_never_corrupt() {
    let dir = dir();
    // A perfectly good file: only the read fails.
    put(
        &dir,
        "note.json",
        br#"{"version":3,"title":"t","tags":[],"pinned":false}"#,
    );
    let file = VersionedFile::<NoteV3>::with_fs(dir.path(), Arc::new(DeniedFs));
    match file.load() {
        Loaded::Unreadable(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
        other => panic!("{other:?}"),
    }
}

#[skuld::test]
fn io_failed_read_is_not_cannot_read() {
    let dir = dir();
    let file = VersionedFile::<NoteV3>::with_fs(dir.path(), Arc::new(DeniedFs));
    assert_eq!(file.load().cannot_read(), None);
}

#[skuld::test]
fn a_directory_where_the_file_should_be_is_unreadable_not_absent() {
    let dir = dir();
    std::fs::create_dir(dir.path().join("note.json")).unwrap();
    assert!(matches!(
        VersionedFile::<NoteV3>::new(dir.path()).load(),
        Loaded::Unreadable(_)
    ));
}

// cannot_read =========================================================================================================

#[skuld::test]
fn cannot_read_covers_exactly_newer_and_corrupt() {
    let raw = || Raw::new(b"x".to_vec());
    let all: Vec<(Loaded<NoteV3>, Option<CannotRead>)> = vec![
        (Loaded::Absent, None),
        (
            Loaded::Unreadable(io::Error::from(io::ErrorKind::PermissionDenied)),
            None,
        ),
        (
            Loaded::Corrupt {
                failure: ParseFailure::framing("test"),
                raw: raw(),
            },
            Some(CannotRead::Corrupt),
        ),
        (Loaded::Obsolete { found: 1, raw: raw() }, None),
        (Loaded::Newer { found: 9, raw: raw() }, Some(CannotRead::Newer)),
        (
            Loaded::Current {
                value: note(&[], false),
                found: 3,
            },
            None,
        ),
    ];
    for (loaded, want) in all {
        assert_eq!(loaded.cannot_read(), want, "{loaded:?}");
    }
}

// Raw and redaction ===================================================================================================

#[skuld::test]
fn raw_debug_prints_length_only() {
    let raw = Raw::new(b"203.0.113.7 hunter2".to_vec());
    assert_eq!(format!("{raw:?}"), "Raw(<19 bytes>)");
}

fn capture() -> (impl tracing::Subscriber + Send + Sync, WaitableWriter) {
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .with_target(true)
        .finish();
    (subscriber, writer)
}

#[skuld::test]
fn corrupt_and_newer_never_echo_contents() {
    const SECRET: &str = "203.0.113.7-hunter2";
    let (subscriber, log) = capture();
    let _guard = set_default_in_current_thread(subscriber);

    let mut shown = String::new();
    for body in [
        // `tags` is a string: serde's own message quotes the offending value.
        format!(r#"{{"version":3,"title":"t","tags":"{SECRET}","pinned":false}}"#),
        format!(r#"{{"version":99,"password":"{SECRET}"}}"#),
        format!(r#"{{"version":"{SECRET}"}}"#),
        format!(r#"{{"version":3,"title":"{SECRET}""#),
    ] {
        let dir = dir();
        put(&dir, "note.json", body.as_bytes());
        let loaded = VersionedFile::<NoteV3>::new(dir.path()).load();
        assert!(loaded.cannot_read().is_some(), "{body}: {loaded:?}");
        shown.push_str(&format!("{loaded:?}\n"));
    }
    // An obsolete one carries bytes too.
    let dir = dir();
    put(
        &dir,
        "dropped.json",
        format!(r#"{{"version":1,"value":"{SECRET}"}}"#).as_bytes(),
    );
    let loaded = VersionedFile::<DroppedFile>::new(dir.path()).load();
    assert!(matches!(loaded, Loaded::Obsolete { .. }));
    shown.push_str(&format!("{loaded:?}\n"));

    let log = log.snapshot();
    assert!(!log.is_empty(), "guard: loading a file that cannot be read must log");
    assert!(!log.contains(SECRET), "log echoed the file: {log}");
    assert!(!shown.contains(SECRET), "Debug echoed the file: {shown}");
}

#[skuld::test]
fn a_file_that_cannot_be_read_logs_once_with_the_file_name_and_versions() {
    let (subscriber, log) = capture();
    let _guard = set_default_in_current_thread(subscriber);
    let dir = dir();
    put(&dir, "note.json", br#"{"version":99}"#);
    let _ = VersionedFile::<NoteV3>::new(dir.path()).load();

    let log = log.snapshot();
    assert_eq!(log.matches("WARN").count(), 1, "{log}");
    assert!(log.contains("note.json"), "{log}");
    assert!(log.contains("99") && log.contains('3'), "{log}");
}

#[skuld::test]
fn unknown_fields_are_ignored_at_every_depth() {
    use crate::versioned_file::fixtures::{Inner, Kind, Nested};

    let dir = dir();
    put(
        &dir,
        "nested.json",
        br#"{
            "version": 1,
            "extra_top": 1,
            "inner": {"n": 1, "extra_inner": [1, 2]},
            "list": [{"n": 2, "extra_item": {}}, {"n": 3}],
            "kind": {"Tagged": {"label": "l", "extra_variant": null}}
        }"#,
    );
    match VersionedFile::<Nested>::new(dir.path()).load() {
        Loaded::Current { value, found: 1 } => assert_eq!(
            value,
            Nested {
                inner: Inner { n: 1 },
                list: vec![Inner { n: 2 }, Inner { n: 3 }],
                kind: Kind::Tagged { label: "l".to_string() },
            }
        ),
        other => panic!("{other:?}"),
    }
}
