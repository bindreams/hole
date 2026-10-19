use std::cell::RefCell;
use std::io;
use std::path::Path;

use super::{DefaultPlacement, Placement, Removal, StoreError, VersionedFile};
use crate::versioned_file::fixtures::{
    dir, names, put, unreadable_bytes, ConfigFile, DecisionFile, DroppedFile, LegacyRecordFile, NotAnObject, NoteV3,
    OsRecordFile, OwnsVersionKey,
};
use crate::versioned_file::{CannotRead, Loaded, VersionedState};

const BOTH: [CannotRead; 2] = [CannotRead::Newer, CannotRead::Corrupt];

fn plain() -> DefaultPlacement {
    DefaultPlacement::default()
}

fn note() -> NoteV3 {
    NoteV3 {
        title: "t".to_string(),
        tags: vec!["a".to_string()],
        pinned: true,
    }
}

/// Puts an unreadable file for `S` in `dir` and returns its bytes.
fn put_unreadable<S: VersionedState>(dir: &tempfile::TempDir, cause: CannotRead) -> &'static [u8] {
    let bytes = unreadable_bytes(cause);
    put(dir, S::FILE_NAME, bytes);
    bytes
}

fn read(dir: &tempfile::TempDir, name: &str) -> Vec<u8> {
    std::fs::read(dir.path().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

// What is written =====================================================================================================

#[skuld::test]
fn store_writes_a_flat_object_with_the_version_first() {
    let dir = dir();
    VersionedFile::<NoteV3>::new(dir.path())
        .store(&note(), &plain())
        .unwrap();

    let text = String::from_utf8(read(&dir, "note.json")).unwrap();
    assert!(text.starts_with("{\n  \"version\": 3,\n"), "{text}");
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        parsed,
        serde_json::json!({"version": 3, "title": "t", "tags": ["a"], "pinned": true})
    );
    assert_eq!(names(&dir), ["note.json"], "no temp file may stay behind");
}

#[skuld::test]
fn store_then_load_round_trips() {
    let dir = dir();
    let file = VersionedFile::<NoteV3>::new(dir.path());
    file.store(&note(), &plain()).unwrap();
    match file.load() {
        Loaded::Current { value, found } => {
            assert_eq!(found, 3);
            assert_eq!(value, note());
        }
        other => panic!("{other:?}"),
    }
}

#[skuld::test]
fn store_creates_a_missing_directory() {
    let dir = dir();
    let nested = dir.path().join("a").join("b");
    VersionedFile::<NoteV3>::new(&nested).store(&note(), &plain()).unwrap();
    assert!(nested.join("note.json").is_file());
}

#[skuld::test]
fn payload_with_a_version_key_is_refused_by_store() {
    let dir = dir();
    let file = VersionedFile::<OwnsVersionKey>::new(dir.path());
    let err = file.store(&OwnsVersionKey { version: 7 }, &plain()).unwrap_err();
    assert!(matches!(err, StoreError::Encode(_)), "{err:?}");
    assert!(names(&dir).is_empty(), "nothing may be written: {:?}", names(&dir));
}

#[skuld::test]
fn a_payload_that_is_not_an_object_is_refused_by_store() {
    let dir = dir();
    let err = VersionedFile::<NotAnObject>::new(dir.path())
        .store(&NotAnObject(vec![1]), &plain())
        .unwrap_err();
    assert!(matches!(err, StoreError::Encode(_)), "{err:?}");
    assert!(names(&dir).is_empty());
}

#[skuld::test]
fn a_refused_payload_leaves_an_existing_file_alone() {
    let dir = dir();
    let bytes = br#"{"version":1,"version_":0}"#;
    put(&dir, "owns-version.json", bytes);
    let _ = VersionedFile::<OwnsVersionKey>::new(dir.path()).store(&OwnsVersionKey { version: 7 }, &plain());
    assert_eq!(read(&dir, "owns-version.json"), bytes);
}

// Older and obsolete files are ordinary ===============================================================================

#[skuld::test]
fn older_file_is_overwritten_by_store() {
    let dir = dir();
    put(&dir, "note.json", br#"{"version":1,"title":"old"}"#);
    let file = VersionedFile::<NoteV3>::new(dir.path());
    file.store(&note(), &plain()).unwrap();
    assert!(matches!(file.load(), Loaded::Current { found: 3, .. }));
    assert_eq!(names(&dir), ["note.json"], "an older file is not worth a backup");
}

#[skuld::test]
fn obsolete_file_is_overwritten_by_store() {
    let dir = dir();
    put(&dir, "dropped.json", br#"{"version":1,"value":7}"#);
    let file = VersionedFile::<DroppedFile>::new(dir.path());
    file.store(&DroppedFile { value: 8 }, &plain()).unwrap();
    assert!(matches!(
        file.load(),
        Loaded::Current {
            found: 2,
            value: DroppedFile { value: 8 }
        }
    ));
    assert_eq!(names(&dir), ["dropped.json"]);
}

// A file that cannot be read, per role ================================================================================

#[skuld::test]
fn decision_store_moves_aside_then_writes() {
    for cause in BOTH {
        let dir = dir();
        let original = put_unreadable::<DecisionFile>(&dir, cause);
        let file = VersionedFile::<DecisionFile>::new(dir.path());

        file.store(
            &DecisionFile {
                value: "new".to_string(),
            },
            &plain(),
        )
        .unwrap();

        assert_eq!(read(&dir, "decision.json.unreadable.bak"), original, "{cause:?}");
        match file.load() {
            Loaded::Current { value, .. } => assert_eq!(value.value, "new"),
            other => panic!("{cause:?}: {other:?}"),
        }
        assert_eq!(
            names(&dir),
            ["decision.json", "decision.json.unreadable.bak"],
            "{cause:?}"
        );
    }
}

#[skuld::test]
fn os_record_store_and_remove_leave_the_bytes_untouched() {
    for cause in BOTH {
        let dir = dir();
        let original = put_unreadable::<OsRecordFile>(&dir, cause);
        let file = VersionedFile::<OsRecordFile>::new(dir.path());

        let err = file
            .store(
                &OsRecordFile {
                    value: "new".to_string(),
                },
                &plain(),
            )
            .unwrap_err();
        match &err {
            StoreError::Unreadable { path, cause: got } => {
                assert_eq!(path, file.path(), "{cause:?}");
                assert_eq!(*got, cause);
            }
            other => panic!("{cause:?}: {other:?}"),
        }
        assert!(
            err.to_string().contains(&file.path().display().to_string()),
            "the message must name the path: {err}"
        );
        assert_eq!(file.remove().unwrap(), Removal::Kept, "{cause:?}");

        assert_eq!(read(&dir, "os-record.json"), original, "{cause:?}");
        assert_eq!(names(&dir), ["os-record.json"], "{cause:?}");
    }
}

#[skuld::test]
fn legacy_record_store_and_remove_leave_the_bytes_untouched() {
    for cause in BOTH {
        let dir = dir();
        let original = put_unreadable::<LegacyRecordFile>(&dir, cause);
        let file = VersionedFile::<LegacyRecordFile>::new(dir.path());

        let err = file
            .store(
                &LegacyRecordFile {
                    value: "new".to_string(),
                },
                &plain(),
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::Unreadable { .. }), "{cause:?}: {err:?}");
        assert_eq!(file.remove().unwrap(), Removal::Kept, "{cause:?}");

        assert_eq!(read(&dir, "legacy-record.json"), original, "{cause:?}");
        assert_eq!(names(&dir), ["legacy-record.json"], "{cause:?}");
    }
}

#[skuld::test]
fn config_newer_store_is_refused() {
    let dir = dir();
    let original = put_unreadable::<ConfigFile>(&dir, CannotRead::Newer);
    let file = VersionedFile::<ConfigFile>::new(dir.path());

    let err = file
        .store(
            &ConfigFile {
                value: "new".to_string(),
            },
            &plain(),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::Unreadable {
                cause: CannotRead::Newer,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(read(&dir, "config.json"), original);
    assert_eq!(names(&dir), ["config.json"]);
}

#[skuld::test]
fn config_corrupt_store_overwrites_as_today() {
    let dir = dir();
    put_unreadable::<ConfigFile>(&dir, CannotRead::Corrupt);
    let file = VersionedFile::<ConfigFile>::new(dir.path());

    file.store(
        &ConfigFile {
            value: "new".to_string(),
        },
        &plain(),
    )
    .unwrap();

    assert!(matches!(file.load(), Loaded::Current { .. }));
    assert_eq!(
        names(&dir),
        ["config.json"],
        "no backup: that is what a save does today"
    );
}

#[skuld::test]
fn config_remove_keeps_a_file_it_cannot_read() {
    for cause in BOTH {
        let dir = dir();
        let original = put_unreadable::<ConfigFile>(&dir, cause);
        assert_eq!(
            VersionedFile::<ConfigFile>::new(dir.path()).remove().unwrap(),
            Removal::Kept
        );
        assert_eq!(read(&dir, "config.json"), original);
    }
}

#[skuld::test]
fn decision_remove_moves_aside() {
    for cause in BOTH {
        let dir = dir();
        let original = put_unreadable::<DecisionFile>(&dir, cause);
        let file = VersionedFile::<DecisionFile>::new(dir.path());

        let removal = file.remove().unwrap();

        let backup = dir.path().join("decision.json.unreadable.bak");
        assert_eq!(removal, Removal::MovedAside(backup), "{cause:?}");
        assert_eq!(read(&dir, "decision.json.unreadable.bak"), original, "{cause:?}");
        assert!(matches!(file.load(), Loaded::Absent), "{cause:?}");
        assert_eq!(names(&dir), ["decision.json.unreadable.bak"], "{cause:?}");
    }
}

// remove ==============================================================================================================

#[skuld::test]
fn remove_deletes_a_readable_file_and_reports_the_rest() {
    let dir = dir();
    let file = VersionedFile::<NoteV3>::new(dir.path());

    assert_eq!(file.remove().unwrap(), Removal::Absent);

    file.store(&note(), &plain()).unwrap();
    assert_eq!(file.remove().unwrap(), Removal::Removed);
    assert!(names(&dir).is_empty());

    put(&dir, "note.json", br#"{"version":1,"title":"old"}"#);
    assert_eq!(file.remove().unwrap(), Removal::Removed, "an older file");
    assert!(names(&dir).is_empty());

    let dropped = VersionedFile::<DroppedFile>::new(dir.path());
    put(&dir, "dropped.json", br#"{"version":1,"value":7}"#);
    assert_eq!(dropped.remove().unwrap(), Removal::Removed, "an obsolete file");
    assert!(names(&dir).is_empty());
}

// move_aside ==========================================================================================================

#[skuld::test]
fn move_aside_has_nothing_to_move_when_there_is_no_file() {
    let dir = dir();
    assert_eq!(VersionedFile::<NoteV3>::new(dir.path()).move_aside().unwrap(), None);
    assert!(names(&dir).is_empty());
}

#[skuld::test]
fn move_aside_works_whatever_the_role() {
    // The role decides what an ordinary write or remove may do; the pf release
    // path moves an OS record aside on purpose.
    let dir = dir();
    let original = put_unreadable::<OsRecordFile>(&dir, CannotRead::Newer);
    let file = VersionedFile::<OsRecordFile>::new(dir.path());

    let moved = file.move_aside().unwrap();

    assert_eq!(moved, Some(dir.path().join("os-record.json.unreadable.bak")));
    assert_eq!(read(&dir, "os-record.json.unreadable.bak"), original);
    assert_eq!(names(&dir), ["os-record.json.unreadable.bak"]);
}

#[skuld::test]
fn move_aside_moves_a_readable_file_too() {
    let dir = dir();
    let file = VersionedFile::<NoteV3>::new(dir.path());
    file.store(&note(), &plain()).unwrap();
    let before = read(&dir, "note.json");

    let moved = file.move_aside().unwrap().expect("a file to move");

    assert_eq!(std::fs::read(&moved).unwrap(), before);
    assert!(matches!(file.load(), Loaded::Absent));
}

// Placement ===========================================================================================================

/// Records each call with what is on disk at that moment.
struct Recorder<'a> {
    path: &'a Path,
    events: RefCell<Vec<String>>,
}

impl Recorder<'_> {
    fn on_disk(&self) -> String {
        match std::fs::read(self.path) {
            Ok(bytes) if String::from_utf8_lossy(&bytes).contains("\"new\"") => "new".to_string(),
            Ok(_) => "old".to_string(),
            Err(_) => "absent".to_string(),
        }
    }
}

impl Placement for Recorder<'_> {
    fn prepare_dir(&self, dir: &Path) -> io::Result<()> {
        self.events
            .borrow_mut()
            .push(format!("prepare_dir[{}]", self.on_disk()));
        std::fs::create_dir_all(dir)
    }

    fn prepare_tmp(&self, tmp: &Path) -> io::Result<()> {
        let tmp_bytes = std::fs::read(tmp)?;
        assert!(
            !tmp_bytes.is_empty(),
            "the temp file must be complete before prepare_tmp"
        );
        self.events
            .borrow_mut()
            .push(format!("prepare_tmp[{}]", self.on_disk()));
        Ok(())
    }

    fn after_publish(&self, _path: &Path) -> io::Result<()> {
        self.events
            .borrow_mut()
            .push(format!("after_publish[{}]", self.on_disk()));
        Ok(())
    }

    fn sync_dir(&self, _dir: &Path) -> io::Result<()> {
        self.events.borrow_mut().push(format!("sync_dir[{}]", self.on_disk()));
        Ok(())
    }
}

#[skuld::test]
fn placement_runs_around_the_publish_in_order() {
    let dir = dir();
    let path = put(&dir, "decision.json", br#"{"version":1,"value":"old"}"#);
    let placement = Recorder {
        path: &path,
        events: RefCell::new(Vec::new()),
    };

    VersionedFile::<DecisionFile>::new(dir.path())
        .store(
            &DecisionFile {
                value: "new".to_string(),
            },
            &placement,
        )
        .unwrap();

    assert_eq!(
        *placement.events.borrow(),
        [
            "prepare_dir[old]",
            "prepare_tmp[old]",
            "after_publish[new]",
            "sync_dir[new]"
        ]
    );
}

#[skuld::test]
fn a_failed_prepare_tmp_leaves_no_temp_and_the_original() {
    struct Fails;
    impl Placement for Fails {
        fn prepare_dir(&self, dir: &Path) -> io::Result<()> {
            std::fs::create_dir_all(dir)
        }
        fn prepare_tmp(&self, _tmp: &Path) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
        fn after_publish(&self, _path: &Path) -> io::Result<()> {
            Ok(())
        }
        fn sync_dir(&self, _dir: &Path) -> io::Result<()> {
            Ok(())
        }
    }

    let dir = dir();
    let bytes = br#"{"version":1,"value":"old"}"#;
    put(&dir, "decision.json", bytes);

    let err = VersionedFile::<DecisionFile>::new(dir.path())
        .store(
            &DecisionFile {
                value: "new".to_string(),
            },
            &Fails,
        )
        .unwrap_err();

    assert!(matches!(err, StoreError::Io(_)), "{err:?}");
    assert_eq!(read(&dir, "decision.json"), bytes);
    assert_eq!(names(&dir), ["decision.json"]);
}

// Redaction ===========================================================================================================

#[skuld::test]
fn no_error_or_cause_text_echoes_the_file() {
    const SECRET: &str = "hunter2";

    let mut shown = Vec::new();
    for cause in BOTH {
        let dir = dir();
        let bytes = put_unreadable::<OsRecordFile>(&dir, cause);
        assert!(
            String::from_utf8_lossy(bytes).contains(SECRET),
            "guard: the fixture carries the secret"
        );
        let file = VersionedFile::<OsRecordFile>::new(dir.path());

        let err = file
            .store(&OsRecordFile { value: "v".into() }, &plain())
            .expect_err("an os record is not replaced");
        shown.push(format!("{err}"));
        shown.push(format!("{err:?}"));
        shown.push(format!("{cause}"));
        shown.push(format!("{cause:?}"));
        if let Loaded::Corrupt { failure, .. } = file.load() {
            shown.push(format!("{failure}"));
            shown.push(format!("{failure:?}"));
        }
    }
    for err in [
        VersionedFile::<OwnsVersionKey>::new(dir().path())
            .store(&OwnsVersionKey { version: 7 }, &plain())
            .expect_err("encode"),
        VersionedFile::<NotAnObject>::new(dir().path())
            .store(&NotAnObject(vec![1]), &plain())
            .expect_err("encode"),
    ] {
        shown.push(format!("{err}"));
        shown.push(format!("{err:?}"));
    }

    assert!(shown.iter().all(|text| !text.is_empty()), "guard: {shown:?}");
    for text in &shown {
        assert!(!text.contains(SECRET), "echoed the file: {text}");
    }
}
