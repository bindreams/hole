//! The order of `store`'s steps, proven by failing each one, plus the backup
//! names and what a failed read does to them.

use std::io;
use std::path::Path;
use std::sync::{Arc, Barrier};

use tempfile::NamedTempFile;

use super::{DefaultPlacement, Fs, Removal, StoreError, VersionedFile};
use crate::versioned_file::fixtures::{dir, names, put, unreadable_bytes, DecisionFile, NoteV3};
use crate::versioned_file::{CannotRead, Loaded};

fn plain() -> DefaultPlacement {
    DefaultPlacement::default()
}

fn decision(value: &str) -> DecisionFile {
    DecisionFile {
        value: value.to_string(),
    }
}

// Failing each step ===================================================================================================

/// Fails the publish (step 4), as a rename that does not happen.
struct FailsPublish;

impl Fs for FailsPublish {
    fn publish(&self, _tmp: NamedTempFile, _dest: &Path) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

/// Fails the backup link (step 3) for a reason other than a taken name.
struct FailsLink;

impl Fs for FailsLink {
    fn hard_link(&self, _original: &Path, _link: &Path) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

#[skuld::test]
fn decision_store_never_exposes_an_absent_file() {
    for cause in [CannotRead::Newer, CannotRead::Corrupt] {
        let dir = dir();
        let original = unreadable_bytes(cause);
        put(&dir, "decision.json", original);
        let file = VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(FailsPublish));

        let err = file.store(&decision("new"), &plain()).unwrap_err();

        assert!(matches!(err, StoreError::Io(_)), "{cause:?}: {err:?}");
        // The original is still at its name, with its bytes, and the temp is gone.
        // The backup made before the failed publish is a second name for the same
        // bytes: nothing is lost.
        assert_eq!(std::fs::read(dir.path().join("decision.json")).unwrap(), original);
        assert_eq!(
            names(&dir),
            ["decision.json", "decision.json.unreadable.bak"],
            "{cause:?}"
        );
        assert_eq!(
            std::fs::read(dir.path().join("decision.json.unreadable.bak")).unwrap(),
            original
        );
    }
}

#[skuld::test]
fn decision_store_aborts_untouched_when_the_backup_link_fails() {
    for cause in [CannotRead::Newer, CannotRead::Corrupt] {
        let dir = dir();
        let original = unreadable_bytes(cause);
        put(&dir, "decision.json", original);
        let file = VersionedFile::<DecisionFile>::with_fs(dir.path(), Arc::new(FailsLink));

        let err = file.store(&decision("new"), &plain()).unwrap_err();

        assert!(matches!(err, StoreError::Io(_)), "{cause:?}: {err:?}");
        assert_eq!(std::fs::read(dir.path().join("decision.json")).unwrap(), original);
        assert_eq!(names(&dir), ["decision.json"], "no temp and no backup: {cause:?}");
    }
}

#[skuld::test]
fn store_is_atomic_under_a_failed_rename() {
    // An ordinary overwrite of a readable file: the old bytes survive.
    let dir = dir();
    let old = br#"{"version":3,"title":"old","tags":[],"pinned":false}"#;
    put(&dir, "note.json", old);
    let file = VersionedFile::<NoteV3>::with_fs(dir.path(), Arc::new(FailsPublish));

    let new = NoteV3 {
        title: "new".to_string(),
        tags: vec![],
        pinned: true,
    };
    assert!(file.store(&new, &plain()).is_err());

    assert_eq!(std::fs::read(dir.path().join("note.json")).unwrap(), old);
    assert_eq!(names(&dir), ["note.json"]);
}

// Backup names ========================================================================================================

#[skuld::test]
fn second_unreadable_file_gets_the_next_free_bak_name() {
    let dir = dir();
    let file = VersionedFile::<DecisionFile>::new(dir.path());
    let unreadable = [
        &br#"{"version":99,"value":"first"}"#[..],
        br#"{"version":1,"value":"second"#,
        br#"{"version":98,"value":"third"}"#,
    ];

    for (i, bytes) in unreadable.iter().enumerate() {
        put(&dir, "decision.json", bytes);
        file.store(&decision(&format!("v{i}")), &plain()).unwrap();
    }

    assert_eq!(
        names(&dir),
        [
            "decision.json",
            "decision.json.unreadable.2.bak",
            "decision.json.unreadable.3.bak",
            "decision.json.unreadable.bak",
        ]
    );
    for (name, bytes) in [
        ("decision.json.unreadable.bak", unreadable[0]),
        ("decision.json.unreadable.2.bak", unreadable[1]),
        ("decision.json.unreadable.3.bak", unreadable[2]),
    ] {
        assert_eq!(
            std::fs::read(dir.path().join(name)).unwrap(),
            bytes,
            "{name}: an earlier backup must survive untouched"
        );
    }
}

#[skuld::test]
fn remove_and_move_aside_also_take_the_next_free_name() {
    let dir = dir();
    put(&dir, "decision.json.unreadable.bak", b"first");
    put(&dir, "decision.json", unreadable_bytes(CannotRead::Newer));

    let removal = VersionedFile::<DecisionFile>::new(dir.path()).remove().unwrap();

    assert_eq!(
        removal,
        Removal::MovedAside(dir.path().join("decision.json.unreadable.2.bak"))
    );
    assert_eq!(
        std::fs::read(dir.path().join("decision.json.unreadable.bak")).unwrap(),
        b"first"
    );
}

/// Many writers at once over one unreadable decision file. Each probe and its
/// write is one step under the file's lock, so the first writer backs the
/// original up and every later one finds the file it wrote.
#[skuld::test]
fn racing_stores_back_the_original_up_once() {
    const WRITERS: usize = 8;
    let dir = dir();
    let original = unreadable_bytes(CannotRead::Newer);
    put(&dir, "decision.json", original);
    let start = Barrier::new(WRITERS);

    std::thread::scope(|scope| {
        for i in 0..WRITERS {
            let (path, start) = (dir.path(), &start);
            scope.spawn(move || {
                start.wait();
                VersionedFile::<DecisionFile>::new(path)
                    .store(&decision(&format!("writer {i}")), &plain())
                    .expect("every writer stores");
            });
        }
    });

    assert_eq!(
        names(&dir),
        ["decision.json", "decision.json.unreadable.bak"],
        "one backup, of the file that was unreadable"
    );
    assert_eq!(
        std::fs::read(dir.path().join("decision.json.unreadable.bak")).unwrap(),
        original
    );
    assert!(matches!(
        VersionedFile::<DecisionFile>::new(dir.path()).load(),
        Loaded::Current { .. }
    ));
}

// A backup is the same file ===========================================================================================

/// `(volume, file index)` of whatever `path` names.
#[cfg(unix)]
fn identity(path: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).unwrap();
    (meta.dev(), meta.ino())
}

#[cfg(windows)]
fn identity(path: &Path) -> (u64, u64) {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};

    let file = std::fs::File::open(path).unwrap();
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open for the call and `info` is a valid out-parameter.
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }.unwrap();
    (
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    )
}

/// A `.unreadable.bak` of a decision file holds the server password, so it
/// must carry exactly the protection the original had: a hard link is the same
/// file object under a second name, a copy would be a new file with whatever
/// the directory hands out.
#[skuld::test]
fn backup_preserves_mode_and_dacl() {
    let dir = dir();
    let path = put(&dir, "decision.json", unreadable_bytes(CannotRead::Newer));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let before = identity(&path);

    VersionedFile::<DecisionFile>::new(dir.path())
        .store(&decision("new"), &plain())
        .unwrap();

    let backup = dir.path().join("decision.json.unreadable.bak");
    assert_eq!(
        identity(&backup),
        before,
        "the backup must be the original file, not a copy"
    );
    assert_ne!(identity(&path), before, "the new file is a different one");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&backup), 0o600);
        assert_eq!(mode(&path), 0o600, "the written file is private too");
    }
}
