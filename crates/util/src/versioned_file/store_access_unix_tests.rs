//! Unix: who can open the lock file, and what `remove` and `move_aside` do where
//! they cannot create one.
//!
//! The lock is held with only read access to its file, so anyone who can open
//! it can stall every writer: it must open for exactly the principals that may
//! write the state file.

use std::io;

use super::{DefaultPlacement, Fs, Removal, VersionedFile};
use crate::versioned_file::fixtures::{dir, put, unreadable_bytes, DecisionFile, OsRecordFile};
use crate::versioned_file::CannotRead;

fn decision(value: &str) -> DecisionFile {
    DecisionFile {
        value: value.to_string(),
    }
}

fn plain() -> DefaultPlacement {
    DefaultPlacement::default()
}

// A directory the caller cannot write =================================================================================

#[cfg(unix)]
mod read_only_directory {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;

    /// Makes `path` read-only and restores it on drop, so the temp dir can go.
    struct ReadOnly<'a>(&'a Path);

    impl<'a> ReadOnly<'a> {
        fn new(path: &'a Path) -> Self {
            std::fs::set_permissions(path, PermissionsExt::from_mode(0o555)).unwrap();
            // A privileged user ignores the mode bits, which would make every
            // test below pass without exercising anything.
            let probe = path.join(".probe");
            if std::fs::File::create(&probe).is_ok() {
                std::fs::remove_file(&probe).unwrap();
                panic!("this test needs a user the directory mode binds: run it as a non-root user");
            }
            Self(path)
        }
    }

    impl Drop for ReadOnly<'_> {
        fn drop(&mut self) {
            std::fs::set_permissions(self.0, PermissionsExt::from_mode(0o755)).unwrap();
        }
    }

    #[skuld::test]
    fn remove_of_an_absent_file_in_a_read_only_directory_is_absent() {
        let dir = dir();
        let _ro = ReadOnly::new(dir.path());

        let removal = VersionedFile::<DecisionFile>::new(dir.path()).remove();

        assert_eq!(removal.unwrap(), Removal::Absent);
    }

    #[skuld::test]
    fn move_aside_of_an_absent_file_in_a_read_only_directory_is_none() {
        let dir = dir();
        let _ro = ReadOnly::new(dir.path());

        let moved = VersionedFile::<DecisionFile>::new(dir.path()).move_aside();

        assert_eq!(moved.unwrap(), None);
    }

    #[skuld::test]
    fn an_absent_file_leaves_no_lock_file_behind() {
        let dir = dir();
        let file = VersionedFile::<DecisionFile>::new(dir.path());

        assert_eq!(file.remove().unwrap(), Removal::Absent);
        assert_eq!(file.move_aside().unwrap(), None);

        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "nothing was removed or moved"
        );
    }

    // The caller cannot lock the file, so it is no writer of it: it may still
    // learn that the file's role would leave it alone.
    #[skuld::test]
    fn remove_by_a_non_writer_answers_kept_where_the_role_keeps_the_file() {
        let dir = dir();
        let bytes = unreadable_bytes(CannotRead::Corrupt);
        put(&dir, "os-record.json", bytes);
        let _ro = ReadOnly::new(dir.path());

        let removal = VersionedFile::<OsRecordFile>::new(dir.path()).remove();

        assert_eq!(removal.unwrap(), Removal::Kept);
        assert_eq!(std::fs::read(dir.path().join("os-record.json")).unwrap(), bytes);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no lock file was made"
        );
    }

    /// The file is gone by the time it is read.
    struct Vanished;

    impl Fs for Vanished {
        fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
            Err(io::ErrorKind::NotFound.into())
        }
    }

    #[skuld::test]
    fn remove_by_a_non_writer_answers_absent_for_a_file_that_is_gone_when_read() {
        let dir = dir();
        put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);
        let _ro = ReadOnly::new(dir.path());

        let removal = VersionedFile::<DecisionFile>::with_fs(dir.path(), std::sync::Arc::new(Vanished)).remove();

        assert_eq!(removal.unwrap(), Removal::Absent);
    }

    #[skuld::test]
    fn remove_by_a_non_writer_is_the_lock_error_where_the_role_would_act() {
        for bytes in [
            &br#"{"version":1,"value":"v"}"#[..],
            unreadable_bytes(CannotRead::Corrupt),
        ] {
            let dir = dir();
            put(&dir, "decision.json", bytes);
            let _ro = ReadOnly::new(dir.path());

            let removal = VersionedFile::<DecisionFile>::new(dir.path()).remove();

            assert_eq!(removal.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
    }

    /// The file cannot be read, and the caller cannot lock it either.
    struct DeniedRead;

    impl Fs for DeniedRead {
        fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }

    #[skuld::test]
    fn remove_by_a_non_writer_over_an_io_failed_file_follows_the_io_failure_cell() {
        let dir = dir();
        put(&dir, "os-record.json", b"unread");
        put(&dir, "decision.json", b"unread");
        let _ro = ReadOnly::new(dir.path());

        let os_record = VersionedFile::<OsRecordFile>::with_fs(dir.path(), std::sync::Arc::new(DeniedRead));
        let decision = VersionedFile::<DecisionFile>::with_fs(dir.path(), std::sync::Arc::new(DeniedRead));

        assert_eq!(os_record.remove().unwrap(), Removal::Kept);
        assert_eq!(decision.remove().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(dir.path().join("decision.json")).unwrap(), b"unread");
    }

    #[skuld::test]
    fn a_file_that_is_there_but_cannot_be_locked_is_an_error_not_absent() {
        let dir = dir();
        put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);
        let _ro = ReadOnly::new(dir.path());
        let file = VersionedFile::<DecisionFile>::new(dir.path());

        assert_eq!(file.remove().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(file.move_aside().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}

// Unix: the lock's mode ===============================================================================================

#[cfg(unix)]
mod unix_mode {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    use super::*;
    use crate::versioned_file::Placement;

    /// Publishes the state file with this mode.
    struct Mode(u32);

    impl Placement for Mode {
        fn prepare_tmp(&self, tmp: &Path) -> io::Result<()> {
            std::fs::set_permissions(tmp, PermissionsExt::from_mode(self.0))
        }
    }

    fn mode_of(dir: &tempfile::TempDir, name: &str) -> u32 {
        std::fs::metadata(dir.path().join(name)).unwrap().permissions().mode() & 0o777
    }

    /// The lock `store` makes for a state file of `state_mode`.
    fn lock_mode_after_store(state_mode: u32) -> u32 {
        let dir = dir();
        VersionedFile::<DecisionFile>::new(dir.path())
            .store(&decision("v"), &Mode(state_mode))
            .unwrap();
        assert_eq!(
            mode_of(&dir, "decision.json"),
            state_mode,
            "the state file keeps its mode"
        );
        mode_of(&dir, "decision.json.lock")
    }

    // Each class gets read and write exactly where the state file gives it
    // write; the owner always keeps both, since it may change the file's mode.
    #[skuld::test]
    fn the_lock_is_open_to_the_classes_that_can_write_the_state_file() {
        for (state, lock) in [
            (0o644, 0o600),
            (0o664, 0o660),
            (0o640, 0o600),
            (0o620, 0o660),
            (0o602, 0o606),
            (0o666, 0o666),
            (0o600, 0o600),
            (0o444, 0o600),
            (0o755, 0o600),
        ] {
            assert_eq!(
                lock_mode_after_store(state),
                lock,
                "state file {state:o} must give a lock of {lock:o}"
            );
        }
    }

    #[skuld::test]
    fn remove_creates_a_missing_lock_for_the_files_writers_only() {
        for (state, lock) in [(0o644, 0o600), (0o664, 0o660)] {
            let dir = dir();
            let path = put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);
            std::fs::set_permissions(&path, PermissionsExt::from_mode(state)).unwrap();

            let removal = VersionedFile::<DecisionFile>::new(dir.path()).remove().unwrap();

            assert_eq!(removal, Removal::Removed);
            assert_eq!(mode_of(&dir, "decision.json.lock"), lock, "state file {state:o}");
        }
    }

    #[skuld::test]
    fn move_aside_creates_a_missing_lock_for_the_files_writers_only() {
        let dir = dir();
        let path = put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);
        std::fs::set_permissions(&path, PermissionsExt::from_mode(0o644)).unwrap();

        VersionedFile::<DecisionFile>::new(dir.path()).move_aside().unwrap();

        assert_eq!(mode_of(&dir, "decision.json.lock"), 0o600);
    }

    /// A 0644 state file and a lock anyone can open.
    fn dir_with_file_and_wide_lock() -> tempfile::TempDir {
        let dir = dir();
        let state = put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);
        std::fs::set_permissions(&state, PermissionsExt::from_mode(0o644)).unwrap();
        let lock = put(&dir, "decision.json.lock", b"");
        std::fs::set_permissions(&lock, PermissionsExt::from_mode(0o666)).unwrap();
        dir
    }

    #[skuld::test]
    fn store_narrows_a_lock_wider_than_its_files_writers() {
        let dir = dir_with_file_and_wide_lock();

        VersionedFile::<DecisionFile>::new(dir.path())
            .store(&decision("v"), &Mode(0o644))
            .unwrap();

        assert_eq!(mode_of(&dir, "decision.json.lock"), 0o600);
    }

    #[skuld::test]
    fn remove_narrows_a_lock_wider_than_its_files_writers() {
        let dir = dir_with_file_and_wide_lock();

        VersionedFile::<DecisionFile>::new(dir.path()).remove().unwrap();

        assert_eq!(mode_of(&dir, "decision.json.lock"), 0o600);
    }

    #[skuld::test]
    fn move_aside_narrows_a_lock_wider_than_its_files_writers() {
        let dir = dir_with_file_and_wide_lock();

        VersionedFile::<DecisionFile>::new(dir.path()).move_aside().unwrap();

        assert_eq!(mode_of(&dir, "decision.json.lock"), 0o600);
    }

    /// Records the lock file's access at the instant it exists.
    struct AtCreation(std::sync::Mutex<Vec<(u32, u32)>>);

    impl Fs for AtCreation {
        fn after_lock_created(&self, file: &std::fs::File) {
            let meta = file.metadata().unwrap();
            self.0.lock().unwrap().push((meta.mode() & 0o777, meta.uid()));
        }
    }

    // The lock gets its wider mode after it exists, so for that instant it must
    // be no wider than its creator alone.
    #[skuld::test]
    fn a_new_lock_is_closed_to_everyone_but_its_creator_when_it_first_exists() {
        let dir = dir();
        let fs = std::sync::Arc::new(AtCreation(Default::default()));
        let file = VersionedFile::<DecisionFile>::with_fs(dir.path(), fs.clone());

        file.store(&decision("v"), &Mode(0o666)).unwrap();

        // SAFETY: `geteuid` has no preconditions.
        let me = unsafe { libc::geteuid() };
        assert_eq!(*fs.0.lock().unwrap(), [(0o600, me)], "one lock, made owner-only");
        assert_eq!(
            mode_of(&dir, "decision.json.lock"),
            0o666,
            "and then given the writers' mode"
        );
    }

    #[skuld::test]
    fn the_lock_is_never_open_for_reading_by_a_principal_that_cannot_write() {
        let dir = dir();
        let file = VersionedFile::<DecisionFile>::new(dir.path());
        file.store(&decision("v"), &Mode(0o644)).unwrap();
        file.store(&decision("again"), &Mode(0o644)).unwrap();
        let state = mode_of(&dir, "decision.json");
        let lock = mode_of(&dir, "decision.json.lock");

        // Group and other can read the state file, and must not open its lock.
        assert_eq!(state & 0o044, 0o044);
        assert_eq!(lock & 0o077, 0, "{lock:o}");
    }

    // The lock follows the file as `place` leaves it, not the one it replaces.
    #[skuld::test]
    fn store_derives_the_lock_from_the_new_file_not_the_one_it_replaces() {
        let dir = dir();
        let old = put(&dir, "decision.json", br#"{"version":1,"value":"old"}"#);
        std::fs::set_permissions(&old, PermissionsExt::from_mode(0o666)).unwrap();

        VersionedFile::<DecisionFile>::new(dir.path())
            .store(&decision("new"), &Mode(0o600))
            .unwrap();

        assert_eq!(mode_of(&dir, "decision.json"), 0o600);
        assert_eq!(mode_of(&dir, "decision.json.lock"), 0o600);
    }

    #[skuld::test]
    fn the_lock_can_still_be_taken_again_by_the_writer() {
        let dir = dir();
        let file = VersionedFile::<DecisionFile>::new(dir.path());

        for round in 0..3 {
            file.store(&decision(&format!("v{round}")), &Mode(0o644)).unwrap();
        }

        assert_eq!(mode_of(&dir, "decision.json.lock"), 0o600);
        assert_eq!(file.remove().unwrap(), Removal::Removed);
    }

    #[skuld::test]
    fn a_default_placement_gives_the_lock_the_default_files_writers() {
        let dir = dir();
        VersionedFile::<DecisionFile>::new(dir.path())
            .store(&decision("v"), &plain())
            .unwrap();

        // A temp file is made 0600: only its owner writes it.
        assert_eq!(mode_of(&dir, "decision.json"), 0o600);
        assert_eq!(mode_of(&dir, "decision.json.lock"), 0o600);
    }
}
