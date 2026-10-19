//! Whatever sits at `<name>.lock` that the type did not make, `store`,
//! `remove` and `move_aside` must come back with an answer. None may wait for
//! it to change, follow it to another file, or leave the directory different.

use std::io;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::{DefaultPlacement, StoreError, VersionedFile};
use crate::versioned_file::fixtures::{dir, put, DecisionFile};

const STATE: &[u8] = br#"{"version":1,"value":"v"}"#;

#[derive(Debug, Clone, Copy)]
enum Op {
    Store,
    Remove,
    MoveAside,
}

const OPS: [Op; 3] = [Op::Store, Op::Remove, Op::MoveAside];

/// What the operation answered, reduced to whether it did something.
fn run(dir: &TempDir, op: Op) -> io::Result<()> {
    let file = VersionedFile::<DecisionFile>::new(dir.path());
    match op {
        Op::Store => file
            .store(
                &DecisionFile {
                    value: "new".to_string(),
                },
                &DefaultPlacement::default(),
            )
            .map_err(|e| match e {
                StoreError::Io(e) => e,
                other => io::Error::other(other),
            }),
        Op::Remove => file.remove().map(drop),
        Op::MoveAside => file.move_aside().map(drop),
    }
}

fn entries(dir: &TempDir) -> Vec<String> {
    let mut all: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    all.sort();
    all
}

fn lock_path(dir: &TempDir) -> PathBuf {
    dir.path().join("decision.json.lock")
}

/// A directory holding a state file and whatever `make` puts at the lock path.
fn dir_with_lock_made_by(make: impl FnOnce(&Path)) -> TempDir {
    let dir = dir();
    put(&dir, "decision.json", STATE);
    make(&lock_path(&dir));
    dir
}

/// Every operation, each on a directory of its own, is refused and changes
/// nothing: not the state file, and not what is at the lock path.
fn refused_and_nothing_changes(make: impl Fn(&Path)) {
    for op in OPS {
        let dir = dir_with_lock_made_by(&make);
        let before = entries(&dir);

        let answer = run(&dir, op);

        assert!(answer.is_err(), "{op:?} answered {answer:?}");
        assert_eq!(entries(&dir), before, "{op:?} changed the directory");
        assert_eq!(
            std::fs::read(dir.path().join("decision.json")).unwrap(),
            STATE,
            "{op:?}"
        );
    }
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::*;

    #[skuld::test]
    fn a_dangling_symlink_at_the_lock_path_is_refused() {
        let away = dir();
        let nowhere = away.path().join("nowhere");

        refused_and_nothing_changes(|lock| symlink(&nowhere, lock).unwrap());

        assert!(!nowhere.exists(), "the link's target was created through it");
    }

    #[skuld::test]
    fn a_symlink_to_a_file_elsewhere_is_refused_and_the_file_is_left_alone() {
        let away = dir();
        let elsewhere = put(&away, "elsewhere", b"not a lock");
        std::fs::set_permissions(&elsewhere, PermissionsExt::from_mode(0o666)).unwrap();

        refused_and_nothing_changes(|lock| symlink(&elsewhere, lock).unwrap());

        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"not a lock");
        assert_eq!(
            std::fs::metadata(&elsewhere).unwrap().permissions().mode() & 0o777,
            0o666,
            "the file the link names was given a lock's mode"
        );
    }

    #[skuld::test]
    fn a_directory_at_the_lock_path_is_refused() {
        refused_and_nothing_changes(|lock| std::fs::create_dir(lock).unwrap());
    }

    // A pipe opens for reading and writing without waiting, so only the check
    // that the path is a regular file refuses it.
    #[skuld::test]
    fn a_pipe_at_the_lock_path_is_refused() {
        refused_and_nothing_changes(|lock| {
            let path = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(lock.as_os_str())).unwrap();
            // SAFETY: `path` is a valid NUL-terminated path.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0, "mkfifo");
        });
    }

    #[skuld::test]
    fn a_lock_file_the_caller_cannot_open_answers_instead_of_waiting() {
        for op in OPS {
            let dir = dir_with_lock_made_by(|lock| {
                std::fs::write(lock, b"").unwrap();
                std::fs::set_permissions(lock, PermissionsExt::from_mode(0o000)).unwrap();
            });

            // Refused for a user the mode binds; opened and brought right by root.
            let _ = run(&dir, op);
        }
    }

    #[skuld::test]
    fn a_lock_file_of_the_wrong_mode_is_made_right_by_every_operation() {
        for op in OPS {
            let dir = dir_with_lock_made_by(|lock| {
                std::fs::write(lock, b"").unwrap();
                std::fs::set_permissions(lock, PermissionsExt::from_mode(0o666)).unwrap();
            });

            run(&dir, op).unwrap_or_else(|e| panic!("{op:?}: {e}"));

            let mode = std::fs::metadata(lock_path(&dir)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{op:?}");
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::os::windows::fs::symlink_file;

    use super::*;
    use crate::versioned_file::store::store_access_windows_tests::{aces, set_aces, Ace, EVERYONE};

    /// Symlinks need `SeCreateSymbolicLinkPrivilege`: an elevated token, or
    /// Developer Mode.
    fn link(target: &Path, at: &Path) {
        symlink_file(target, at).unwrap_or_else(|e| {
            panic!("this test needs the privilege to create symlinks (an elevated token or Developer Mode): {e}")
        });
    }

    #[skuld::test]
    fn a_dangling_symlink_at_the_lock_path_is_refused() {
        let away = dir();
        let nowhere = away.path().join("nowhere");

        refused_and_nothing_changes(|lock| link(&nowhere, lock));

        assert!(!nowhere.exists(), "the link's target was created through it");
    }

    #[skuld::test]
    fn a_symlink_to_a_file_elsewhere_is_refused_and_the_file_is_left_alone() {
        let away = dir();
        let elsewhere = put(&away, "elsewhere", b"not a lock");
        let dacl_before = aces(&elsewhere);

        refused_and_nothing_changes(|lock| link(&elsewhere, lock));

        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"not a lock");
        assert_eq!(
            aces(&elsewhere),
            dacl_before,
            "the file the link names was given a lock's DACL"
        );
    }

    #[skuld::test]
    fn a_directory_at_the_lock_path_is_refused() {
        refused_and_nothing_changes(|lock| std::fs::create_dir(lock).unwrap());
    }

    #[skuld::test]
    fn a_lock_file_the_caller_cannot_open_answers_instead_of_waiting() {
        for op in OPS {
            let dir = dir_with_lock_made_by(|lock| {
                std::fs::write(lock, b"").unwrap();
                set_aces(lock, &[Ace::deny(&EVERYONE, 0x1F_01FF)]);
            });

            let _ = run(&dir, op);
        }
    }
}
