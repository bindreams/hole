//! The fail-closed state files are written as root into a state directory the interactive user may
//! own: a symlinked directory must not redirect any of them.

use std::path::PathBuf;

use util::dir::testing::{plant_link, user_dir, SystemScratch};

use super::{boottime_witness, lockdown_state};

/// A state directory that is a link to the folder the system owns, and the system's folder to look in: it is
/// shared, so what it held before is what it must hold after.
fn state_dir_linked_to_the_system() -> (tempfile::TempDir, SystemScratch, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    let state_dir = tmp.path().join("state");
    plant_link(scratch.root(), &state_dir);
    (tmp, scratch, state_dir)
}

/// Whether each of `names` is in the system's folder.
fn present(scratch: &SystemScratch, names: &[&str]) -> Vec<bool> {
    names.iter().map(|name| scratch.root().join(name).exists()).collect()
}

#[skuld::test]
fn lockdown_state_is_not_written_through_a_symlinked_state_directory() {
    let (_tmp, scratch, state_dir) = state_dir_linked_to_the_system();
    let names = [lockdown_state::STATE_FILE_NAME];
    let before = present(&scratch, &names);
    let state = lockdown_state::LockdownState {
        version: lockdown_state::SCHEMA_VERSION,
        enabled: true,
    };

    assert!(lockdown_state::save(&state_dir, &state, None).is_err());

    assert_eq!(
        present(&scratch, &names),
        before,
        "a state file was written in the system's folder"
    );
}

#[skuld::test]
fn the_boottime_witness_is_not_written_through_a_symlinked_state_directory() {
    let (_tmp, scratch, state_dir) = state_dir_linked_to_the_system();
    let names = [boottime_witness::STATE_FILE_NAME];
    let before = present(&scratch, &names);

    // Reports no error by design; it must still write nothing.
    boottime_witness::record_armed(&state_dir, None);

    assert_eq!(
        present(&scratch, &names),
        before,
        "a state file was written in the system's folder"
    );
}

#[skuld::test]
#[cfg(target_os = "macos")]
fn failclosed_state_is_not_written_through_a_symlinked_state_directory() {
    use super::failclosed_state::{save, FailClosedState, SCHEMA_VERSION, STATE_FILE_NAME};
    let (_tmp, scratch, state_dir) = state_dir_linked_to_the_system();
    let before = present(&scratch, &[STATE_FILE_NAME]);
    let state = FailClosedState {
        version: SCHEMA_VERSION,
        pf_token: "1".into(),
        pf_was_enabled: true,
    };

    assert!(save(&state_dir, &state, None).is_err());

    assert_eq!(
        present(&scratch, &[STATE_FILE_NAME]),
        before,
        "a state file was written in the system's folder"
    );
}

#[skuld::test]
#[cfg(target_os = "macos")]
fn lockdown_pf_state_is_not_written_through_a_symlinked_state_directory() {
    use super::lockdown_pf_state::{save, LockdownPfState, SCHEMA_VERSION, STATE_FILE_NAME};
    let (_tmp, scratch, state_dir) = state_dir_linked_to_the_system();
    let before = present(&scratch, &[STATE_FILE_NAME]);
    let state = LockdownPfState {
        version: SCHEMA_VERSION,
        pf_token: "1".into(),
        main_snapshot: String::new(),
        nat_snapshot: String::new(),
        main_snapshot_captured: false,
    };

    assert!(save(&state_dir, &state, None).is_err());

    assert_eq!(
        present(&scratch, &[STATE_FILE_NAME]),
        before,
        "a state file was written in the system's folder"
    );
}

#[skuld::test]
fn lockdown_state_is_written_through_a_users_link_to_the_users_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    user_dir(&real);
    let state_dir = tmp.path().join("state");
    plant_link(&real, &state_dir);
    let state = lockdown_state::LockdownState {
        version: lockdown_state::SCHEMA_VERSION,
        enabled: true,
    };

    lockdown_state::save(&state_dir, &state, None).unwrap();

    assert!(real.join(lockdown_state::STATE_FILE_NAME).is_file());
}

// A name the user planted ---------------------------------------------------------------------------------------------
//
// The readers run as root or SYSTEM in a state directory the user may own, and open the name as `O_RDONLY`: a
// FIFO planted there makes a read by path wait for a writer, a link is read as whatever it points at. Each row
// writes a valid file, plants the name and reads again: the reader must not report the valid file the name leads to.

use util::dir::testing::{planted_name_is_not_read, PlantedName, Reader};

#[cfg(target_os = "macos")]
fn write_state(dir: &std::path::Path, name: &str, json: &[u8]) {
    util::dir::write_state_file(dir, std::ffi::OsStr::new(name), json, None).unwrap();
}

/// The readers by name, and what each reports of a valid file.
fn readers() -> Vec<(&'static str, Reader<'static>)> {
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut readers = vec![
        (
            "lockdown_state::load_intent",
            Reader {
                file: lockdown_state::STATE_FILE_NAME,
                write_valid: &|dir| {
                    let state = lockdown_state::LockdownState {
                        version: lockdown_state::SCHEMA_VERSION,
                        enabled: true,
                    };
                    lockdown_state::save(dir, &state, None).unwrap();
                },
                reads_it: &|dir| lockdown_state::load_intent(dir) == lockdown_state::Intent::On,
            },
        ),
        (
            "boottime_witness::load",
            Reader {
                file: boottime_witness::STATE_FILE_NAME,
                write_valid: &|dir| boottime_witness::record_armed(dir, None),
                reads_it: &|dir| boottime_witness::load(dir) == super::ArmingWitness::Armed,
            },
        ),
    ];
    #[cfg(target_os = "macos")]
    readers.extend(pf_readers());
    readers
}

/// The two readers of the pf state, which only macOS compiles.
#[cfg(target_os = "macos")]
fn pf_readers() -> Vec<(&'static str, Reader<'static>)> {
    use super::{failclosed_state, lockdown_pf_state, StateFile};
    vec![
        (
            "failclosed_state::load_presence",
            Reader {
                file: failclosed_state::STATE_FILE_NAME,
                write_valid: &|dir| {
                    let state = failclosed_state::FailClosedState {
                        version: failclosed_state::SCHEMA_VERSION,
                        pf_token: "1".into(),
                        pf_was_enabled: true,
                    };
                    write_state(
                        dir,
                        failclosed_state::STATE_FILE_NAME,
                        &serde_json::to_vec(&state).unwrap(),
                    );
                },
                reads_it: &|dir| matches!(failclosed_state::load_presence(dir), StateFile::Present(_)),
            },
        ),
        (
            "lockdown_pf_state::load_presence",
            Reader {
                file: lockdown_pf_state::STATE_FILE_NAME,
                write_valid: &|dir| {
                    let state = lockdown_pf_state::LockdownPfState {
                        version: lockdown_pf_state::SCHEMA_VERSION,
                        pf_token: "1".into(),
                        main_snapshot: String::new(),
                        nat_snapshot: String::new(),
                        main_snapshot_captured: false,
                    };
                    write_state(
                        dir,
                        lockdown_pf_state::STATE_FILE_NAME,
                        &serde_json::to_vec(&state).unwrap(),
                    );
                },
                reads_it: &|dir| matches!(lockdown_pf_state::load_presence(dir), StateFile::Present(_)),
            },
        ),
    ]
}

fn readers_that_read_a_planted_name(kind: PlantedName) -> Vec<String> {
    let mut failures = Vec::new();
    for (name, reader) in readers() {
        let tmp = tempfile::tempdir().unwrap();
        if let Err(why) = planted_name_is_not_read(tmp.path(), kind, &reader) {
            failures.push(format!("{name}: {why}"));
        }
    }
    failures
}

#[skuld::test]
fn no_state_reader_reads_through_a_symlink_planted_at_its_name() {
    let failures = readers_that_read_a_planted_name(PlantedName::SymlinkToFile);

    assert!(failures.is_empty(), "{failures:#?}");
}

#[cfg(unix)]
#[skuld::test]
fn no_state_reader_waits_on_a_fifo_planted_at_its_name() {
    let failures = readers_that_read_a_planted_name(PlantedName::Fifo);

    assert!(failures.is_empty(), "{failures:#?}");
}
