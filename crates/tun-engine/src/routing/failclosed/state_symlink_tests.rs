//! The fail-closed state files are written as root into a state directory the interactive user may
//! own: a symlinked directory must not redirect any of them.

use std::path::PathBuf;

use util::dir::testing::{plant_link, user_dir, SystemScratch};

use super::{boottime_witness, lockdown_state, pf_record, CoverLock};

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

    assert!(lockdown_state::set_enabled(&CoverLock::acquire(&state_dir), true, None).is_err());

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
    boottime_witness::record_armed(&CoverLock::acquire(&state_dir), None);

    assert_eq!(
        present(&scratch, &names),
        before,
        "a state file was written in the system's folder"
    );
}

#[skuld::test]
fn failclosed_state_is_not_written_through_a_symlinked_state_directory() {
    use super::failclosed_state::{FailClosedState, STATE_FILE_NAME};
    let (_tmp, scratch, state_dir) = state_dir_linked_to_the_system();
    let before = present(&scratch, &[STATE_FILE_NAME]);
    let state = FailClosedState {
        pf_token: "1".into(),
        pf_was_enabled: true,
    };

    let lock = CoverLock::acquire(&state_dir);

    assert!(pf_record::swap(&lock, &state, None).is_err());

    assert_eq!(
        present(&scratch, &[STATE_FILE_NAME]),
        before,
        "a state file was written in the system's folder"
    );
}

#[skuld::test]
fn lockdown_pf_state_is_not_written_through_a_symlinked_state_directory() {
    use super::lockdown_pf_state::{LockdownPfState, STATE_FILE_NAME};
    let (_tmp, scratch, state_dir) = state_dir_linked_to_the_system();
    let before = present(&scratch, &[STATE_FILE_NAME]);
    let state = LockdownPfState {
        pf_token: "1".into(),
        main_snapshot: String::new(),
        nat_snapshot: String::new(),
        main_snapshot_captured: false,
    };

    let lock = CoverLock::acquire(&state_dir);

    assert!(pf_record::swap(&lock, &state, None).is_err());

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

    lockdown_state::set_enabled(&CoverLock::acquire(&state_dir), true, None).unwrap();

    assert!(real.join(lockdown_state::STATE_FILE_NAME).is_file());
}

// A name the user planted ---------------------------------------------------------------------------------------------
//
// The readers run as root or SYSTEM in a state directory the user may own, and open the name as `O_RDONLY`: a
// FIFO planted there makes a read by path wait for a writer, a link is read as whatever it points at. Each row
// writes a valid file, plants the name and reads again: the reader must not report the valid file the name leads to.

use util::dir::testing::{planted_name_is_not_read, PlantedName, Reader};

fn write_state(dir: &std::path::Path, name: &str, json: &[u8]) {
    util::dir::Dir::open(dir, true, None, util::dir::Principal::System)
        .unwrap()
        .write_atomic(std::ffi::OsStr::new(name), json, None, |_| Ok(()))
        .unwrap();
}

/// The readers by name, and what each reports of a valid file.
fn readers() -> Vec<(&'static str, Reader<'static>)> {
    let mut readers = vec![
        (
            "lockdown_state::load_intent",
            Reader {
                file: lockdown_state::STATE_FILE_NAME,
                write_valid: &|dir| lockdown_state::set_enabled(&CoverLock::acquire(dir), true, None).unwrap(),
                reads_it: &|dir| lockdown_state::load_intent(dir) == lockdown_state::Intent::On,
            },
        ),
        (
            "boottime_witness::load",
            Reader {
                file: boottime_witness::STATE_FILE_NAME,
                write_valid: &|dir| boottime_witness::record_armed(&CoverLock::acquire(dir), None),
                reads_it: &|dir| boottime_witness::load(dir) == super::ArmingWitness::Armed,
            },
        ),
    ];
    readers.extend(pf_readers());
    readers
}

/// The two readers of the pf state.
fn pf_readers() -> Vec<(&'static str, Reader<'static>)> {
    use super::failclosed_state::{self, FailClosedState};
    use super::lockdown_pf_state::{self, LockdownPfState};
    use super::StateFile;
    vec![
        (
            "pf_record::read::<FailClosedState>",
            Reader {
                file: failclosed_state::STATE_FILE_NAME,
                write_valid: &|dir| {
                    write_state(
                        dir,
                        failclosed_state::STATE_FILE_NAME,
                        br#"{"version":1,"pf_token":"1","pf_was_enabled":true}"#,
                    );
                },
                reads_it: &|dir| matches!(pf_record::read::<FailClosedState>(dir), StateFile::Present(_)),
            },
        ),
        (
            "pf_record::read::<LockdownPfState>",
            Reader {
                file: lockdown_pf_state::STATE_FILE_NAME,
                write_valid: &|dir| {
                    write_state(
                        dir,
                        lockdown_pf_state::STATE_FILE_NAME,
                        br#"{"version":1,"pf_token":"1","main_snapshot":"","nat_snapshot":"","main_snapshot_captured":false}"#,
                    );
                },
                reads_it: &|dir| matches!(pf_record::read::<LockdownPfState>(dir), StateFile::Present(_)),
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

#[skuld::test]
fn no_state_reader_reads_a_hard_link_the_system_would_not_have_made() {
    // Refused when the runner is the system (a planted second name of a file it owns), read when it is a user.
    let failures = readers_that_read_a_planted_name(PlantedName::HardLink);

    assert!(failures.is_empty(), "{failures:#?}");
}

#[cfg(unix)]
#[skuld::test]
fn no_state_reader_waits_on_a_fifo_planted_at_its_name() {
    let failures = readers_that_read_a_planted_name(PlantedName::Fifo);

    assert!(failures.is_empty(), "{failures:#?}");
}

// What a reader says about a file it cannot parse ---------------------------------------------------------------------
//
// A user can put a file they cannot read at a state name: a system file moved into their folder keeps its owner and
// its one link. The parse failure the reader logs goes to `bridge.log`, which the elevated bridge hands to the user,
// so it carries a category and a position and never a fragment of the file.

const ECHOED_SECRET: &str = "hunter2-SECRET";

/// The warnings `read` logs when `file` in a fresh folder is the object `{ <head> "<secret>" }`: `head` ends at a key
/// whose value is a string where something else belongs, and `serde_json`'s own message for that quotes the string.
fn warnings_for_a_file_that_quotes_a_secret(file: &str, head: &str, read: fn(&std::path::Path)) -> String {
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(file), format!(r#"{{{head}"{ECHOED_SECRET}"}}"#)).unwrap();
    let writer = garter::test_utils::WaitableWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        read(tmp.path());
    }
    writer.snapshot()
}

/// A reader that logs a parse failure: its name, the file it reads, the start of a document of that file that puts a
/// string where it does not belong (a framed file's payload failure keeps a position; its framing has none), and a
/// call of it.
type ParseFailureReader = (&'static str, &'static str, &'static str, fn(&std::path::Path));

fn parse_failure_readers() -> Vec<ParseFailureReader> {
    let mut readers: Vec<ParseFailureReader> = vec![
        (
            "lockdown_state::load_intent",
            lockdown_state::STATE_FILE_NAME,
            r#""version":1,"enabled":"#,
            |dir| {
                let _ = lockdown_state::load_intent(dir);
            },
        ),
        (
            "boottime_witness::load",
            boottime_witness::STATE_FILE_NAME,
            r#""version":1,"armed":"#,
            |dir| {
                let _ = boottime_witness::load(dir);
            },
        ),
    ];
    {
        use super::failclosed_state::{self, FailClosedState};
        use super::lockdown_pf_state::{self, LockdownPfState};
        readers.push((
            "pf_record::read::<FailClosedState>",
            failclosed_state::STATE_FILE_NAME,
            r#""version":1,"pf_token":"1","pf_was_enabled":"#,
            |dir| {
                let _ = pf_record::read::<FailClosedState>(dir);
            },
        ));
        readers.push((
            "pf_record::read::<LockdownPfState>",
            lockdown_pf_state::STATE_FILE_NAME,
            r#""version":1,"pf_token":"1","main_snapshot":"","nat_snapshot":"","main_snapshot_captured":"#,
            |dir| {
                let _ = pf_record::read::<LockdownPfState>(dir);
            },
        ));
    }
    readers
}

#[skuld::test]
fn no_state_reader_logs_a_fragment_of_a_file_it_cannot_parse() {
    let mut failures = Vec::new();
    for (name, file, head, read) in parse_failure_readers() {
        let logs = warnings_for_a_file_that_quotes_a_secret(file, head, read);
        if logs.contains(ECHOED_SECRET) {
            failures.push(format!("{name} logged the file's content: {logs}"));
        } else if !logs.contains("line 1") {
            failures.push(format!("{name}: the warning lost its position: {logs}"));
        }
    }

    assert!(failures.is_empty(), "{failures:#?}");
}
