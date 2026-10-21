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
