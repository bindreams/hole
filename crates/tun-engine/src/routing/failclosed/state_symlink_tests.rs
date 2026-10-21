//! The fail-closed state files are written as root into a state directory the interactive user may
//! own: a symlinked directory must not redirect any of them.

use std::path::{Path, PathBuf};

use super::{boottime_witness, lockdown_state};

/// A symlink to the directory `target` at `link`, of the kind an unprivileged user can plant. Run as
/// root, the link is given away so that it is no longer root's own.
fn plant_symlink(target: &Path, link: &Path) {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(target_os = "macos")]
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            std::os::unix::fs::lchown(link, Some(65534), Some(65534)).unwrap();
        }
    }
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(target, link).unwrap();
}

/// A state directory that is a symlink to `outside`, which is empty.
fn symlinked_state_dir() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let state_dir = tmp.path().join("state");
    plant_symlink(&outside, &state_dir);
    (tmp, outside, state_dir)
}

fn assert_nothing_outside(outside: &Path) {
    assert!(
        std::fs::read_dir(outside).unwrap().next().is_none(),
        "a state file was written outside the state directory"
    );
}

#[skuld::test]
fn lockdown_state_is_not_written_through_a_symlinked_state_directory() {
    let (_tmp, outside, state_dir) = symlinked_state_dir();
    let state = lockdown_state::LockdownState {
        version: lockdown_state::SCHEMA_VERSION,
        enabled: true,
    };

    assert!(lockdown_state::save(&state_dir, &state, None).is_err());

    assert_nothing_outside(&outside);
}

#[skuld::test]
fn the_boottime_witness_is_not_written_through_a_symlinked_state_directory() {
    let (_tmp, outside, state_dir) = symlinked_state_dir();

    // Reports no error by design; it must still write nothing.
    boottime_witness::record_armed(&state_dir, None);

    assert_nothing_outside(&outside);
}

#[skuld::test]
#[cfg(target_os = "macos")]
fn failclosed_state_is_not_written_through_a_symlinked_state_directory() {
    use super::failclosed_state::{save, FailClosedState, SCHEMA_VERSION};
    let (_tmp, outside, state_dir) = symlinked_state_dir();
    let state = FailClosedState {
        version: SCHEMA_VERSION,
        pf_token: "1".into(),
        pf_was_enabled: true,
    };

    assert!(save(&state_dir, &state, None).is_err());

    assert_nothing_outside(&outside);
}

#[skuld::test]
#[cfg(target_os = "macos")]
fn lockdown_pf_state_is_not_written_through_a_symlinked_state_directory() {
    use super::lockdown_pf_state::{save, LockdownPfState, SCHEMA_VERSION};
    let (_tmp, outside, state_dir) = symlinked_state_dir();
    let state = LockdownPfState {
        version: SCHEMA_VERSION,
        pf_token: "1".into(),
        main_snapshot: String::new(),
        nat_snapshot: String::new(),
        main_snapshot_captured: false,
    };

    assert!(save(&state_dir, &state, None).is_err());

    assert_nothing_outside(&outside);
}
