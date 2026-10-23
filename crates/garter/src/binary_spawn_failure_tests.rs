// A spawn that never ran the program ----------------------------------------------------------------------------------
//
// cosca reports a failed `exec` of a tokio `Command` on Unix as `MayHaveStarted`, because it cannot prove the program never
// ran. When the kernel refused the file, that text is wrong for the reader: it says a child "had been reaped by someone
// else" or "may still be running" where the OS error says what is the matter.
#![allow(clippy::disallowed_methods)] // CancellationToken::new roots the shutdown of a run that never starts

use std::os::unix::fs::PermissionsExt as _;

use cosca::error::{ChildFate, Error};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::binary::{spawn_failure_text, BinaryPlugin};
use crate::plugin::ChainPlugin;

/// The message `BinaryPlugin::run` fails with when it cannot spawn `plugin`.
async fn spawn_failure_of(plugin: BinaryPlugin) -> String {
    let (ready, _ready_rx) = oneshot::channel();
    let error = plugin
        .run(
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
            CancellationToken::new(),
            ready,
        )
        .await
        .expect_err("a plugin that cannot be spawned must fail the run");
    error.to_string()
}

/// `message` is the spawn failure for `errno`: the OS error, and nothing claiming a child exists.
fn assert_reports_only_the_os_error(message: &str, errno: i32) {
    let os_error = std::io::Error::from_raw_os_error(errno).to_string();
    assert!(message.contains("failed to spawn"), "{message}");
    assert!(message.contains(&os_error), "{message}: expected `{os_error}`");
    assert!(!message.contains("may have started"), "{message}");
    assert!(!message.contains("may still be running"), "{message}");
}

#[skuld::test]
async fn a_missing_plugin_reports_the_os_error() {
    let dir = tempfile::tempdir().unwrap();

    let message = spawn_failure_of(BinaryPlugin::new(dir.path().join("no-such-plugin"), None)).await;

    assert_reports_only_the_os_error(&message, libc::ENOENT);
}

#[skuld::test]
async fn a_non_executable_plugin_reports_the_os_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-executable");
    std::fs::write(&path, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let message = spawn_failure_of(BinaryPlugin::new(path, None)).await;

    assert_reports_only_the_os_error(&message, libc::EACCES);
}

#[skuld::test]
async fn a_plugin_path_through_a_file_reports_the_os_error() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a-file");
    std::fs::write(&file, b"").unwrap();

    let message = spawn_failure_of(BinaryPlugin::new(file.join("plugin"), None)).await;

    assert_reports_only_the_os_error(&message, libc::ENOTDIR);
}

#[skuld::test]
async fn a_plugin_that_is_a_symlink_loop_reports_the_os_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("loop");
    std::os::unix::fs::symlink(&path, &path).unwrap();

    let message = spawn_failure_of(BinaryPlugin::new(path, None)).await;

    assert_reports_only_the_os_error(&message, libc::ELOOP);
}

#[skuld::test]
async fn a_plugin_with_an_overlong_name_reports_the_os_error() {
    let dir = tempfile::tempdir().unwrap();
    // NAME_MAX is 255 on Linux and macOS.
    let path = dir.path().join("a".repeat(300));

    let message = spawn_failure_of(BinaryPlugin::new(path, None)).await;

    assert_reports_only_the_os_error(&message, libc::ENAMETOOLONG);
}

#[skuld::test]
async fn a_plugin_whose_environment_is_too_big_reports_the_os_error() {
    // Past ARG_MAX (1 MiB on macOS) and past Linux's per-string limit (128 KiB).
    let plugin =
        BinaryPlugin::new(std::env::current_exe().unwrap(), None).env("GARTER_TEST_TOO_BIG", "x".repeat(4 << 20));

    let message = spawn_failure_of(plugin).await;

    assert_reports_only_the_os_error(&message, libc::E2BIG);
}

fn may_have_started(fate: ChildFate, wrapper_elevated: bool) -> Error {
    may_have_started_from(fate, wrapper_elevated, std::io::Error::from_raw_os_error(libc::ENOENT))
}

fn may_have_started_from(fate: ChildFate, wrapper_elevated: bool, cause: std::io::Error) -> Error {
    Error::MayHaveStarted {
        fate,
        wrapper_elevated,
        source: Box::new(Error::Io(cause)),
    }
}

/// A child that may still be running is a fact the user can act on; cosca's text carries it. `EMFILE` is a
/// cause tokio's own setup can fail with after the program started.
#[skuld::test]
fn a_child_that_may_still_run_keeps_the_cosca_text() {
    for fate in [ChildFate::Running { id: None }, ChildFate::Unknown] {
        let error = may_have_started_from(fate, false, std::io::Error::from_raw_os_error(libc::EMFILE));
        assert_eq!(spawn_failure_text(&error), error.to_string(), "{fate:?}");
    }
}

/// Off Linux cosca answers a failed `exec` with a child that may be running. These are the errnos that macOS's
/// `execve(2)` and `posix_spawn(2)` document (ERRORS) and that nothing after the exec can return (tokio's `kevent`
/// registration, `fcntl` and `sigaction`; cosca's own errors are not `Io` carrying an errno): the program never ran.
#[cfg(target_os = "macos")]
const REFUSED_BY_EXEC_ONLY: [i32; 10] = [
    libc::E2BIG,
    libc::EACCES,
    libc::EBADARCH,
    libc::EIO,
    libc::ELOOP,
    libc::ENAMETOOLONG,
    libc::ENOENT,
    libc::ENOEXEC,
    libc::ENOTDIR,
    libc::ETXTBSY,
];

/// Errnos that tokio's or cosca's steps after a successful spawn can return (`kevent`: ENOMEM, EFAULT, EINVAL, EBADF, ENOTSUP;
/// `fcntl`: EBADF, EPERM; `sigaction`: EFAULT, EINVAL) or that no exec documents (EPERM, EAGAIN, EMFILE, ENFILE): the
/// program may be running, or nothing says it is not.
#[cfg(target_os = "macos")]
const NOT_PROVABLY_UNSTARTED: [i32; 9] = [
    libc::ENOMEM,
    libc::EFAULT,
    libc::EINVAL,
    libc::EBADF,
    libc::EPERM,
    libc::EAGAIN,
    libc::EMFILE,
    libc::ENFILE,
    libc::ENOTSUP,
];

#[cfg(target_os = "macos")]
#[skuld::test]
fn a_failed_exec_with_an_unreported_child_reports_the_os_error() {
    for errno in REFUSED_BY_EXEC_ONLY {
        let error = may_have_started_from(
            ChildFate::Running { id: None },
            false,
            std::io::Error::from_raw_os_error(errno),
        );
        let text = spawn_failure_text(&error);
        assert_eq!(
            text,
            std::io::Error::from_raw_os_error(errno).to_string(),
            "errno {errno}"
        );
    }
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn an_errno_the_exec_does_not_own_keeps_the_cosca_text_for_an_unreported_child() {
    for errno in NOT_PROVABLY_UNSTARTED {
        let error = may_have_started_from(
            ChildFate::Running { id: None },
            false,
            std::io::Error::from_raw_os_error(errno),
        );
        assert_eq!(spawn_failure_text(&error), error.to_string(), "errno {errno}");
    }
}

/// An `Io` error that carries no errno cannot be an exec refusal, whatever its kind says.
#[cfg(target_os = "macos")]
#[skuld::test]
fn an_error_with_no_errno_keeps_the_cosca_text_for_an_unreported_child() {
    let error = may_have_started_from(
        ChildFate::Running { id: None },
        false,
        std::io::Error::new(std::io::ErrorKind::NotFound, "wrapped"),
    );
    assert_eq!(spawn_failure_text(&error), error.to_string());
}

/// Linux's handshake already says whether a child is left, so its `Running` is never an exec failure.
#[cfg(target_os = "linux")]
#[skuld::test]
fn on_linux_a_running_child_keeps_the_cosca_text_whatever_the_cause() {
    let error = may_have_started(ChildFate::Running { id: None }, false);
    assert_eq!(spawn_failure_text(&error), error.to_string());
}

/// A wrapper that runs another program is not the program that failed to start.
#[cfg(not(target_os = "linux"))]
#[skuld::test]
fn an_unreported_elevation_backend_keeps_the_cosca_text() {
    let error = may_have_started(ChildFate::Running { id: None }, true);
    assert_eq!(spawn_failure_text(&error), error.to_string());
}

/// The fate of an elevation backend says nothing about the elevated program behind it.
#[skuld::test]
fn an_elevation_backend_keeps_the_cosca_text() {
    let error = may_have_started(ChildFate::Reaped, true);
    assert_eq!(spawn_failure_text(&error), error.to_string());
}

#[skuld::test]
fn a_child_that_is_gone_reports_only_the_cause() {
    for fate in [ChildFate::Reaped, ChildFate::Killed, ChildFate::Gone] {
        let text = spawn_failure_text(&may_have_started(fate, false));
        assert!(text.contains("No such file or directory"), "{fate:?}: {text}");
        assert!(!text.contains("may have started"), "{fate:?}: {text}");
    }
}

#[skuld::test]
fn an_error_that_is_not_may_have_started_is_unchanged() {
    let error = Error::Io(std::io::Error::from_raw_os_error(13));
    assert_eq!(spawn_failure_text(&error), error.to_string());
}
