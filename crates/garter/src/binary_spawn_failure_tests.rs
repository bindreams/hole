// A failed plugin spawn is an error that names the plugin, with the OS error as its source, unless a child may still run
// (see `spawn_failure`).
#![allow(clippy::disallowed_methods)] // CancellationToken::new roots the shutdown of a run that never starts

use std::os::unix::fs::PermissionsExt as _;

use cosca::error::{ChildFate, Error};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::binary::{spawn_failure, BinaryPlugin};
use crate::plugin::ChainPlugin;

use std::error::Error as _;

/// The error `BinaryPlugin::run` fails with when it cannot spawn `plugin`.
async fn spawn_failure_of(plugin: BinaryPlugin) -> crate::Error {
    let (ready, _ready_rx) = oneshot::channel();
    plugin
        .run(
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
            CancellationToken::new(),
            ready,
        )
        .await
        .expect_err("a plugin that cannot be spawned must fail the run")
}

/// `error` is the spawn failure of the plugin `name` for `errno`: it names the plugin and not where it lives, the OS
/// error is its source, and nothing claims a child exists. `dir` is the plugin's directory.
fn assert_reports_only_the_os_error(error: &crate::Error, name: &str, dir: &std::path::Path, errno: i32) {
    let os_error = std::io::Error::from_raw_os_error(errno).to_string();
    assert!(
        matches!(error, crate::Error::Spawn { plugin, .. } if plugin == name),
        "{error:?}"
    );
    assert_eq!(error.to_string(), format!("could not spawn plugin '{name}'"));
    let dir_name = dir.file_name().unwrap().to_string_lossy().into_owned();
    assert!(!error.to_string().contains(&dir_name), "{error}");
    let cause = error.source().expect("the cause is the source").to_string();
    assert!(cause.contains(&os_error), "{cause}: expected `{os_error}`");
    assert!(!cause.contains("may have started"), "{cause}");
    assert!(!cause.contains("may still be running"), "{cause}");
}

/// `error` is the spawn failure for `errno` of a child that may still run: an unconfirmed stop naming `name`, with
/// cosca's text as its cause.
fn assert_is_an_unconfirmed_stop(error: &crate::Error, name: &str, errno: i32) {
    let os_error = std::io::Error::from_raw_os_error(errno).to_string();
    assert!(
        matches!(error, crate::Error::StopUnconfirmed { plugins, .. } if plugins == &[name]),
        "{error:?}"
    );
    assert!(!error.stop_confirmed());
    let cause = error.source().expect("the cause is the source").to_string();
    assert!(cause.contains(&os_error), "{cause}: expected `{os_error}`");
    assert!(cause.contains("may have started"), "{cause}");
    assert!(cause.contains("may still be running"), "{cause}");
}

/// What a real refused `exec` of `name` for `errno` reads as. On Linux the pidfd handshake proves the child never ran,
/// so it is a spawn failure. On macOS cosca reports `Running { id: None }` for any failed spawn, and an unreported
/// child is not proven gone, so it is an unconfirmed stop until cosca can tell an exec failure from a failed setup
/// (https://github.com/bindreams/cosca/issues/964).
fn assert_refused_spawn(error: &crate::Error, name: &str, dir: &std::path::Path, errno: i32) {
    if cfg!(target_os = "macos") {
        assert_is_an_unconfirmed_stop(error, name, errno);
    } else {
        assert_reports_only_the_os_error(error, name, dir, errno);
    }
}

#[skuld::test]
async fn a_missing_plugin_is_refused() {
    let dir = tempfile::tempdir().unwrap();

    let error = spawn_failure_of(BinaryPlugin::new(dir.path().join("no-such-plugin"), None)).await;

    assert_refused_spawn(&error, "no-such-plugin", dir.path(), libc::ENOENT);
}

#[skuld::test]
async fn a_non_executable_plugin_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-executable");
    std::fs::write(&path, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let error = spawn_failure_of(BinaryPlugin::new(path, None)).await;

    assert_refused_spawn(&error, "not-executable", dir.path(), libc::EACCES);
}

#[skuld::test]
async fn a_plugin_path_through_a_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a-file");
    std::fs::write(&file, b"").unwrap();

    let error = spawn_failure_of(BinaryPlugin::new(file.join("plugin"), None)).await;

    assert_refused_spawn(&error, "plugin", dir.path(), libc::ENOTDIR);
}

#[skuld::test]
async fn a_plugin_that_is_a_symlink_loop_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("loop");
    std::os::unix::fs::symlink(&path, &path).unwrap();

    let error = spawn_failure_of(BinaryPlugin::new(path, None)).await;

    assert_refused_spawn(&error, "loop", dir.path(), libc::ELOOP);
}

#[skuld::test]
async fn a_plugin_with_an_overlong_name_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    // NAME_MAX is 255 on Linux and macOS.
    let name = "a".repeat(300);
    let path = dir.path().join(&name);

    let error = spawn_failure_of(BinaryPlugin::new(path, None)).await;

    assert_refused_spawn(&error, &name, dir.path(), libc::ENAMETOOLONG);
}

#[skuld::test]
async fn a_plugin_whose_environment_is_too_big_is_refused() {
    // Past ARG_MAX (1 MiB on macOS) and past Linux's per-string limit (128 KiB).
    let plugin =
        BinaryPlugin::new(std::env::current_exe().unwrap(), None).env("GARTER_TEST_TOO_BIG", "x".repeat(4 << 20));

    let exe = std::env::current_exe().unwrap();
    let error = spawn_failure_of(plugin).await;

    assert_refused_spawn(
        &error,
        &exe.file_stem().unwrap().to_string_lossy(),
        exe.parent().unwrap(),
        libc::E2BIG,
    );
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

/// `failure` is an unconfirmed stop of `plugin` whose cause is cosca's error, with the text `cosca_text`.
fn assert_unconfirmed(failure: &crate::Error, plugin: &str, cosca_text: &str, context: &str) {
    assert!(
        matches!(failure, crate::Error::StopUnconfirmed { plugins, .. } if plugins == &[plugin]),
        "{context}: {failure:?}"
    );
    assert_eq!(failure.source().unwrap().to_string(), cosca_text, "{context}");
}

/// `failure` is a spawn failure of `plugin` whose cause is `cause_text`: a confirmed stop.
fn assert_spawn_failed(failure: &crate::Error, plugin: &str, cause_text: &str, context: &str) {
    assert!(
        matches!(failure, crate::Error::Spawn { plugin: p, .. } if p == plugin),
        "{context}: {failure:?}"
    );
    assert!(failure.stop_confirmed(), "{context}");
    assert_eq!(failure.source().unwrap().to_string(), cause_text, "{context}");
}

/// A child that may still be running is not a confirmed stop: the error says so and names the plugin. A fate cosca
/// reports as `Running { id: None }` is its own statement that it cannot say.
#[skuld::test]
fn a_child_that_may_still_run_is_an_unconfirmed_stop() {
    for fate in [ChildFate::Running { id: None }, ChildFate::Unknown] {
        let error = may_have_started_from(fate, false, std::io::Error::from_raw_os_error(libc::EMFILE));
        let text = error.to_string();
        assert_unconfirmed(&spawn_failure("p", error), "p", &text, &format!("{fate:?}"));
    }
}

/// A reported child is a running one whatever the cause says.
#[skuld::test]
fn a_reported_child_is_an_unconfirmed_stop_whatever_the_cause() {
    for errno in [libc::ENOTDIR, libc::ENOENT] {
        let fate = ChildFate::Running {
            id: Some(cosca::identity::ProcessId::current()),
        };
        let error = may_have_started_from(fate, false, std::io::Error::from_raw_os_error(errno));
        let text = error.to_string();
        assert_unconfirmed(&spawn_failure("p", error), "p", &text, &format!("errno {errno}"));
    }
}

/// The fate of an elevation backend says nothing about the elevated program behind it, whatever the fate is.
#[skuld::test]
fn an_elevation_backend_is_an_unconfirmed_stop() {
    for fate in [ChildFate::Reaped, ChildFate::Running { id: None }] {
        let error = may_have_started(fate, true);
        let text = error.to_string();
        assert_unconfirmed(&spawn_failure("p", error), "p", &text, &format!("elevated, {fate:?}"));
    }
}

#[skuld::test]
fn a_child_that_is_gone_is_a_spawn_failure_with_only_the_cause() {
    for fate in [ChildFate::Reaped, ChildFate::Killed, ChildFate::Gone] {
        assert_spawn_failed(
            &spawn_failure("p", may_have_started(fate, false)),
            "p",
            &Error::Io(std::io::Error::from_raw_os_error(libc::ENOENT)).to_string(),
            &format!("{fate:?}"),
        );
    }
}

#[skuld::test]
fn an_error_that_is_not_may_have_started_is_a_spawn_failure_with_that_error_as_its_cause() {
    let error = Error::Io(std::io::Error::from_raw_os_error(13));
    let text = error.to_string();
    assert_spawn_failed(&spawn_failure("p", error), "p", &text, "not may-have-started");
}
