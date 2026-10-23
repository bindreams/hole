// A spawn that never ran the program ----------------------------------------------------------------------------------
//
// cosca reports a failed `exec` of a tokio `Command` on Unix as `MayHaveStarted`, because it cannot prove the program never
// ran. For a missing or non-executable plugin that text is wrong for the reader: it says a child "had been reaped by someone
// else" where the OS error says what is the matter.
#![allow(clippy::disallowed_methods)] // CancellationToken::new roots the shutdown of a run that never starts

use std::os::unix::fs::PermissionsExt as _;

use cosca::error::{ChildFate, Error};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::binary::{spawn_failure_text, BinaryPlugin};
use crate::plugin::ChainPlugin;

/// The message `BinaryPlugin::run` fails with when it cannot spawn `path`.
async fn spawn_failure_of(path: &std::path::Path) -> String {
    let plugin = BinaryPlugin::new(path, None);
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

#[skuld::test]
async fn a_missing_plugin_reports_the_os_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("no-such-plugin");

    let message = spawn_failure_of(&path).await;

    assert!(message.contains("failed to spawn"), "{message}");
    assert!(message.contains("No such file or directory"), "{message}");
    assert!(!message.contains("may have started"), "{message}");
}

#[skuld::test]
async fn a_non_executable_plugin_reports_the_os_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-executable");
    std::fs::write(&path, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let message = spawn_failure_of(&path).await;

    assert!(message.contains("Permission denied"), "{message}");
    assert!(!message.contains("may have started"), "{message}");
}

fn may_have_started(fate: ChildFate, wrapper_elevated: bool) -> Error {
    Error::MayHaveStarted {
        fate,
        wrapper_elevated,
        source: Box::new(Error::Io(std::io::Error::from_raw_os_error(2))),
    }
}

/// A child that may still be running is a fact the user can act on; cosca's text carries it.
#[skuld::test]
fn a_child_that_may_still_run_keeps_the_cosca_text() {
    for fate in [ChildFate::Running { id: None }, ChildFate::Unknown] {
        let error = may_have_started(fate, false);
        assert_eq!(spawn_failure_text(&error), error.to_string(), "{fate:?}");
    }
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
