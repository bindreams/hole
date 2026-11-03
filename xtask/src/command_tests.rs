#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::process::Command;

use super::*;

#[skuld::test]
fn describe_names_program_arguments_and_directory() {
    let mut cmd = Command::new("go");
    cmd.args(["build", "-ldflags=-s -w", ""]).current_dir("some/dir");
    let line = describe(&cmd);
    assert!(line.starts_with("go \"build\" \"-ldflags=-s -w\" \"\""), "{line}");
    assert!(line.contains("(in some") && line.ends_with("dir)"), "{line}");
}

#[skuld::test]
fn a_failing_captured_command_reports_command_status_and_stderr() {
    let err = run_captured(Command::new("git").arg("--no-such-flag")).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("git \"--no-such-flag\""), "{msg}");
    assert!(msg.contains("129"), "{msg}");
    assert!(msg.contains("no-such-flag"), "stderr missing: {msg}");
}

/// The caller reads the exit code itself, so a non-zero exit is not an error here.
#[skuld::test]
fn a_command_that_ran_and_failed_returns_its_output() {
    let output = run_output(Command::new("git").arg("--no-such-flag")).unwrap();
    assert_eq!(output.status.code(), Some(129));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no-such-flag"));
}

#[skuld::test]
fn a_command_that_cannot_start_is_an_error_from_run_output() {
    let err = run_output(&mut Command::new("hole-xtask-no-such-program")).unwrap_err();
    assert!(err.downcast_ref::<ProgramNotFound>().is_some(), "{err:#}");
}

#[skuld::test]
fn a_failing_inherited_command_reports_the_command_and_status() {
    let args = ["rev-parse", "-q", "--verify", "refs/no-such-ref"];
    // The status text is the OS's own, so take it from the same command run on its own.
    let status = Command::new("git").args(args).status().unwrap();
    assert!(!status.success());
    let err = run_inherited(Command::new("git").args(args)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("refs/no-such-ref"), "{msg}");
    assert!(msg.ends_with(&format!("failed: {status}")), "{msg}");
}

#[skuld::test]
fn a_missing_program_says_it_was_not_found() {
    let err = run_inherited(&mut Command::new("hole-xtask-no-such-program")).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("hole-xtask-no-such-program") && msg.contains("not found"),
        "{msg}"
    );
}

#[skuld::test]
fn a_missing_working_directory_is_not_reported_as_a_missing_program() {
    let dir = std::env::temp_dir().join("hole-xtask-no-such-directory");
    let err = run_inherited(Command::new("git").arg("--version").current_dir(&dir)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(err.downcast_ref::<ProgramNotFound>().is_none(), "{msg}");
    assert!(
        msg.contains("working directory") && msg.contains("does not exist"),
        "{msg}"
    );
    assert!(
        crate::retry::is_permanent(&err),
        "no retry can create the directory: {msg}"
    );
}
