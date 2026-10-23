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

#[skuld::test]
fn a_failing_inherited_command_reports_the_command_and_status() {
    let err = run_inherited(Command::new("git").args(["rev-parse", "-q", "--verify", "refs/no-such-ref"])).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("refs/no-such-ref"), "{msg}");
    assert!(msg.contains("failed: ") && msg.contains('1'), "{msg}");
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
