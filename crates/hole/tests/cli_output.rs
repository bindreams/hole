//! A `hole` command run with its output piped hands the caller its result on stdout and its error on stderr, and writes
//! the error to `gui-cli.log`, before the process exits.
//!
//! The real `hole` executable runs, so the test crosses the same exit path a script does: `dispatch` ends in
//! `process::exit`, with the log guard's stdio relay behind stdout and stderr.

#![allow(clippy::disallowed_methods)] // attended test: runs the workspace's own `hole`

use std::path::Path;
use std::process::{Command, Output};

hole_test_observability::register!();

/// What `hole bridge status` prints, one line per state of the bridge service (`status_report`, `crates/hole/src/cli.rs`).
const STATUS_LINES: [&str; 5] = [
    "installed (running)",
    "installed (stopped)",
    "not installed",
    "installed (disabled)",
    "installed (being changed)",
];

/// Reads `CARGO_BIN_EXE_hole` at run time first: a nextest archive run remaps it.
fn hole(log_dir: &Path, args: &[&str]) -> Output {
    let exe = std::env::var_os("CARGO_BIN_EXE_hole").unwrap_or_else(|| env!("CARGO_BIN_EXE_hole").into());
    Command::new(exe)
        .args(args)
        .env("HOLE_LOG_DIR", log_dir)
        // The debug-only switch that turns the stdio relay off: the shipped build has no such switch.
        .env_remove("HOLE_LOGGING_DISABLE_REDIRECT")
        .output()
        .expect("run hole")
}

#[skuld::test]
fn a_result_printed_by_a_command_reaches_a_pipe() {
    let log_dir = tempfile::tempdir().expect("log dir");
    let out = hole(log_dir.path(), &["bridge", "status"]);

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        STATUS_LINES.contains(&stdout.trim_end()),
        "`hole bridge status` printed {stdout:?} to a pipe, not one of its status lines {STATUS_LINES:?} \
         (exit {:?}, stderr {:?})",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[skuld::test]
fn an_error_reaches_stderr_and_the_log() {
    let work = tempfile::tempdir().expect("work dir");
    let absent = work.path().join("absent.json");
    let log_dir = tempfile::tempdir_in(work.path()).expect("log dir");
    let out = hole(
        log_dir.path(),
        &["proxy", "start", "--config-file", absent.to_str().expect("utf-8 path")],
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    let log = std::fs::read_to_string(log_dir.path().join("gui-cli.log")).unwrap_or_default();
    assert_eq!(out.status.code(), Some(1), "exit code (stderr {stderr:?})");
    assert!(
        stderr.contains("failed to read") && stderr.contains("absent.json"),
        "stderr is {stderr:?}, which does not say the config file could not be read"
    );
    assert!(
        log.contains("failed to read") && log.contains("absent.json"),
        "gui-cli.log is {log:?}, which does not record that the config file could not be read"
    );
}

fn main() {
    skuld::run_all();
}
