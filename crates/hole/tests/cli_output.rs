//! A `hole` command run with its output piped hands the caller its result on stdout and its error on stderr, and writes
//! the error to `gui-cli.log`, before the process exits.
//!
//! The real `hole` executable runs because `dispatch` ends in `process::exit`, with the log guard's stdio relay behind
//! stdout and stderr.

#![allow(clippy::disallowed_methods)] // attended test: runs the workspace's own `hole`

use std::path::Path;
use std::process::{Command, Output};

hole_test_observability::register!();

/// What `hole bridge status` prints, one line per state of the bridge service (`status_report`).
const STATUS_LINES: [&str; 5] = [
    "installed (running)",
    "installed (stopped)",
    "not installed",
    "installed (disabled)",
    "installed (being changed)",
];

/// `hole` with `args`, logging to `log_dir`, not yet started. Reads `CARGO_BIN_EXE_hole` at run time first: a nextest
/// archive run remaps it.
fn hole_command(log_dir: &Path, args: &[&str]) -> Command {
    let exe = std::env::var_os("CARGO_BIN_EXE_hole").unwrap_or_else(|| env!("CARGO_BIN_EXE_hole").into());
    let mut command = Command::new(exe);
    command
        .args(args)
        .env("HOLE_LOG_DIR", log_dir)
        // The debug-only switch that turns the stdio relay off: the shipped build has no such switch.
        .env_remove("HOLE_LOGGING_DISABLE_REDIRECT");
    command
}

fn hole(log_dir: &Path, args: &[&str]) -> Output {
    hole_command(log_dir, args).output().expect("run hole")
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

/// A caller that closed stdout before the command wrote to it (`hole bridge status | true`) is told of no loss: the
/// command printed, the caller chose not to read. The log shows that the line was printed.
#[skuld::test]
fn a_command_whose_stdout_the_caller_closed_reports_no_loss() {
    let log_dir = tempfile::tempdir().expect("log dir");
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    let out = hole_command(log_dir.path(), &["bridge", "status"])
        .stdout(writer)
        .output()
        .expect("run hole");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let log = std::fs::read_to_string(log_dir.path().join("gui-cli.log")).unwrap_or_default();
    assert!(
        STATUS_LINES.iter().any(|line| log.contains(line)),
        "gui-cli.log is {log:?}, which does not show that the status line was printed (stderr {stderr:?})"
    );
    assert!(
        !stderr.contains("could not be fully delivered"),
        "a closed stdout was reported as a loss: {stderr:?}"
    );
}

/// A command whose stdout takes no bytes says that its output was not delivered, on stderr and in the log. The stdout
/// here is a file opened for reading only, which the operating system refuses to write.
#[skuld::test]
fn a_command_whose_stdout_refuses_writes_says_that_its_output_was_not_delivered() {
    let work = tempfile::tempdir().expect("work dir");
    let log_dir = tempfile::tempdir_in(work.path()).expect("log dir");
    let target = work.path().join("stdout");
    std::fs::write(&target, b"").expect("create the file");
    let read_only = std::fs::File::open(&target).expect("open the file for reading");
    let out = hole_command(log_dir.path(), &["bridge", "status"])
        .stdout(read_only)
        .output()
        .expect("run hole");

    let stderr = String::from_utf8_lossy(&out.stderr);
    let log = std::fs::read_to_string(log_dir.path().join("gui-cli.log")).unwrap_or_default();
    // One status line was printed, so one write was refused.
    let report = "hole: the output could not be fully delivered: stdout was not fully written: \
                  writes refused: 1, messages dropped: 0";
    assert_eq!(
        std::fs::read(&target).expect("read the file back"),
        b"",
        "the file took bytes, so nothing was refused"
    );
    assert!(
        stderr.contains(report),
        "stderr is {stderr:?}, which does not say that stdout was not written"
    );
    assert!(
        log.contains(report),
        "gui-cli.log is {log:?}, which does not record that stdout was not written"
    );
}

/// A command whose stderr takes no bytes records in the log what stderr did not receive: the line the command
/// printed there, and the log event the stderr sink was given. Each record exists only because the exit waited for
/// that sink's writer and read what it could not write. The stderr here is a file opened for reading only.
#[skuld::test]
fn a_command_whose_stderr_refuses_writes_records_in_the_log_what_was_not_delivered() {
    let work = tempfile::tempdir().expect("work dir");
    let log_dir = tempfile::tempdir_in(work.path()).expect("log dir");
    let absent = work.path().join("absent.json");
    let target = work.path().join("stderr");
    std::fs::write(&target, b"").expect("create the file");
    let read_only = std::fs::File::open(&target).expect("open the file for reading");
    // The command prints its error to stderr and logs it as an event, so each of the two stderr sinks has a write.
    let out = hole_command(
        log_dir.path(),
        &["proxy", "start", "--config-file", absent.to_str().expect("utf-8 path")],
    )
    .stderr(read_only)
    .output()
    .expect("run hole");

    let log = std::fs::read_to_string(log_dir.path().join("gui-cli.log")).unwrap_or_default();
    assert_eq!(out.status.code(), Some(1), "exit code (gui-cli.log {log:?})");
    for sink in ["stderr", "the log on stderr"] {
        let report =
            format!("hole: the output could not be fully delivered: {sink} was not fully written: writes refused: ");
        assert!(
            log.contains(&report),
            "gui-cli.log is {log:?}, which does not record that {sink} was not written"
        );
    }
}

/// A command whose log file takes no bytes says on stderr that the log was not fully written. The file is locked by
/// this test; on Windows a lock is mandatory, and the operating system refuses a write into the locked range.
#[cfg(windows)]
#[skuld::test]
fn a_command_whose_log_file_refuses_writes_says_so_on_stderr() {
    let log_dir = tempfile::tempdir().expect("log dir");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(log_dir.path().join("gui-cli.log"))
        .expect("create the log file");
    log.lock().expect("lock the log file");
    let out = hole(log_dir.path(), &["bridge", "status"]);

    let stderr = String::from_utf8_lossy(&out.stderr);
    // How many writes the file refused is every event it was given, which depends on `RUST_LOG` and on the machine.
    let report = "hole: the output could not be fully delivered: the log file was not fully written: writes refused: ";
    assert_eq!(
        log.metadata().expect("the log file's size").len(),
        0,
        "the file took bytes, so nothing was refused"
    );
    assert!(
        stderr.contains(report),
        "stderr is {stderr:?}, which does not say that the log file was not written"
    );
}

fn main() {
    skuld::run_all();
}
