//! Live-API tests that need a real foreign process holding the target file.
//!
//! Integration-test target, not a unit test module, because
//! `CARGO_BIN_EXE_hold_file` is only set for `tests/*.rs`. The tiny
//! `hold_file` bin (see `src/bin/hold_file.rs`) opens the path passed
//! via the `HOLD_FILE` env var and waits for stdin EOF, so we can
//! observe it as a file holder.
//!
//! Path resolution: prefer the runtime `CARGO_BIN_EXE_hold_file` env
//! var (set by nextest's archive workflow when the binary is extracted
//! to a temp dir on the runner). Fall back to the compile-time value
//! via `env!()` for plain `cargo test` invocations on the build host.

use handle_holders::{find_holders, FileHolder};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};

// Install the workspace test subscriber + panic hook. See
// `crates/test-observability/` and bindreams/hole#301.
hole_test_observability::register!();

fn main() {
    skuld::run_all();
}

/// Spawn `hold_file` and park until its stdout emits "ready", meaning
/// the child has the file handle open. Deterministic — no sleep-based
/// poll over `find_holders`. See bindreams/hole#383.
fn spawn_holder_ready(path: &Path) -> (Child, BufReader<ChildStdout>) {
    let exe = std::env::var("CARGO_BIN_EXE_hold_file").unwrap_or_else(|_| env!("CARGO_BIN_EXE_hold_file").to_string());
    let mut child = Command::new(exe)
        .env("HOLD_FILE", path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn hold_file child");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read ready line from hold_file");
    assert_eq!(line.trim(), "ready", "unexpected ready line: {line:?}");
    (child, reader)
}

/// Shut down the holder by closing its stdin pipe — `hold_file` exits
/// on EOF. This exercises the stdin-EOF exit path (the production
/// contract) rather than forcefully terminating, so a regression in
/// `hold_file`'s EOF handling shows up here.
fn shutdown_holder(mut child: Child) {
    drop(child.stdin.take());
    let _ = child.wait();
}

fn collect_holders(path: &Path) -> Vec<FileHolder> {
    find_holders(path).expect("find_holders")
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn find_holders_finds_foreign_process_holding_file_windows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("locked.bin");
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(b"content"))
        .expect("write file");

    let (child, _stdout) = spawn_holder_ready(&path);
    let child_pid = child.id();
    let holders = collect_holders(&path);
    shutdown_holder(child);

    let me = std::process::id();
    assert!(
        !holders.iter().any(|h| h.pid == me),
        "current pid {me} must be filtered out, got {holders:?}",
    );
    assert!(
        !holders.is_empty(),
        "expected at least one holder, got empty (child pid was {child_pid})",
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn find_holders_no_holders_returns_empty_windows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("unlocked.bin");
    std::fs::write(&path, b"content").expect("write file");

    let holders = find_holders(&path).expect("find_holders");
    assert!(
        holders.is_empty(),
        "expected no holders for unheld file, got {holders:?}",
    );
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn find_holders_detects_child_holding_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("locked.bin");
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(b"content"))
        .expect("write file");

    let (child, _stdout) = spawn_holder_ready(&path);
    let holders = collect_holders(&path);
    shutdown_holder(child);

    let me = std::process::id();
    assert!(
        holders.iter().any(|h| h.pid != me),
        "expected at least one non-self holder, got {holders:?}",
    );
    assert!(
        !holders.iter().any(|h| h.pid == me),
        "current pid {me} must be filtered out, got {holders:?}",
    );
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn find_holders_no_holders_returns_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("unlocked.bin");
    std::fs::write(&path, b"content").expect("write file");

    let holders = find_holders(&path).expect("find_holders");
    assert!(
        holders.is_empty(),
        "expected no holders for unheld file, got {holders:?}",
    );
}
