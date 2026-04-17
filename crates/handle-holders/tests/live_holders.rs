//! Live-API tests that need a real foreign process holding the target file.
//!
//! Integration-test target, not a unit test module, because
//! `env!("CARGO_BIN_EXE_hold_file")` is only set for `tests/*.rs`.
//! The tiny `hold_file` bin (see `src/bin/hold_file.rs`) opens the
//! path passed via the `HOLD_FILE` env var and sleeps, so we can
//! observe it as a file holder without re-invoking a full test
//! binary (which re-initializes skuld/tokio/tracing and tripped a
//! Rust runtime abort in earlier attempts).

use handle_holders::{find_holders, FileHolder};
use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn main() {
    skuld::run_all();
}

fn spawn_holder(path: &Path) -> Child {
    let exe = env!("CARGO_BIN_EXE_hold_file");
    Command::new(exe)
        .env("HOLD_FILE", path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn hold_file child")
}

fn wait_for_holder(path: &Path, deadline: Duration) -> Vec<FileHolder> {
    let started = Instant::now();
    loop {
        let holders = find_holders(path).expect("find_holders");
        if !holders.is_empty() || started.elapsed() >= deadline {
            return holders;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn find_holders_finds_foreign_process_holding_file_windows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("locked.bin");
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(b"content"))
        .expect("write file");

    let mut child = spawn_holder(&path);
    let child_pid = child.id();
    let holders = wait_for_holder(&path, Duration::from_secs(10));
    let _ = child.kill();
    let _ = child.wait();

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

    let mut child = spawn_holder(&path);
    let holders = wait_for_holder(&path, Duration::from_secs(3));
    let _ = child.kill();
    let _ = child.wait();

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
