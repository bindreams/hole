use super::*;

#[skuld::test]
fn kill_pid_on_live_process() {
    let mut child = std::process::Command::new(if cfg!(windows) { "timeout" } else { "sleep" })
        .args(if cfg!(windows) {
            &["/t", "60", "/nobreak"][..]
        } else {
            &["60"][..]
        })
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sleeper");

    let pid = child.id();
    let r1 = kill_pid(pid);
    assert!(r1.is_ok(), "first kill failed: {r1:?}");

    let _ = child.wait();

    let r2 = kill_pid(pid);
    assert!(r2.is_ok(), "second kill should be idempotent, got: {r2:?}");
}

#[skuld::test]
fn kill_pid_nonexistent_is_ok() {
    let result = kill_pid(999_999_999);
    assert!(
        result.is_ok(),
        "killing a nonexistent PID should succeed, got: {result:?}"
    );
}

#[skuld::test]
fn process_start_time_of_self() {
    let pid = std::process::id();
    let start = process_start_time(pid);
    assert!(start.is_some(), "should be able to read own start time");

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let start_ms = start.unwrap();
    assert!(start_ms < now_ms, "start time {start_ms} should be before now {now_ms}");
    assert!(
        now_ms - start_ms < 600_000,
        "start time should be within 10 minutes of now (test just started)"
    );
}

#[skuld::test]
fn process_start_time_nonexistent() {
    assert!(process_start_time(999_999_999).is_none());
}

#[skuld::test]
fn recover_plugins_kills_tracked_process() {
    let dir = tempfile::tempdir().unwrap();

    let mut child = std::process::Command::new(if cfg!(windows) { "timeout" } else { "sleep" })
        .args(if cfg!(windows) {
            &["/t", "60", "/nobreak"][..]
        } else {
            &["60"][..]
        })
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sleeper");

    let pid = child.id();
    let start_ms = process_start_time(pid).expect("read child start time");

    plugin_state::append_record(
        dir.path(),
        plugin_state::PluginRecord {
            pid,
            start_time_unix_ms: start_ms,
        },
    )
    .unwrap();

    recover_plugins(dir.path());

    // Verify the child is dead by waiting on it.
    let status = child.wait().expect("wait on killed child");
    assert!(!status.success(), "process should have been killed (non-zero exit)");

    assert!(
        plugin_state::load(dir.path()).is_none(),
        "state file should be cleared after recovery"
    );
}

#[skuld::test]
fn recover_plugins_skips_reused_pid() {
    let dir = tempfile::tempdir().unwrap();

    let child = std::process::Command::new(if cfg!(windows) { "timeout" } else { "sleep" })
        .args(if cfg!(windows) {
            &["/t", "60", "/nobreak"][..]
        } else {
            &["60"][..]
        })
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sleeper");

    let pid = child.id();

    // Record a wildly wrong start time to simulate PID reuse.
    plugin_state::append_record(
        dir.path(),
        plugin_state::PluginRecord {
            pid,
            start_time_unix_ms: 1, // epoch start — definitely wrong
        },
    )
    .unwrap();

    recover_plugins(dir.path());

    // Process should still be alive — recovery skipped it because start
    // time didn't match.
    assert!(
        process_start_time(pid).is_some(),
        "process should NOT have been killed (PID reuse detected)"
    );

    // Clean up.
    let mut child = child;
    kill_pid(pid).ok();
    let _ = child.wait();
}
