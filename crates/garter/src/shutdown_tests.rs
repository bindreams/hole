use std::time::Duration;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use crate::shutdown;

#[skuld::test]
async fn cancel_token_on_shutdown_signal() {
    let token = CancellationToken::new();
    let child_token = token.child_token();
    token.cancel();
    assert!(child_token.is_cancelled());
}

/// Spawn a long-running child process suitable for shutdown tests.
///
/// On Windows, spawns with `CREATE_NEW_PROCESS_GROUP` so that
/// `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)` targets the child.
fn spawn_sleeper() -> tokio::process::Child {
    #[cfg(unix)]
    {
        Command::new("sleep").arg("60").spawn().unwrap()
    }
    #[cfg(windows)]
    {
        Command::new("timeout")
            .args(["/t", "60", "/nobreak"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(windows::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP.0)
            .spawn()
            .unwrap()
    }
}

/// Spawn a child that ignores the termination signal.
///
/// On Unix: traps SIGTERM. On Windows: not possible without a custom binary,
/// so we rely on the force-kill path by using a very short timeout instead.
fn spawn_signal_ignoring_sleeper() -> tokio::process::Child {
    #[cfg(unix)]
    {
        Command::new("sh")
            .args(["-c", "trap '' TERM; sleep 60"])
            .spawn()
            .unwrap()
    }
    #[cfg(windows)]
    {
        // On Windows, there's no easy way to spawn a process that ignores
        // CTRL_BREAK from the command line. We reuse spawn_sleeper() here;
        // the force-kill test uses a 0ms timeout to guarantee the kill path.
        spawn_sleeper()
    }
}

#[skuld::test]
async fn graceful_stop_terminates_child() {
    let mut child = spawn_sleeper();
    let id = child.id().expect("child should have an id");
    assert!(id > 0);
    shutdown::graceful_stop(&mut child, Duration::from_secs(2))
        .await
        .unwrap();
    let status = child.try_wait().unwrap();
    assert!(status.is_some(), "child should have exited after graceful_stop");
}

#[skuld::test]
async fn graceful_stop_force_kills_after_timeout() {
    let mut child = spawn_signal_ignoring_sleeper();

    // On Unix, the child ignores SIGTERM so we hit the timeout.
    // On Windows, we use 0ms timeout to guarantee the force-kill path
    // (the child would respond to CTRL_BREAK, but 0ms gives it no chance).
    #[cfg(unix)]
    let timeout = Duration::from_millis(100);
    #[cfg(windows)]
    let timeout = Duration::ZERO;

    shutdown::graceful_stop(&mut child, timeout).await.unwrap();
    let status = child.try_wait().unwrap();
    assert!(status.is_some(), "child should have been force-killed");
}

/// Verify that CTRL_BREAK actually causes a prompt exit (not a timeout+force-kill).
#[cfg(windows)]
#[skuld::test]
async fn graceful_stop_exits_via_ctrl_break() {
    let mut child = spawn_sleeper();

    let start = std::time::Instant::now();
    shutdown::graceful_stop(&mut child, Duration::from_secs(10))
        .await
        .unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(3),
        "child should have exited via CTRL_BREAK, not timed out (took {elapsed:?})"
    );
}
