// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per the hole workspace clippy.toml's "Bridge cancellation contract"
// sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

use std::process::ExitStatus;
use std::time::Duration;

use cosca::tokio::Command;
use cosca::Stdio;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

mod common;
use common::mock_plugin_path;

#[skuld::test]
async fn cancel_token_on_shutdown_signal() {
    let token = CancellationToken::new();
    let child_token = token.child_token();
    token.cancel();
    assert!(child_token.is_cancelled());
}

/// A parked `mock-plugin`, plus the control connection it dialled on startup.
/// Holding that connection is what makes readiness an observed edge rather than
/// a wait: the child dials only after its signal disposition is installed.
struct Sleeper {
    child: cosca::tokio::Child,
    _control: TcpStream,
}

/// Spawn a parked `mock-plugin` as a contained root and return it once it has
/// reported readiness. `ignore_signals` makes it absorb the cooperative signal,
/// so the only end available to it is the forced one.
async fn spawn_sleeper(ignore_signals: bool) -> Sleeper {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();

    let mut cmd = Command::new();
    cmd.executable(mock_plugin_path())
        .env("MOCK_PLUGIN_SLEEP", "1")
        .env("MOCK_PLUGIN_GRANDCHILD_CALLBACK", control_addr.to_string())
        .kill_on_drop(true)
        .contain()
        .nesting(cosca::containment::Nesting::Mark);
    cmd.stdin(Stdio::null()).unwrap();
    cmd.stdout(Stdio::null()).unwrap();
    cmd.stderr(Stdio::null()).unwrap();
    if ignore_signals {
        cmd.env("MOCK_PLUGIN_IGNORE_SIGNALS", "1");
    }

    let child = cmd.spawn().unwrap();
    let (control, _) = control.accept().await.expect("the child dials the control channel");
    Sleeper {
        child,
        _control: control,
    }
}

/// The child ended through the cooperative signal: `SIGTERM`'s default disposition
/// on Unix, `STATUS_CONTROL_C_EXIT` on Windows.
#[track_caller]
fn assert_cooperative_end(status: ExitStatus) {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGTERM));
    }
    #[cfg(windows)]
    assert_eq!(status.code(), Some(0xC000013A_u32 as i32));
}

/// The child was force-killed: `SIGKILL` on Unix, `TerminateProcess(_, 1)` on Windows.
#[track_caller]
fn assert_forced_end(status: ExitStatus) {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }
    #[cfg(windows)]
    assert_eq!(status.code(), Some(1));
}

#[skuld::test]
async fn graceful_shutdown_ends_the_child_by_the_cooperative_signal() {
    let mut sleeper = spawn_sleeper(false).await;

    let status = sleeper.child.graceful_shutdown(Duration::from_secs(10)).await.unwrap();

    assert_cooperative_end(status);
}

#[skuld::test]
async fn graceful_shutdown_escalates_when_the_child_ignores_the_signal() {
    let mut sleeper = spawn_sleeper(true).await;

    let status = sleeper
        .child
        .graceful_shutdown(Duration::from_millis(100))
        .await
        .unwrap();

    assert_forced_end(status);
}

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}
