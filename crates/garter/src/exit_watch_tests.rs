// A real child is the only honest subject: the watch exists to leave its zombie in place.
#![allow(clippy::disallowed_methods)] // the test children are shells, never privileged

use std::future::Future;
use std::pin::pin;
use std::process::Stdio;
use std::task::{Context, Poll, Waker};

use tokio::process::Command;
use tokio::signal::unix::{signal, SignalKind};

use crate::exit_watch::wait_exit_without_reaping;

/// A shell that exits 0 once its stdin closes.
fn shell_waiting_for_stdin() -> tokio::process::Child {
    Command::new("/bin/sh")
        .arg("-c")
        .arg("cat >/dev/null")
        .stdin(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn the shell")
}

/// The watch is pending while the child runs, resolves once it has exited, and leaves it unreaped: the child's status is
/// still there to collect.
#[skuld::test]
async fn the_watch_resolves_when_the_child_exits_and_leaves_it_unreaped() {
    let mut child = shell_waiting_for_stdin();
    let pid = child.id().expect("a running child has a pid");

    let mut watch = pin!(wait_exit_without_reaping(pid));
    assert!(
        watch
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "the child is still running"
    );

    drop(child.stdin.take());
    watch.await.expect("watch the exit");
    // A second watch of the same zombie resolves too: the first did not reap it.
    wait_exit_without_reaping(pid).await.expect("watch the zombie");

    let status = child.wait().await.expect("the zombie is still ours to reap");
    assert!(status.success(), "{status:?}");
}

/// A child that exited before the watch started resolves on the first poll, so a caller probing with a zero timeout
/// reads it as exited.
#[skuld::test]
async fn a_child_that_already_exited_is_ready_on_the_first_poll() {
    let mut child = shell_waiting_for_stdin();
    let pid = child.id().expect("a running child has a pid");
    drop(child.stdin.take());
    wait_exit_without_reaping(pid).await.expect("watch the exit");

    let mut watch = pin!(wait_exit_without_reaping(pid));
    assert!(matches!(
        watch.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(()))
    ));
    child.wait().await.unwrap();
}

/// A pid that is not our child cannot be watched without reaping, and says so rather than resolving.
#[skuld::test]
async fn a_pid_that_is_not_our_child_is_an_error() {
    // pid 1 is never a child of the test process.
    let watched = wait_exit_without_reaping(1).await;
    assert!(watched.is_err(), "{watched:?}");
}

/// `SIGCHLD` also announces other children: the watch re-reads its own child's state at each wake and stays pending
/// while that child runs.
#[skuld::test]
async fn another_childs_exit_does_not_resolve_the_watch() {
    let mut child = shell_waiting_for_stdin();
    let pid = child.id().expect("a running child has a pid");
    let mut watch = pin!(wait_exit_without_reaping(pid));
    assert!(watch
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending());

    // The other child's exit raises `SIGCHLD`. This stream was subscribed before the watch's first poll too, so once it
    // yields, the watch's own stream has been notified as well.
    let mut sigchld = signal(SignalKind::child()).expect("subscribe to SIGCHLD");
    let mut other = Command::new("/bin/sh")
        .arg("-c")
        .arg("exit 0")
        .spawn()
        .expect("spawn the shell");
    sigchld.recv().await.expect("SIGCHLD");
    other.wait().await.expect("reap the other child");
    assert!(
        watch
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "the watch resolved for a child that is still running"
    );

    drop(child.stdin.take());
    watch.await.expect("watch the exit");
    child.wait().await.unwrap();
}
