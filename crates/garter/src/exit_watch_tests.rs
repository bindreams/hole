// A real child is the only honest subject: the watch exists to leave its zombie in place.
#![allow(clippy::disallowed_methods)] // the test children are shells, never privileged

use std::future::Future;
use std::pin::pin;
use std::process::Stdio;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use tokio::process::Command;
use tokio::signal::unix::{signal, SignalKind};

use rustix::io::Errno;

use crate::binary::{root_exit_watch, root_exit_watch_within};
use crate::exit_watch::{wait_exit_without_reaping, watch_error};

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

/// `ECHILD` on a child this process has not reaped means a third party reaped it or `SIGCHLD` is ignored: the module's
/// contract is broken, which is a bug to surface, not an input to route around.
#[skuld::test]
async fn a_pid_that_is_not_our_child_is_a_contract_violation() {
    // pid 1 is never a child of the test process (and if this is pid 1, it is not its own child).
    let watched = std::panic::catch_unwind(|| {
        let mut watch = pin!(wait_exit_without_reaping(1));
        watch.as_mut().poll(&mut Context::from_waker(Waker::noop()))
    });
    assert!(watched.is_err(), "the watch of a pid that is not our child returned");
}

/// A `waitid` error that only a bug can cause is a contract violation, whichever way it surfaced; one an environment can
/// cause (a seccomp profile denying `waitid`) is an error the caller routes around.
#[skuld::test]
fn only_a_bug_can_cause_a_waitid_einval_efault_or_echild() {
    for errno in [Errno::INVAL, Errno::FAULT, Errno::CHILD] {
        let classified = std::panic::catch_unwind(|| watch_error(errno));
        assert!(
            classified.is_err(),
            "{errno:?} was routed around as an unwatchable root"
        );
    }
    for errno in [Errno::PERM, Errno::NOSYS] {
        let classified = watch_error(errno);
        assert_eq!(classified.raw_os_error(), Some(errno.raw_os_error()), "{errno:?}");
    }
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

// The production glue: cosca cannot watch, `waitid` does --------------------------------------------------------------
//
// A kernel with `pidfd_open` never reaches the fallback, so these inject what cosca's watch answers on one without it
// and watch a real child. Whatever the answer, the root stays unreaped: its status is still there to collect.

/// The ways cosca's own watch can fail to watch a root.
const COSCA_CANNOT_WATCH: [&str; 3] = [
    "unsupported (before 5.3)",
    "denied by a seccomp profile",
    "unassessable",
];

fn cosca_cannot_watch(how: &str) -> cosca::error::Error {
    match how {
        "unsupported (before 5.3)" => cosca::error::Error::Unsupported {
            op: "wait".into(),
            platform: "linux",
            detail: "pidfd_open requires Linux kernel >= 5.3".into(),
        },
        "denied by a seccomp profile" => {
            cosca::error::Error::Io(std::io::Error::from_raw_os_error(Errno::PERM.raw_os_error()))
        }
        _ => cosca::error::Error::Unassessable {
            detail: "the root cannot be assessed".into(),
            source: None,
        },
    }
}

#[skuld::test]
async fn a_root_cosca_cannot_watch_is_watched_by_waitid_and_left_unreaped() {
    for how in COSCA_CANNOT_WATCH {
        let mut child = shell_waiting_for_stdin();
        let pid = child.id().expect("a running child has a pid");

        let mut watch = pin!(root_exit_watch(pid, Err(cosca_cannot_watch(how))));
        assert!(
            watch
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "{how}: the child is still running"
        );
        drop(child.stdin.take());
        watch.await.unwrap_or_else(|e| panic!("{how}: {e}"));

        let status = child.wait().await.expect("the zombie is still ours to reap");
        assert!(status.success(), "{how}: {status:?}");
    }
}

#[skuld::test]
async fn a_probe_of_a_root_cosca_cannot_watch_reads_its_state_without_reaping_it() {
    for how in COSCA_CANNOT_WATCH {
        let mut child = shell_waiting_for_stdin();
        let pid = child.id().expect("a running child has a pid");

        let running = root_exit_watch_within(pid, Duration::ZERO, Err(cosca_cannot_watch(how))).await;
        assert!(
            matches!(running, Ok(false)),
            "{how}: the child is still running: {running:?}"
        );

        drop(child.stdin.take());
        wait_exit_without_reaping(pid).await.expect("watch the exit");
        let exited = root_exit_watch_within(pid, Duration::ZERO, Err(cosca_cannot_watch(how))).await;
        assert!(matches!(exited, Ok(true)), "{how}: the child has exited: {exited:?}");

        let status = child.wait().await.expect("the zombie is still ours to reap");
        assert!(status.success(), "{how}: {status:?}");
    }
}

#[skuld::test]
async fn a_root_cosca_cannot_watch_that_exits_within_its_grace_is_reported_exited_and_left_unreaped() {
    for how in COSCA_CANNOT_WATCH {
        let mut child = shell_waiting_for_stdin();
        let pid = child.id().expect("a running child has a pid");
        drop(child.stdin.take());

        let exited = root_exit_watch_within(pid, Duration::from_secs(3600), Err(cosca_cannot_watch(how))).await;
        assert!(matches!(exited, Ok(true)), "{how}: {exited:?}");

        let status = child.wait().await.expect("the zombie is still ours to reap");
        assert!(status.success(), "{how}: {status:?}");
    }
}

/// Where cosca's watch worked, its answer is the answer: `waitid` is not consulted (for pid 1 it would be a contract
/// violation, as pid 1 is not our child).
#[skuld::test]
async fn an_answer_from_cosca_is_not_second_guessed() {
    assert!(root_exit_watch(1, Ok(())).await.is_ok());
    for answer in [true, false] {
        let watched = root_exit_watch_within(1, Duration::from_secs(3600), Ok(answer)).await;
        assert!(matches!(watched, Ok(a) if a == answer), "{answer}: {watched:?}");
    }
}
