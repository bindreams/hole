//! Integration seams: ready-rendezvous against a fake bridge child, and the
//! teardown helper against a real grandchild tree. The REAL end-to-end
//! (sudo, TUN, Vite, webview) is the manual smoke test in the PR checklist —
//! it needs a password prompt and a real network stack.

use crate::policy::ChildRole;
use crate::supervise::{create_run_dir, is_reaped, teardown_grouped};
use crate::test_child;

use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;

/// A fresh parent yields the plain `<parent>/<name>` leaf.
#[skuld::test]
fn create_run_dir_uses_plain_name_when_free() {
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path().join("dev-run");
    let dir = create_run_dir(&parent, "2026-06-20_15-30-45", 4242).unwrap();
    assert_eq!(dir, parent.join("2026-06-20_15-30-45"));
    assert!(dir.is_dir());
}

/// A same-second collision (the leaf already exists) falls back to
/// `<name>-<pid>` so the doomed run can't truncate the live run's logs.
#[skuld::test]
fn create_run_dir_falls_back_to_pid_on_collision() {
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path().join("dev-run");
    let primary = parent.join("2026-06-20_15-30-45");
    std::fs::create_dir_all(&primary).unwrap();
    // Sentinel: the original must survive untouched.
    std::fs::write(primary.join("dev-console.log"), b"live").unwrap();

    let dir = create_run_dir(&parent, "2026-06-20_15-30-45", 4242).unwrap();
    assert_eq!(dir, parent.join("2026-06-20_15-30-45-4242"));
    assert!(dir.is_dir());
    assert_eq!(std::fs::read(primary.join("dev-console.log")).unwrap(), b"live");
}

#[skuld::test]
async fn fake_bridge_satisfies_ready_listener() {
    let ready = crate::ready::ReadyListener::bind().await.unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut cmd = tokio::process::Command::new(exe);
    cmd.env(test_child::MODE_ENV, "fake-bridge");
    cmd.env("DEV_CONSOLE_READY_SPEC", ready.notify_arg());
    cmd.stdin(std::process::Stdio::null());
    cmd.kill_on_drop(true);
    let mut child = cmd.spawn().unwrap();
    ready.wait().await.expect("fake bridge echoes the token");
    let _ = child.kill().await;
}

/// dev.py:306-307 parity: an already-reaped child must not be signalled —
/// its pgid may have been recycled (the term_group contract requires holding
/// an un-reaped leader). Pin the guard predicate on live vs reaped children,
/// and that teardown on a reaped child returns without the grace wait.
#[skuld::test]
async fn reaped_children_are_not_signalled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut cmd = tokio::process::Command::new(exe);
    cmd.env(test_child::MODE_ENV, "sleep");
    cmd.env(test_child::CONTROL_ENV, listener.local_addr().unwrap().to_string());
    cmd.stdin(std::process::Stdio::null());
    cmd.kill_on_drop(true);
    let mut gc = kill_group::GroupedChild::spawn(&mut cmd, kill_group::Nesting::Mark).unwrap();
    let (_conn, _) = listener.accept().await.unwrap();
    assert!(!is_reaped(&gc.child), "live child is not reaped");
    gc.kill_tree().await; // kills AND reaps
    assert!(is_reaped(&gc.child), "kill_tree reaps the direct child");
    teardown_grouped(&mut gc, ChildRole::Vite).await;
}

/// The spec's promised integration test: teardown reaps a grandchild tree.
/// Control-channel death-watch pattern (see kill-group's tests): the
/// GRANDCHILD holds the conn; EOF/RST proves the tree died.
#[skuld::test]
async fn teardown_reaps_grandchild_tree() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut cmd = tokio::process::Command::new(exe);
    cmd.env(test_child::MODE_ENV, "spawn-grandchild");
    cmd.env(test_child::CONTROL_ENV, listener.local_addr().unwrap().to_string());
    cmd.stdin(std::process::Stdio::null());
    cmd.kill_on_drop(true);
    let mut gc = kill_group::GroupedChild::spawn(&mut cmd, kill_group::Nesting::Mark).unwrap();
    let (mut conn, _) = listener.accept().await.unwrap();
    let mut byte = [0u8; 1];
    conn.read_exact(&mut byte).await.unwrap(); // grandchild readiness

    teardown_grouped(&mut gc, ChildRole::Vite).await;

    // Production parity: the supervise funnel drops the child slots right
    // after shutdown, and GroupedChild::Drop's tree reap (job kill / group
    // SIGKILL) is the backstop for tree members the graceful phase cannot
    // reach — on Windows CTRL_BREAK stops at console-group boundaries, so a
    // grandchild in its own console group (this harness's deliberate #197
    // mirror) dies only here. The contract under test is "teardown + drop
    // leaves no survivors", matching the real funnel order.
    drop(gc);

    let mut buf = [0u8; 1];
    match conn.read(&mut buf).await {
        Ok(0) => {}
        Ok(n) => panic!("grandchild sent {n} unexpected byte(s)"),
        Err(e) => assert!(
            matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ),
            "teardown must reap the grandchild tree; got: {e:?}"
        ),
    }
}
