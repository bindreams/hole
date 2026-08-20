//! Integration seams: ready-rendezvous against a fake bridge child, and the
//! teardown helper against a real grandchild tree. The REAL end-to-end
//! (sudo, TUN, Vite, webview) is the manual smoke test in the PR checklist —
//! it needs a password prompt and a real network stack.

use crate::policy::ChildRole;
use crate::supervise::{create_run_dir, has_exited, teardown_grouped};
use crate::test_child;

use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};
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

/// dev.py:306-307 parity: an already-exited child must not be signalled — its
/// pgid may have been recycled, and on Windows its handle is released. Pin the
/// guard predicate on live vs exited children, and that teardown on an exited
/// child returns without the grace wait.
///
/// The `kill_tree` → `wait` → observed-exit sequence here is also the
/// executable stand-in for `run_vite_and_measure`'s, which is
/// `windows_console`-labelled and so never runs in CI.
#[skuld::test]
async fn exited_children_are_not_signalled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(std::env::current_exe().unwrap());
    cmd.arg(std::env::current_exe().unwrap());
    cmd.env(test_child::MODE_ENV, "sleep");
    cmd.env(test_child::CONTROL_ENV, listener.local_addr().unwrap().to_string());
    cmd.stdin(cosca::Stdio::null()).unwrap();
    cmd.kill_on_drop(true)
        .contain()
        .nesting(cosca::containment::Nesting::Mark);
    let mut child = cmd.spawn().unwrap();
    let (_conn, _) = listener.accept().await.unwrap();
    assert!(!has_exited(&mut child), "live child has not exited");
    // Signal-only since the cosca migration: the wait is what reaps.
    child.kill_tree().unwrap();
    child.wait().await.unwrap();
    assert!(has_exited(&mut child), "kill_tree + wait ends the direct child");
    teardown_grouped(&mut child, ChildRole::Vite).await;
}

/// The spec's promised integration test: teardown reaps a grandchild tree.
/// Control-channel death-watch pattern: the GRANDCHILD holds the conn; EOF/RST
/// proves the tree died.
#[skuld::test]
async fn teardown_reaps_grandchild_tree() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(std::env::current_exe().unwrap());
    cmd.arg(std::env::current_exe().unwrap());
    cmd.env(test_child::MODE_ENV, "spawn-grandchild");
    cmd.env(test_child::CONTROL_ENV, listener.local_addr().unwrap().to_string());
    cmd.stdin(cosca::Stdio::null()).unwrap();
    cmd.kill_on_drop(true)
        .contain()
        .nesting(cosca::containment::Nesting::Mark);
    let mut child = cmd.spawn().unwrap();
    let (mut conn, _) = listener.accept().await.unwrap();
    let mut byte = [0u8; 1];
    conn.read_exact(&mut byte).await.unwrap(); // grandchild readiness

    teardown_grouped(&mut child, ChildRole::Vite).await;

    // Production parity: the supervise funnel drops the child slots right
    // after shutdown, and Drop's tree reap (job kill / group SIGKILL) is the
    // backstop for tree members the graceful phase cannot reach — on Windows
    // CTRL_BREAK stops at console-group boundaries, so a grandchild in its own
    // console group (this harness's deliberate #197 mirror) dies only here.
    // The contract under test is "teardown + drop leaves no survivors",
    // matching the real funnel order.
    drop(child);

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

/// cosca's argv **includes argv[0]** — `executable()` only overrides which file
/// the OS loads, it never supplies a program name. So a caller holding a full
/// argv (`bridge_argv`) passes all of it: skipping `argv[0]` would drop the
/// program name, and prepending it again would hand `sudo` a second copy of
/// itself. `spawn_bridge`'s caller is the only site that passes a multi-element
/// argv, and it is the real elevated bridge launch that no other test can reach.
#[skuld::test]
async fn contained_spawn_delivers_the_whole_argv_verbatim() {
    let exe = std::env::current_exe().unwrap();
    // The production shape: bridge_argv's argv[0] IS the program, followed by
    // its own arguments.
    let argv: Vec<String> = vec![
        exe.to_string_lossy().into_owned(),
        "bridge".into(),
        "run".into(),
        "--socket-path".into(),
        "/tmp/hole-dev.sock".into(),
    ];

    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(&argv[0]);
    cmd.args(&argv);
    cmd.env(test_child::MODE_ENV, "echo-argv");
    cmd.stdin(cosca::Stdio::null()).unwrap();
    cmd.stdout(cosca::Stdio::pipe()).unwrap();
    cmd.kill_on_drop(true)
        .contain()
        .nesting(cosca::containment::Nesting::Mark);
    let mut child = cmd.spawn().unwrap();

    let mut received = Vec::new();
    let mut lines = tokio::io::BufReader::new(child.stdout().unwrap()).lines();
    while let Some(line) = lines.next_line().await.unwrap() {
        received.push(line);
    }
    child.wait().await.unwrap();

    assert_eq!(received, argv, "the child's argv must be the argv we passed");
}

/// The sequence `run_vite_and_measure` depends on, with a real descendant.
///
/// `kill_tree` only signals, and the ROOT's own `wait` says nothing about a
/// grandchild — the process that mutates the console input mode there is
/// node/esbuild, not npm, and conhost keeps changing console state while a
/// member is still being torn down. `wait_tree` is the job object's
/// kernel-owned process-count edge: it is what orders anything read afterwards
/// against every member having FINISHED exiting.
///
/// The order is forced: `kill_tree` CLOSES the job handle, which is that same
/// edge, so a drain check after it answers `Unassessable`. The tree is asked to
/// end cooperatively and the drain is what confirms it — an escalation would
/// destroy the evidence it exists to collect.
///
/// `exited_children_are_not_signalled` cannot stand in for this: its child has
/// no descendants, so it pins only the root's own reap.
#[cfg(windows)]
#[skuld::test]
async fn wait_tree_drains_the_grandchild_after_the_cooperative_signal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = cosca::tokio::Command::new();
    cmd.executable(std::env::current_exe().unwrap());
    cmd.arg(std::env::current_exe().unwrap());
    // Same console group, so CTRL_BREAK reaches the grandchild too — the shape
    // `npm run dev` has, where node and esbuild share Vite's group.
    cmd.env(test_child::MODE_ENV, "spawn-grandchild-same-group");
    cmd.env(test_child::CONTROL_ENV, listener.local_addr().unwrap().to_string());
    cmd.stdin(cosca::Stdio::null()).unwrap();
    cmd.kill_on_drop(true)
        .contain()
        .nesting(cosca::containment::Nesting::Mark);
    let mut child = cmd.spawn().unwrap();

    let (mut conn, _) = listener.accept().await.unwrap();
    let mut byte = [0u8; 1];
    conn.read_exact(&mut byte).await.unwrap(); // grandchild readiness

    child.terminate_tree().unwrap();
    // Class-2 bound: an out-of-process exit that might never come. A tree that
    // stops honouring the signal must fail here, loudly, rather than be
    // escalated past — the escalation is what would hide it.
    let drain = child.wait_tree_timeout(crate::supervise::GRACE_TIMEOUT).await.unwrap();
    assert_eq!(
        drain,
        cosca::containment::TreeDrain::AllMembersExited,
        "the job object's membership count is kernel-owned: this is positive proof, not advisory"
    );

    // No drop and no root wait: after the drain edge ALONE the grandchild must
    // already be gone. Only the grandchild's own process can hold this socket.
    let mut buf = [0u8; 1];
    match conn.read(&mut buf).await {
        Ok(0) => {}
        Ok(n) => panic!("grandchild sent {n} unexpected byte(s) after the tree drained"),
        Err(e) => assert!(
            matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ),
            "the grandchild must be gone once wait_tree returns; got: {e:?}"
        ),
    }
    child.wait().await.unwrap();
}
