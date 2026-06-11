use std::process::Stdio;

use crate::grouped_child::{GroupedChild, Nesting, NESTED_ENV, NESTED_ENV_LEGACY};
use crate::test_child;

use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;

// Serialization: `GroupedChild::spawn` READS the process env (root detection)
// in every test and two tests WRITE it; skuld runs all tests in one process.
// Serial filters match against running tests' LABELS, so every test here must
// both carry the label and serialize on it (precedent:
// crates/plugin-e2e/tests/interop.rs).
#[skuld::label]
const KILL_GROUP_ENV: skuld::Label;

/// Build a `tokio::process::Command` re-invoking this test binary in `mode`,
/// pointed at `control` for the liveness dial-back.
fn child_cmd(mode: &str, control: std::net::SocketAddr) -> tokio::process::Command {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = tokio::process::Command::new(exe);
    cmd.env(test_child::MODE_ENV, mode);
    cmd.env(test_child::CONTROL_ENV, control.to_string());
    cmd.env_remove(NESTED_ENV); // tests control root/nested explicitly
    cmd.env_remove(NESTED_ENV_LEGACY);
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    cmd.kill_on_drop(true);
    cmd
}

/// Read the one readiness byte, then return the conn for the death-watch.
async fn await_ready(listener: &TcpListener) -> tokio::net::TcpStream {
    let (mut conn, _) = listener.accept().await.expect("child dials control");
    let mut byte = [0u8; 1];
    conn.read_exact(&mut byte).await.expect("readiness byte");
    assert_eq!(&byte, b"+");
    conn
}

/// EOF or RST on the control conn proves the process holding it died.
/// (Reuse-immune; sleep-free; bounded by the nextest per-test timeout —
/// the sanctioned class-2 failure-to-human bound.)
async fn assert_dies(mut conn: tokio::net::TcpStream) {
    let mut buf = [0u8; 1];
    match conn.read(&mut buf).await {
        Ok(0) => {}
        Ok(n) => panic!("child sent {n} unexpected byte(s)"),
        Err(e) => assert!(
            matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ),
            "unexpected control-conn error: {e:?}"
        ),
    }
}

#[skuld::test(labels = [KILL_GROUP_ENV], serial = KILL_GROUP_ENV)]
async fn root_spawn_marks_descendants() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = child_cmd("sleep", listener.local_addr().unwrap());
    let mut gc = GroupedChild::spawn(&mut cmd, Nesting::Mark).unwrap();
    // Structural pin: Mark must have injected BOTH marker names into the
    // child env (the legacy name is the published-binary compat contract).
    for var in [NESTED_ENV, NESTED_ENV_LEGACY] {
        let marked = cmd
            .as_std()
            .get_envs()
            .any(|(k, v)| k == std::ffi::OsStr::new(var) && v.is_some());
        assert!(marked, "Mark spawn must set {var} on the child");
    }
    let conn = await_ready(&listener).await;
    gc.kill_tree().await;
    assert_dies(conn).await;
}

/// NOTE: nextest may occasionally flag this test `LEAK`: the death-watch
/// fires on the grandchild's socket EOF (its death), but the OS-level
/// process teardown (SIGKILL delivery → reparent → reap by init/launchd)
/// can still be in flight when nextest snapshots handles. The contract —
/// the grandchild DIES — is fully verified; there is no userspace
/// rendezvous for "non-child process fully reaped" (kill(2) is async by
/// design), and the default nextest profile does not fail on leaks.
#[skuld::test(labels = [KILL_GROUP_ENV], serial = KILL_GROUP_ENV)]
async fn kill_tree_reaps_grandchild() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = child_cmd("spawn-grandchild", listener.local_addr().unwrap());
    let mut gc = GroupedChild::spawn(&mut cmd, Nesting::Mark).unwrap();
    // The GRANDCHILD (sleep mode) dials the control listener; its conn is the
    // death-watch. The intermediate child never dials.
    let grandchild_conn = await_ready(&listener).await;
    gc.kill_tree().await;
    assert_dies(grandchild_conn).await;
}

/// NOTE: nextest may occasionally flag this test `LEAK`: the death-watch
/// fires on the grandchild's socket EOF (its death), but the OS-level
/// process teardown (SIGKILL delivery → reparent → reap by init/launchd)
/// can still be in flight when nextest snapshots handles. The contract —
/// the grandchild DIES — is fully verified; there is no userspace
/// rendezvous for "non-child process fully reaped" (kill(2) is async by
/// design), and the default nextest profile does not fail on leaks.
#[skuld::test(labels = [KILL_GROUP_ENV], serial = KILL_GROUP_ENV)]
async fn drop_reaps_grandchild() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = child_cmd("spawn-grandchild", listener.local_addr().unwrap());
    let gc = GroupedChild::spawn(&mut cmd, Nesting::Mark).unwrap();
    let grandchild_conn = await_ready(&listener).await;
    drop(gc); // Drop = synchronous tree reap
    assert_dies(grandchild_conn).await;
}

#[skuld::test(labels = [KILL_GROUP_ENV], serial = KILL_GROUP_ENV)]
async fn nested_spawn_creates_no_group() {
    // Simulate being inside an ancestor's kill-group: with the marker set in
    // OUR process env (that is what root detection reads; in real nesting it
    // arrived by inheritance), spawn() must not create a new group (Unix
    // pgids don't nest — a fresh group would ESCAPE the ancestor's kill).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = child_cmd("sleep", listener.local_addr().unwrap());
    // SAFETY: serialized on KILL_GROUP_ENV — no other test reads or writes
    // the process environment concurrently (precedent:
    // crates/hole/src/logging_tests.rs:12-30).
    unsafe { std::env::set_var(NESTED_ENV, "1") };
    let result = GroupedChild::spawn(&mut cmd, Nesting::Mark);
    // SAFETY: as above.
    unsafe { std::env::remove_var(NESTED_ENV) };
    let mut gc = result.unwrap();
    assert!(!gc.is_root(), "marker set => nested spawn, no new group");
    let conn = await_ready(&listener).await;
    gc.kill_tree().await;
    assert_dies(conn).await;
}

#[skuld::test(labels = [KILL_GROUP_ENV], serial = KILL_GROUP_ENV)]
async fn legacy_marker_is_honored() {
    // Cross-version compat: a PUBLISHED old garter/garter-bin still sets
    // GARTER_IN_KILL_GROUP; a new kill-group nested under it must join, not
    // escape (the standalone garter-bin + new-galoshes skew — see the module
    // docs). Same env-serialization rules as above.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = child_cmd("sleep", listener.local_addr().unwrap());
    // SAFETY: serialized on KILL_GROUP_ENV.
    unsafe { std::env::set_var(NESTED_ENV_LEGACY, "1") };
    let result = GroupedChild::spawn(&mut cmd, Nesting::Mark);
    // SAFETY: as above.
    unsafe { std::env::remove_var(NESTED_ENV_LEGACY) };
    let mut gc = result.unwrap();
    assert!(!gc.is_root(), "legacy marker set => nested spawn");
    let conn = await_ready(&listener).await;
    gc.kill_tree().await;
    assert_dies(conn).await;
}

/// The root child must already be inside the job before its first
/// instruction runs. With suspended-spawn→assign→resume this holds by
/// construction; IsProcessInJob right after spawn() returns is the
/// observable pin (spawn() resumes before returning, but membership is
/// irrevocable — a process cannot leave a job).
#[cfg(windows)]
#[skuld::test(labels = [KILL_GROUP_ENV], serial = KILL_GROUP_ENV)]
async fn root_child_is_inside_job_after_spawn() {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::IsProcessInJob;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = child_cmd("sleep", listener.local_addr().unwrap());
    let mut gc = GroupedChild::spawn(&mut cmd, Nesting::Mark).unwrap();
    let raw = gc.child.raw_handle().expect("child handle");
    let mut in_job = windows::core::BOOL::default();
    // Job=None asks "is it in ANY job" — terminals already put us in one, so
    // ask against OUR job handle, exposed via a crate-private test probe.
    let job = gc.test_job_handle().expect("root spawn has a job");
    // SAFETY: both handles are live for the duration of the call. The job
    // parameter is Option<HANDLE> (None would ask "in ANY job", which is
    // always true under Windows Terminal) — verified against windows 0.62.
    unsafe { IsProcessInJob(HANDLE(raw), Some(job), &mut in_job).unwrap() };
    assert!(in_job.as_bool(), "child must be assigned before resume");
    let conn = await_ready(&listener).await; // also proves resume happened
    gc.kill_tree().await;
    assert_dies(conn).await;
}

/// Graceful phase: the group signal must reach a child that handles it
/// (SIGTERM on Unix / CTRL_BREAK on Windows) and let it exit CLEANLY (0) —
/// distinct from kill_tree's hard kill.
#[skuld::test(labels = [KILL_GROUP_ENV], serial = KILL_GROUP_ENV)]
async fn signal_group_term_lets_child_exit_cleanly() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = child_cmd("trap-term", listener.local_addr().unwrap());
    let mut gc = GroupedChild::spawn(&mut cmd, Nesting::Mark).unwrap();
    // Readiness byte arrives only after the child installed its handler —
    // no race between install and signal.
    let _conn = await_ready(&listener).await;
    gc.signal_group_term().unwrap();
    let status = gc.child.wait().await.unwrap();
    assert!(status.success(), "graceful signal must produce exit 0, got {status:?}");
}

/// The nested/degraded arm: with no group of our own, the graceful signal
/// goes to the direct child — which must still exit cleanly.
#[skuld::test(labels = [KILL_GROUP_ENV], serial = KILL_GROUP_ENV)]
async fn signal_group_term_reaches_nested_child_directly() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = child_cmd("trap-term", listener.local_addr().unwrap());
    // SAFETY: serialized on KILL_GROUP_ENV (see the file-head comment).
    unsafe { std::env::set_var(NESTED_ENV, "1") };
    let result = GroupedChild::spawn(&mut cmd, Nesting::Mark);
    // SAFETY: as above.
    unsafe { std::env::remove_var(NESTED_ENV) };
    let mut gc = result.unwrap();
    assert!(!gc.is_root());
    let _conn = await_ready(&listener).await;
    gc.signal_group_term().unwrap();
    let status = gc.child.wait().await.unwrap();
    assert!(
        status.success(),
        "nested graceful signal must produce exit 0, got {status:?}"
    );
}

/// term_group on an already-dead group is success (ESRCH tolerance) — the
/// teardown path must not error when the tree died before the graceful phase.
/// The EPERM→leader fallback is NOT unit-testable without a privilege
/// boundary (it needs a group member this uid may not signal); it is
/// exercised for real by the dev-mode supervisor's sudo bridge (PR 2 smoke
/// test) and documented on `term_group`.
#[cfg(unix)]
#[skuld::test(labels = [KILL_GROUP_ENV], serial = KILL_GROUP_ENV)]
async fn term_group_tolerates_dead_group() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = child_cmd("sleep", listener.local_addr().unwrap());
    let mut gc = GroupedChild::spawn(&mut cmd, Nesting::Mark).unwrap();
    let pgid = gc.child.id().expect("live child has a pid");
    let conn = await_ready(&listener).await;
    gc.kill_tree().await;
    assert_dies(conn).await;
    // NOTE: gc (and its reaped Child) is still alive in this scope, so the
    // pid is not recyclable — matching term_group's hold-the-leader contract
    // as closely as a dead-group test can.
    crate::grouped_child::term_group(pgid).expect("dead group is ESRCH => success");
}

#[skuld::test(labels = [KILL_GROUP_ENV], serial = KILL_GROUP_ENV)]
async fn opaque_root_does_not_mark_descendants() {
    // Nesting::Opaque: a group IS created (is_root), but the child env must
    // NOT carry either marker — its own kill-group spawns become roots again.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cmd = child_cmd("sleep", listener.local_addr().unwrap());
    let mut gc = GroupedChild::spawn(&mut cmd, Nesting::Opaque).unwrap();
    assert!(gc.is_root());
    for var in [NESTED_ENV, NESTED_ENV_LEGACY] {
        let marked = cmd
            .as_std()
            .get_envs()
            .any(|(k, v)| k == std::ffi::OsStr::new(var) && v.is_some());
        assert!(!marked, "Opaque spawn must not set {var} on the child");
    }
    let conn = await_ready(&listener).await;
    gc.kill_tree().await;
    assert_dies(conn).await;
}
