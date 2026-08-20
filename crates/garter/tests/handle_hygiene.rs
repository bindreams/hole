//! `CreateProcessW` with `bInheritHandles = TRUE` and no handle list hands the child
//! EVERY handle currently marked inheritable — not only the ones nominated as its
//! stdio. A grandchild whose own stdio was redirected elsewhere can therefore still
//! hold a duplicate of its grandparent's stdout write end, and the supervisor reading
//! that pipe never sees EOF (bindreams/hole#197). That invariant has no test in this
//! repo or in cosca (filed upstream as bindreams/cosca#103), and this is the change
//! that could break it.
//!
//! The two legs differ only in HOW the grandchild is spawned. The control leg uses
//! `std::process::Command`, which scopes nothing, and must observe the leak; the real
//! leg uses a nested contained cosca spawn and must not.
//!
//! What the real leg pins is the handle list, not the clear. A cosca spawn that names
//! its program — every spawn hole makes — routes to the raw `CreateProcessW` backend,
//! which nominates exactly its own stdio through `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`:
//! an allowlist, in force whether or not the spawn is contained. So an uncontained
//! cosca spawn is no control at all. `clear_std_handle_inheritance` is the weaker
//! second mechanism, and it covers the case hole does not have: an argv-only spawn,
//! which routes to the std backend where no handle list applies.
//!
//! The control runs first on purpose: if the hazard stops reproducing at all — a
//! change in how cargo or std marks handles — the real leg's EOF proves nothing, and
//! the control says so out loud.

#[cfg(windows)]
mod common;

#[cfg(windows)]
use common::mock_plugin_path;
#[cfg(windows)]
use cosca::tokio::{Child, ChildStdout, Command};
#[cfg(windows)]
use cosca::Stdio;
#[cfg(windows)]
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader, Lines};
#[cfg(windows)]
use tokio::net::{TcpListener, TcpStream};

/// Start one leg: a contained helper (both legs), which spawns its grandchild through
/// the route `nest` names — `"std"` for the unscoped control, `"contain"` for the
/// nested cosca spawn under test.
///
/// Containing the helper in BOTH legs is what makes `kill_tree` legal on it either
/// way, and the control leg's std-spawned grandchild is still reaped, because Windows
/// job membership is inherited regardless of how the child was created.
#[cfg(windows)]
async fn start_leg(nest: &str) -> (Child, Lines<BufReader<TcpStream>>, ChildStdout) {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();

    let mut cmd = Command::new();
    cmd.executable(mock_plugin_path())
        .arg(mock_plugin_path())
        .env("MOCK_PLUGIN_HYGIENE_PROBE", control_addr.to_string())
        .env("MOCK_PLUGIN_HYGIENE_NEST", nest)
        .kill_on_drop(true)
        .contain()
        .nesting(cosca::containment::Nesting::Mark);
    cmd.stdin(Stdio::null()).unwrap();
    cmd.stdout(Stdio::pipe()).unwrap();
    cmd.stderr(Stdio::null()).unwrap();
    let mut helper = cmd.spawn().unwrap();

    let host_pipe = helper.stdout().expect("the helper's stdout was piped");
    let (conn, _) = control
        .accept()
        .await
        .expect("the grandchild dials the control channel");
    (helper, BufReader::new(conn).lines(), host_pipe)
}

/// A closed write end: `Ok(0)` on a graceful close, or a broken-pipe error when the
/// holder was killed. Anything else — including bytes — is a live holder.
#[cfg(windows)]
#[track_caller]
fn assert_pipe_eof(read: std::io::Result<usize>, context: &str) {
    match read {
        Ok(0) => {}
        Ok(n) => panic!("{context}: read {n} byte(s); the host pipe is still held"),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(e) => panic!("{context}: unexpected error reading the host pipe: {e}"),
    }
}

#[cfg(windows)]
#[skuld::test]
async fn contained_spawn_keeps_the_host_pipe_out_of_a_grandchild() {
    // Positive control: spawned by std, the grandchild inherits the host pipe.
    {
        let (mut helper, mut control, mut host_pipe) = start_leg("std").await;
        let verdict = control
            .next_line()
            .await
            .unwrap()
            .expect("the grandchild reports its verdict");
        assert_eq!(
            verdict, "held",
            "the #197 hazard no longer reproduces even through an unscoped spawn, so the real leg's EOF would prove nothing"
        );

        let mut sentinel = [0u8; 8];
        host_pipe
            .read_exact(&mut sentinel)
            .await
            .expect("the grandchild's sentinel arrives on the host pipe");
        assert_eq!(&sentinel, b"HYGIENE\n");

        helper.kill_tree().unwrap();
        helper.wait().await.unwrap();

        let mut buf = [0u8; 1];
        assert_pipe_eof(host_pipe.read(&mut buf).await, "after the tree was reaped");
    }

    // The real leg: spawned through cosca, the grandchild does not hold the pipe, so
    // it EOFs while the grandchild is still parked on its control connection — which
    // the verdict line, written after the probe, is the evidence for.
    {
        let (mut helper, mut control, mut host_pipe) = start_leg("contain").await;
        let verdict = control
            .next_line()
            .await
            .unwrap()
            .expect("the grandchild reports its verdict");
        assert_eq!(verdict, "clear");

        let mut buf = [0u8; 1];
        assert_pipe_eof(
            host_pipe.read(&mut buf).await,
            "with a live grandchild that does not hold the pipe",
        );

        helper.kill_tree().unwrap();
        helper.wait().await.unwrap();
    }
}

hole_test_observability::register!();

fn main() {
    skuld::run_all();
}
