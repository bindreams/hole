// Real-child teardown -------------------------------------------------------------------------------------------------
//
// `FakeTree` records calls; it cannot see what dropping a real `cosca::tokio::Child` signals. These
// tests run `supervise_plugin` over a real child and observe a descendant of its process group.
#![allow(clippy::disallowed_methods)] // the test child is a shell, never privileged

use std::pin::pin;
use std::time::Duration;

use cosca::containment::Containment;
use cosca::tokio::Command;
use cosca::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio_util::sync::CancellationToken;

use crate::binary::{supervise_plugin, PluginEnd, PluginTree};

/// The descendant: prints its pid once it traps SIGTERM, then waits (on a child that holds none of
/// the test's pipes). A SIGTERM it receives alive makes it print `got-term`; one it receives after a
/// SIGKILL never runs the trap, so `got-term` proves the descendant outlived the supervision.
const DESCENDANT: &str = r#"
trap 'echo got-term; kill $!; exit 0' TERM
sleep 1000 </dev/null >/dev/null 2>&1 &
echo "ready $$"
wait $!
"#;

/// The root starts the descendant in its own process group and exits at once.
const ROOT: &str = r#"sh -c "$DESCENDANT" </dev/null 2>/dev/null & exit 0"#;

/// A real child whose exit cannot be watched, so `supervise_plugin` reaps it first and leaves a
/// process-group tree alone.
struct UnwatchableRoot(cosca::tokio::Child);

fn unwatchable() -> cosca::error::Error {
    cosca::error::Error::Unsupported {
        op: "wait".into(),
        platform: "test",
        detail: "the exit watch is unavailable".into(),
    }
}

impl PluginTree for UnwatchableRoot {
    fn containment(&self) -> Containment {
        PluginTree::containment(&self.0)
    }
    async fn wait_root_exit(&self) -> Result<(), cosca::error::Error> {
        Err(unwatchable())
    }
    async fn wait_root_exit_within(&self, _grace: Duration) -> Result<bool, cosca::error::Error> {
        Err(unwatchable())
    }
    fn terminate(&self) -> Result<(), cosca::error::Error> {
        PluginTree::terminate(&self.0)
    }
    fn kill_root(&mut self) -> Result<(), cosca::error::Error> {
        PluginTree::kill_root(&mut self.0)
    }
    fn kill_tree(&mut self) -> Result<(), cosca::error::Error> {
        PluginTree::kill_tree(&mut self.0)
    }
    async fn wait_tree_drained(&self) -> Result<(), cosca::error::Error> {
        PluginTree::wait_tree_drained(&self.0).await
    }
    async fn reap(&mut self) -> Result<std::process::ExitStatus, cosca::error::Error> {
        PluginTree::reap(&mut self.0).await
    }
    fn disarm(&mut self) {
        PluginTree::disarm(&mut self.0)
    }
}

/// A real child whose exit is watched the way production watches it on a kernel without `pidfd_open`: cosca's watch
/// answers `Unsupported`, and `root_exit_watch` falls back to `waitid(WNOWAIT)`. Everything but the answer cosca
/// would have given is production's own code.
#[cfg(target_os = "linux")]
struct WaitidRoot(cosca::tokio::Child);

#[cfg(target_os = "linux")]
impl PluginTree for WaitidRoot {
    fn containment(&self) -> Containment {
        PluginTree::containment(&self.0)
    }
    async fn wait_root_exit(&self) -> Result<(), cosca::error::Error> {
        crate::binary::root_exit_watch(self.0.id().pid(), Err(unwatchable())).await
    }
    async fn wait_root_exit_within(&self, grace: Duration) -> Result<bool, cosca::error::Error> {
        crate::binary::root_exit_watch_within(self.0.id().pid(), grace, Err(unwatchable())).await
    }
    fn terminate(&self) -> Result<(), cosca::error::Error> {
        PluginTree::terminate(&self.0)
    }
    fn kill_root(&mut self) -> Result<(), cosca::error::Error> {
        PluginTree::kill_root(&mut self.0)
    }
    fn kill_tree(&mut self) -> Result<(), cosca::error::Error> {
        PluginTree::kill_tree(&mut self.0)
    }
    async fn wait_tree_drained(&self) -> Result<(), cosca::error::Error> {
        PluginTree::wait_tree_drained(&self.0).await
    }
    async fn reap(&mut self) -> Result<std::process::ExitStatus, cosca::error::Error> {
        PluginTree::reap(&mut self.0).await
    }
    fn disarm(&mut self) {
        PluginTree::disarm(&mut self.0)
    }
}

/// Sends SIGTERM to the descendant when the test ends, however it ends.
struct TermOnDrop(libc::pid_t);

impl Drop for TermOnDrop {
    fn drop(&mut self) {
        term(self.0);
    }
}

fn term(pid: libc::pid_t) {
    // SAFETY: `kill` on a pid the descendant reported itself; ESRCH (ignored) if it is gone.
    unsafe { libc::kill(pid, libc::SIGTERM) };
}

/// The root is reaped by `supervise_plugin`; dropping its handle afterwards must not signal the
/// process group the root led. Where `supervise_plugin` leaves the tree alone (a pgid containment),
/// the descendant is still alive afterwards; where it kills the tree, it is gone either way.
#[skuld::test]
async fn dropping_a_reaped_roots_handle_does_not_signal_its_process_group() {
    let mut cmd = Command::new();
    cmd.executable("/bin/sh");
    cmd.arg("/bin/sh");
    cmd.arg("-c");
    cmd.arg(ROOT);
    cmd.env("DESCENDANT", DESCENDANT);
    cmd.stdout(Stdio::pipe()).unwrap();
    cmd.stderr(Stdio::null()).unwrap();
    cmd.kill_on_drop(true);
    cmd.contain();
    cmd.nesting(cosca::containment::Nesting::Mark);
    let mut child = cmd.spawn().expect("spawn the shell");
    let containment = PluginTree::containment(&child);
    let mut stdout = BufReader::new(child.stdout().expect("stdout was piped"));

    let mut ready = String::new();
    stdout.read_line(&mut ready).await.unwrap();
    let pid: libc::pid_t = ready
        .strip_prefix("ready ")
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or_else(|| panic!("the descendant did not report its pid: {ready:?}"));
    let _term = TermOnDrop(pid);

    let mut tree = UnwatchableRoot(child);
    let reader = || tokio::spawn(async {});
    let shutdown = CancellationToken::new();
    let end = supervise_plugin(
        "p",
        &mut tree,
        &shutdown,
        Duration::from_secs(5),
        reader(),
        reader(),
        None,
    );
    let end = pin!(end).await.unwrap();
    assert!(
        matches!(&end.end, PluginEnd::Exited(s) if s.success()),
        "the root exited 0"
    );
    drop(tree);

    // SIGTERM reaches only a descendant that is still alive; its trap then answers on the pipe.
    term(pid);
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).await.unwrap();

    let tree_left_alone = match containment {
        Containment::ProcessGroup | Containment::Session | Containment::FdMarker => true,
        Containment::CgroupV2 | Containment::TreeWalk => false,
        other => panic!("a plain spawn produced {other:?}"),
    };
    assert_eq!(
        rest.contains("got-term"),
        tree_left_alone,
        "{containment:?}: descendant output {rest:?}"
    );
}

// Shutdown against an exit the reactor has not delivered --------------------------------------------------------------

/// A contained shell running `script`, with no output of its own.
fn shell(script: &str) -> cosca::tokio::Child {
    let mut cmd = Command::new();
    cmd.executable("/bin/sh");
    cmd.arg("/bin/sh");
    cmd.arg("-c");
    cmd.arg(script);
    cmd.stdout(Stdio::null()).unwrap();
    cmd.stderr(Stdio::null()).unwrap();
    cmd.kill_on_drop(true);
    cmd.contain();
    cmd.nesting(cosca::containment::Nesting::Mark);
    cmd.spawn().expect("spawn the shell")
}

fn cancelled() -> CancellationToken {
    let token = CancellationToken::new();
    token.cancel();
    token
}

/// The real exit watch registers a pidfd (kqueue on macOS) with the reactor, so it is `Pending` on its
/// first poll even for a root that is already a zombie; a shutdown request that is already pending
/// would win the select. The status of a root that exited first must still be reported.
#[skuld::test]
async fn an_exited_root_is_reported_as_exited_when_a_shutdown_request_is_already_pending() {
    let mut child = shell("exit 3");
    // The root is now a known, unreaped zombie.
    PluginTree::wait_root_exit(&child).await.expect("watch the root exit");

    let reader = || tokio::spawn(async {});
    let end = supervise_plugin(
        "p",
        &mut child,
        &cancelled(),
        Duration::from_secs(5),
        reader(),
        reader(),
        None,
    )
    .await
    .unwrap();

    assert!(
        matches!(&end.end, PluginEnd::Exited(s) if s.code() == Some(3)),
        "the root exited with 3 before the shutdown request: {}",
        match &end.end {
            PluginEnd::Exited(s) => format!("exited, {s:?}"),
            PluginEnd::ShutDown => "ShutDown".to_owned(),
        }
    );
}

/// The probe does not turn every shutdown into an exit: a root that is still running is shut down.
#[skuld::test]
async fn a_running_root_is_shut_down_when_a_shutdown_request_is_already_pending() {
    let mut child = shell("exec sleep 1000");

    let reader = || tokio::spawn(async {});
    let end = supervise_plugin(
        "p",
        &mut child,
        &cancelled(),
        Duration::from_secs(5),
        reader(),
        reader(),
        None,
    )
    .await
    .unwrap();

    assert!(matches!(end.end, PluginEnd::ShutDown), "a running root is shut down");
}

// A take-down against a root that is still running --------------------------------------------------------------------

/// The root keeps a descendant in its process group. It exits 0 on SIGTERM, or when its stdin closes (read through
/// fd 3: an async command's own stdin is /dev/null).
const LIVE_ROOT: &str =
    r#"exec 3<&0; sh -c "$DESCENDANT" </dev/null 2>/dev/null & trap 'exit 0' TERM; cat <&3 >/dev/null & wait $!"#;

/// How a take-down watches the root: through cosca's own watch, with `waitid` alone, or with its exit unwatchable.
#[derive(Clone, Copy, Debug)]
enum Watch {
    Cosca,
    #[cfg(target_os = "linux")]
    Waitid,
    Unwatchable,
}

/// Every way a take-down can watch the root where this platform has it.
const WATCHES: &[Watch] = &[
    Watch::Cosca,
    #[cfg(target_os = "linux")]
    Watch::Waitid,
    Watch::Unwatchable,
];

#[derive(Clone, Copy, Debug)]
enum TakenDownBy {
    Shutdown,
    StartFailure,
}

/// A sitrep reader that has decided the start failed, over a stdout that carries only the `hello`.
async fn decided_start_failure(shutdown: &CancellationToken) -> crate::binary::FailureHold {
    use tokio::io::AsyncWriteExt;
    let freed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (mut plugin_stdout, host_stdout) = tokio::io::duplex(4096);
    let hello = serde_json::to_string(&crate::sitrep::SitrepEvent::Hello {
        protocol: crate::sitrep::SITREP_PROTOCOL.into(),
    })
    .unwrap();
    plugin_stdout
        .write_all(
            format!(
                "{hello}
"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    drop(plugin_stdout);
    let (ready_tx, _ready_rx) = tokio::sync::oneshot::channel();
    let (reader, failure) = crate::binary::spawn_sitrep_stdout_reader(
        host_stdout,
        freed,
        shutdown.clone(),
        ready_tx,
        false,
        None,
        &crate::binary::ReadinessProbes::new("p", shutdown),
    );
    reader.await.unwrap();
    failure
}

/// A running root with a descendant in its group is taken down, and the descendant does not outlive it: it is killed,
/// not asked, so it never runs its SIGTERM trap.
async fn taken_down_root_leaves_no_descendant(watch: Watch, by: TakenDownBy) {
    let mut cmd = Command::new();
    cmd.executable("/bin/sh");
    cmd.arg("/bin/sh");
    cmd.arg("-c");
    cmd.arg(LIVE_ROOT);
    cmd.env("DESCENDANT", DESCENDANT);
    cmd.stdin(Stdio::pipe()).unwrap();
    cmd.stdout(Stdio::pipe()).unwrap();
    cmd.stderr(Stdio::null()).unwrap();
    cmd.kill_on_drop(true);
    cmd.contain();
    cmd.nesting(cosca::containment::Nesting::Mark);
    let mut child = cmd.spawn().expect("spawn the shell");
    let stdin = child.stdin().expect("stdin was piped");
    let mut stdout = BufReader::new(child.stdout().expect("stdout was piped"));
    let mut ready = String::new();
    stdout.read_line(&mut ready).await.unwrap();
    let pid: libc::pid_t = ready
        .strip_prefix("ready ")
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or_else(|| panic!("the descendant did not report its pid: {ready:?}"));
    let _term = TermOnDrop(pid);

    let shutdown = CancellationToken::new();
    let failure = match by {
        TakenDownBy::Shutdown => {
            shutdown.cancel();
            None
        }
        TakenDownBy::StartFailure => Some(decided_start_failure(&shutdown).await),
    };
    let reader = || tokio::spawn(async {});
    let grace = Duration::from_secs(30);
    let shutdown_ref = &shutdown;
    let supervised = async move {
        match watch {
            Watch::Cosca => supervise_plugin("p", &mut child, shutdown_ref, grace, reader(), reader(), failure).await,
            #[cfg(target_os = "linux")]
            Watch::Waitid => {
                let mut tree = WaitidRoot(child);
                supervise_plugin("p", &mut tree, shutdown_ref, grace, reader(), reader(), failure).await
            }
            Watch::Unwatchable => {
                let mut tree = UnwatchableRoot(child);
                supervise_plugin("p", &mut tree, shutdown_ref, grace, reader(), reader(), failure).await
            }
        }
    };
    // A plugin whose start failed is not asked to exit: it exits by itself, here once its stdin closes. The closing
    // runs after the supervision has started, so the root is still running when the take-down begins.
    let exits_by_itself = async {
        if matches!(by, TakenDownBy::StartFailure) {
            drop(stdin);
        }
    };
    let (ended, ()) = tokio::join!(supervised, exits_by_itself);
    let ended = ended.unwrap();
    // Where the exit can be watched, a failed-start root that exits within its grace is not killed and keeps its own
    // status; where it cannot, there is no grace and the root is killed.
    if matches!(by, TakenDownBy::StartFailure) {
        let exited_by_itself = matches!(&ended.end, PluginEnd::Exited(status) if status.success());
        assert_eq!(
            exited_by_itself,
            !matches!(watch, Watch::Unwatchable),
            "{watch:?}: the root's status after a failed start"
        );
    }

    // SIGTERM reaches only a descendant that is still alive; its trap then answers on the pipe.
    term(pid);
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).await.unwrap();
    assert!(
        !rest.contains("got-term"),
        "{watch:?}, {by:?}: the descendant outlived the take-down: {rest:?}"
    );
}

#[skuld::test]
async fn a_shutdown_leaves_no_descendant_whether_or_not_the_exit_can_be_watched() {
    for &watch in WATCHES {
        taken_down_root_leaves_no_descendant(watch, TakenDownBy::Shutdown).await;
    }
}

#[skuld::test]
async fn a_failed_start_leaves_no_descendant_whether_or_not_the_exit_can_be_watched() {
    for &watch in WATCHES {
        taken_down_root_leaves_no_descendant(watch, TakenDownBy::StartFailure).await;
    }
}
