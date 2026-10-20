//! A non-reaping exit watch for a child process, for Linux kernels where cosca's pidfd watch is unavailable.
//!
//! `waitid(P_PID, WEXITED | WNOWAIT)` reports an exit and leaves the child a zombie, so its pid (and the process group
//! id it leads) stays ours until the caller reaps it. A blocking `waitid` on a thread would need no signal, but a
//! dropped watch could not stop it, and a runtime waits for such a thread when it shuts down. `SIGCHLD` wakes a
//! non-blocking check instead, and dropping the future ends the watch.

use std::io;

use rustix::process::{waitid, Pid, WaitId, WaitIdOptions};
use tokio::signal::unix::{signal, SignalKind};

/// Resolves once the child `pid` has exited, leaving it unreaped. An error if `pid` is not a child of this process.
pub(crate) async fn wait_exit_without_reaping(pid: u32) -> io::Result<()> {
    let pid = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{pid} is not a process id")))?;
    // Subscribed before the first look, so an exit between the look and the wait still wakes the loop.
    let mut child_state_changed = signal(SignalKind::child())?;
    loop {
        if has_exited(pid)? {
            return Ok(());
        }
        // `SIGCHLD` is coalesced and also announces other children; each wake re-reads this child's state.
        if child_state_changed.recv().await.is_none() {
            return Err(io::Error::other("the SIGCHLD stream closed"));
        }
    }
}

/// One non-blocking look at the child's state.
fn has_exited(pid: Pid) -> io::Result<bool> {
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    Ok(waitid(WaitId::Pid(pid), options)?.is_some())
}
