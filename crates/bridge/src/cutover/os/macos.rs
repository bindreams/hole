//! Real macOS `CutoverOs`: swap both images (`renamex_np` for the `.app`, plain
//! rename for `HELPER_PATH`) + graceful SIGTERM restart with a kqueue
//! wait-for-exit. Self-orchestrated inline (the bridge is root; the restart is a
//! fire-once `launchctl` call launchd carries out, so no detached survivor is
//! needed beyond the response-flush task the apply layer spawns).
//!
//! Raw FFI (libc kqueue) is sanctioned here per the #165 isolation contract;
//! the blocking `kevent` is a kernel rendezvous for `NOTE_EXIT`, not a poll.
#![allow(clippy::disallowed_methods)]

use crate::cutover::os::CutoverOs;
use crate::platform::os::LAUNCHD_LABEL;
use crate::platform::swap::{execute_swap, SwapPlan};

pub struct MacosCutoverOs {
    pub plan: SwapPlan,
    /// Pid of the running bridge to wait on for exit after SIGTERM.
    pub bridge_pid: i32,
}

impl MacosCutoverOs {
    fn launchctl(args: &[&str]) -> std::io::Result<()> {
        let out = std::process::Command::new("launchctl").args(args).output()?;
        if !out.status.success() {
            return Err(std::io::Error::other(format!(
                "launchctl {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }
}

impl CutoverOs for MacosCutoverOs {
    fn swap_images(&mut self) -> std::io::Result<()> {
        execute_swap(&self.plan)
    }

    fn stop_service_wait_stopped(&mut self) -> std::io::Result<()> {
        // Graceful SIGTERM (NOT `kickstart -k`'s SIGKILL): rides
        // `shutdown_signal` -> `pm.stop()`, so the marker-conditional disarm
        // fires and routes/DNS tear down. Then a kqueue `NOTE_EXIT` waits for
        // the real exit — a kernel event, never a sleep.
        Self::launchctl(&["kill", "SIGTERM", &format!("system/{LAUNCHD_LABEL}")])?;
        wait_pid_exit(self.bridge_pid)
    }

    fn start_service_wait_running(&mut self) -> std::io::Result<()> {
        // KeepAlive may race-respawn after SIGTERM; an explicit start after the
        // confirmed exit is idempotent and deterministic. launchd re-execs the
        // (now swapped) helper path = new inode.
        Self::launchctl(&["start", LAUNCHD_LABEL])
    }
}

/// Block until `pid` exits via kqueue `EVFILT_PROC`/`NOTE_EXIT` (a real kernel
/// event — never a sleep). Mirrors `hole`'s `relaunch.rs` exit-wait; the two are
/// kept in sync. A pid already gone yields `ESRCH`, treated as "already exited".
fn wait_pid_exit(pid: i32) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: kqueue() returns a fresh owned fd or -1.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: kq is a fresh, owned kqueue fd; OwnedFd closes it on drop.
    let kq = unsafe { OwnedFd::from_raw_fd(kq) };

    let change = libc::kevent {
        ident: pid as libc::uintptr_t,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ONESHOT,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let mut out: libc::kevent = unsafe { std::mem::zeroed() };
    // SAFETY: one change registered + one event awaited (NULL timeout blocks
    // until NOTE_EXIT). A dead pid yields -1 + ESRCH = already exited.
    let n = unsafe { libc::kevent(kq.as_raw_fd(), &change, 1, &mut out, 1, std::ptr::null()) };
    if n < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            return Ok(()); // already gone
        }
        return Err(err);
    }
    Ok(())
}
