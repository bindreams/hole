//! Cross-platform exit-wait relaunch.
//!
//! When the GUI must replace itself with a new on-disk image (self-heal, or
//! post-update), it can't just spawn-and-exit: the new instance would lose
//! the `com.hole.app` single-instance lock to the still-running old one and
//! silently forward-and-exit. Instead the old GUI spawns the new image with
//! [`spawn_successor`], which (via [`await_predecessor`] at the top of the
//! new process) **arms a kernel wait on the old PID while it is provably
//! alive**, signals `READY`, and only then blocks. The old GUI exits on
//! `READY`; the new image's wait fires and it proceeds to a normal launch,
//! winning the now-free lock. Arming-before-READY-before-exit closes the
//! PID-reuse window — no sleeps, no polling.

use std::path::Path;

const AWAIT_ENV: &str = "HOLE_AWAIT_EXIT_PID";
const READY: &str = "READY";

/// A kernel wait on another process's exit, armed while that process is
/// still alive (so its PID cannot be recycled out from under us).
pub struct ArmedWait(platform::Inner);

impl ArmedWait {
    /// Arm a wait on `pid`'s exit. Must be called while `pid` is alive; if it
    /// is already gone, [`wait`](Self::wait) becomes a no-op.
    pub fn arm(pid: u32) -> std::io::Result<Self> {
        Ok(Self(platform::Inner::arm(pid)?))
    }

    /// Block until the armed process exits (kernel wait, no timeout).
    pub fn wait(self) {
        self.0.wait();
    }
}

/// Spawn the canonical image to take over after we exit, blocking until it
/// has armed its wait on us (the `READY` line). The caller exits next, at
/// which point the successor's wait fires.
pub fn spawn_successor(canonical: &Path) -> std::io::Result<()> {
    use std::io::BufRead;
    let mut child = std::process::Command::new(canonical)
        .env(AWAIT_ENV, std::process::id().to_string())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let mut line = String::new();
    std::io::BufReader::new(stdout).read_line(&mut line)?;
    if line.trim_end() != READY {
        return Err(std::io::Error::other("successor did not arm exit-wait"));
    }
    Ok(())
}

/// Called at the very top of GUI launch. If we were spawned to take over a
/// predecessor, arm a wait on it, signal `READY` (so it may exit), then
/// block until it does — after which a normal launch proceeds uncontested.
/// A no-op (returns immediately) for an ordinary launch.
pub fn await_predecessor() -> std::io::Result<()> {
    let Some(pid) = std::env::var(AWAIT_ENV).ok().and_then(|s| s.parse::<u32>().ok()) else {
        return Ok(());
    };
    // edition 2021: env mutation is still safe-callable.
    std::env::remove_var(AWAIT_ENV);
    let armed = ArmedWait::arm(pid)?;
    println!("{READY}");
    use std::io::Write;
    std::io::stdout().flush().ok();
    armed.wait();
    Ok(())
}

// Windows: OpenProcess(SYNCHRONIZE) + WaitForSingleObject(INFINITE) ===================================================

#[cfg(windows)]
mod platform {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE};

    pub(super) struct Inner(Option<HANDLE>);

    impl Inner {
        pub(super) fn arm(pid: u32) -> std::io::Result<Self> {
            // SAFETY: plain Win32 call. On failure (no such process / already
            // exited / access denied for a reaped PID) the wait is a no-op.
            match unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) } {
                Ok(h) if !h.is_invalid() => Ok(Self(Some(h))),
                _ => Ok(Self(None)),
            }
        }

        pub(super) fn wait(self) {
            if let Some(h) = self.0 {
                // SAFETY: `h` is a live process handle from OpenProcess; we
                // block on it then close it exactly once. Any return value
                // means the process has exited (or the wait failed) — either
                // way the caller proceeds.
                unsafe {
                    let _ = WaitForSingleObject(h, INFINITE);
                    let _ = CloseHandle(h);
                }
            }
        }
    }
}

// macOS: kqueue EVFILT_PROC / NOTE_EXIT ===============================================================================

#[cfg(target_os = "macos")]
mod platform {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    pub(super) struct Inner(Option<OwnedFd>);

    impl Inner {
        pub(super) fn arm(pid: u32) -> std::io::Result<Self> {
            // SAFETY: kqueue() returns a new fd or -1.
            let kq = unsafe { libc::kqueue() };
            if kq < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: kq is a fresh, owned kqueue fd.
            let kq = unsafe { OwnedFd::from_raw_fd(kq) };

            let kev = libc::kevent {
                ident: pid as libc::uintptr_t,
                filter: libc::EVFILT_PROC,
                flags: libc::EV_ADD | libc::EV_ONESHOT,
                fflags: libc::NOTE_EXIT,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            // SAFETY: register one change (nevents=0). A dead PID yields -1 +
            // ESRCH, which we map to a no-op wait.
            let rc = unsafe { libc::kevent(kq.as_raw_fd(), &kev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ESRCH) {
                    return Ok(Self(None));
                }
                return Err(err);
            }
            Ok(Self(Some(kq)))
        }

        pub(super) fn wait(self) {
            let Some(kq) = self.0 else {
                return;
            };
            // SAFETY: blocking kevent (NULL timeout) for the one NOTE_EXIT.
            // Any return means the process has exited; the kqueue fd is closed
            // by OwnedFd's Drop.
            let mut out: libc::kevent = unsafe { std::mem::zeroed() };
            let _ = unsafe { libc::kevent(kq.as_raw_fd(), std::ptr::null(), 0, &mut out, 1, std::ptr::null()) };
        }
    }
}

#[cfg(test)]
#[path = "relaunch_tests.rs"]
mod relaunch_tests;
