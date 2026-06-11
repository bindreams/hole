//! Cross-platform process-tree reaping for spawned children.
//!
//! A host force-kills a child on abrupt teardown (guard drop / drain-timeout).
//! The child may spawn its own children (e.g. galoshes spawns ex-ray); killing
//! only the direct child orphans those grandchildren. On Windows the orphan also
//! inherits the host's stdout/stderr pipe handles, so the host's pipe-reader
//! never EOFs and tokio's `Runtime::drop` blocks forever (bindreams/hole#197).
//!
//! [`GroupedChild`] fixes both, with no `#[cfg]` at any call site:
//!
//! - **Handle hygiene (Windows).** Before spawning, clear `HANDLE_FLAG_INHERIT`
//!   on this process's own std handles so the child inherits only its own stdio.
//!   This is the race-free fix for the hang: an orphan can never hold the host's
//!   pipes. (Unix already guarantees this via `dup2` + `CLOEXEC`.)
//! - **Tree-kill.** The child is spawned as the root of a kill-group whose whole
//!   descendant tree dies as a unit: a Windows Job Object with
//!   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, or a Unix process group killed with
//!   `kill(-pgid)`.
//!
//! **Root auto-detection.** Only the OUTERMOST kill-group spawn should create a
//! kill-group: Windows jobs nest (a grandchild created inside the root's job
//! joins it), but Unix process groups do not (a grandchild in its own group
//! escapes the ancestor's `kill(-pgid)`). So a kill-group must be created exactly
//! once, at the top. We detect "am I already inside a kill-group?" via the
//! inherited `KILL_GROUP_NESTED` env var: unset → we are the root (create the
//! group, mark the child's env); set → we are nested (spawn normally; the child
//! joins the ancestor's group). This needs no flag or wiring at call sites and
//! composes to arbitrary depth.
//!
//! **`KILL_GROUP_NESTED` is load-bearing: nothing outside kill-group may set
//! it.** An external value would misclassify the outermost spawn as nested, skip
//! the kill-group, and re-introduce the orphan/hang. Root detection is logged at
//! `debug` so a misdetection is diagnosable.
//!
//! **Legacy marker name.** This crate is garter's `proc_group` extracted; the
//! pre-extraction marker name `GARTER_IN_KILL_GROUP` ([`NESTED_ENV_LEGACY`])
//! remains part of the contract. garter and galoshes are PUBLISHED binaries
//! that can skew across versions: an old garter-bin (which sets only the
//! legacy name) can spawn a new galoshes (which checks the new name); without
//! honoring the legacy name the new side would misdetect "root", create its
//! own Unix process group, and its children would ESCAPE the ancestor's kill —
//! the #197 regression. Marked spawns therefore SET both names and root
//! detection HONORS both, indefinitely.

use std::io;
use tokio::process::{Child, Command};

/// Env var marking "this process is already inside a kill-group."
/// Inherited by every descendant; its presence makes a nested spawn skip
/// creating a new kill-group (see the module docs). **Load-bearing: nothing
/// outside kill-group may set it.**
pub const NESTED_ENV: &str = "KILL_GROUP_NESTED";

/// The pre-extraction name of [`NESTED_ENV`] (garter's `proc_group`).
/// Cross-version compat is load-bearing: garter and galoshes are PUBLISHED
/// binaries — an old garter-bin (which sets only this name) can spawn a new
/// galoshes (which checks the new name); without honoring the legacy name
/// the new side would misdetect "root", create its own Unix process group,
/// and its children would ESCAPE the ancestor's kill — the #197 regression.
/// Marked spawns therefore SET both names and root detection HONORS both,
/// indefinitely (two env vars are cheap; a removal deadline is not).
pub const NESTED_ENV_LEGACY: &str = "GARTER_IN_KILL_GROUP";

/// Whether a root spawn marks its descendants as inside the kill-group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nesting {
    /// Mark descendants (default): nested kill-group spawns inside the child
    /// join THIS group instead of creating their own.
    Mark,
    /// Leave descendants unmarked: the child's own kill-group spawns become
    /// roots of their own groups (which nest inside this one on Windows).
    /// Use when the child is itself a supervisor whose internal kill-groups
    /// must keep working — e.g. the dev bridge, whose garter plugin spawns
    /// must each get their own group.
    Opaque,
}

/// A spawned child whose entire descendant tree is reaped together when this
/// guard is [`Drop`]ped. See the module docs.
pub struct GroupedChild {
    pub child: Child,
    group: imp::Group,
}

impl GroupedChild {
    /// Spawn `cmd` with process-tree reaping and (on Windows) stdio handle
    /// hygiene. The caller owns `cmd`'s stdio configuration (piped, etc.).
    ///
    /// Lifecycle: the graceful-signal phase (a later task) does NOT reap;
    /// callers wait (bounded) and then either [`kill_tree`](Self::kill_tree)
    /// explicitly or let [`Drop`] hard-kill any survivors — Drop always runs
    /// the tree reap, so a graceful signal alone never leaks the group.
    pub fn spawn(cmd: &mut Command, nesting: Nesting) -> io::Result<Self> {
        let is_root = std::env::var_os(NESTED_ENV).is_none() && std::env::var_os(NESTED_ENV_LEGACY).is_none();
        if is_root {
            if nesting == Nesting::Mark {
                // Both names: see NESTED_ENV_LEGACY's compat contract.
                cmd.env(NESTED_ENV, "1");
                cmd.env(NESTED_ENV_LEGACY, "1");
            }
            tracing::debug!("kill-group: root spawn — creating a process-tree kill-group");
        } else {
            tracing::debug!("kill-group: nested spawn — joining the ancestor's kill-group");
        }
        imp::spawn(cmd, is_root)
    }

    /// True when this spawn created (or attempted) its own kill-group.
    pub fn is_root(&self) -> bool {
        self.group.is_root()
    }

    /// Hard-kill the whole tree and reap the direct child. Safe to call after
    /// the child already exited.
    pub async fn kill_tree(&mut self) -> io::Result<()> {
        self.group.kill();
        let _ = self.child.start_kill(); // degraded/nested case: direct child
        let _ = self.child.wait().await; // reap; ignore status — it was killed
        Ok(())
    }
}

impl Drop for GroupedChild {
    fn drop(&mut self) {
        // Reap the tree synchronously here (the backstop for task abort /
        // runtime drop, where graceful stop never ran) BEFORE `self.child`'s
        // `kill_on_drop` runs — so an orphan can never linger holding a pipe.
        self.group.kill();
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use windows::Win32::Foundation::{CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT};
    use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;

    /// Owns the Job Object handle (root only). Dropping/killing it terminates
    /// every process in the job (galoshes + ex-ray, which joined by inheritance).
    pub(super) struct Group {
        job: Option<HANDLE>,
    }

    // A Windows job-object HANDLE is a process-wide kernel handle; using it
    // (TerminateJobObject / CloseHandle) from another thread is sound. The raw
    // pointer in `HANDLE` is otherwise `!Send`, which would make the plugin's
    // `run` future non-`Send` and unspawnable.
    unsafe impl Send for Group {}

    impl Group {
        pub(super) fn is_root(&self) -> bool {
            self.job.is_some()
        }

        pub(super) fn kill(&mut self) {
            if let Some(job) = self.job.take() {
                // TerminateJobObject kills the whole tree synchronously; then we
                // release the handle. (KILL_ON_JOB_CLOSE would also fire on the
                // close, but terminating first avoids any runtime-drop ordering
                // race with the host's I/O driver shutdown.)
                unsafe {
                    let _ = TerminateJobObject(job, 1);
                    let _ = CloseHandle(job);
                }
            }
        }
    }

    impl Drop for Group {
        fn drop(&mut self) {
            self.kill();
        }
    }

    pub(super) fn spawn(cmd: &mut Command, is_root: bool) -> io::Result<GroupedChild> {
        // Handle hygiene: a child must inherit only its own (piped) stdio, never
        // this process's std handles. Best-effort — a missing/redirected std
        // handle just means there's nothing to clear.
        clear_std_handle_inheritance();

        // CREATE_NEW_PROCESS_GROUP makes the child its own console group leader so
        // graceful_stop's CTRL_BREAK targets it (unchanged behavior, both root and
        // nested).
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP.0);

        let child = cmd.spawn()?;

        let group = if is_root {
            Group {
                job: assign_to_kill_on_close_job(&child),
            }
        } else {
            Group { job: None }
        };
        Ok(GroupedChild { child, group })
    }

    fn clear_std_handle_inheritance() {
        for std_handle in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            unsafe {
                if let Ok(h) = GetStdHandle(std_handle) {
                    if !h.is_invalid() {
                        // dwmask is a raw u32; dwflags is HANDLE_FLAGS. Clearing
                        // the INHERIT bit (mask = INHERIT, flags = 0).
                        let _ = SetHandleInformation(h, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0));
                    }
                }
            }
        }
    }

    /// Create a `KILL_ON_JOB_CLOSE` job and assign `child` to it. Returns the job
    /// handle (held for the tree's lifetime) or `None` on failure (best-effort:
    /// tree-reaping degrades to the direct child via `kill_on_drop`).
    fn assign_to_kill_on_close_job(child: &Child) -> Option<HANDLE> {
        // Every failure here degrades tree-reaping to just the direct child
        // (`kill_on_drop`), which would re-orphan grandchildren — so log loudly.
        let Some(raw) = child.raw_handle() else {
            tracing::warn!("kill-group: child has no raw handle; process-tree reaping disabled");
            return None;
        };
        unsafe {
            let job = match CreateJobObjectW(None, windows::core::PCWSTR::null()) {
                Ok(j) => j,
                Err(e) => {
                    tracing::warn!(error = %e, "kill-group: CreateJobObjectW failed; process-tree reaping disabled");
                    return None;
                }
            };
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if let Err(e) = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(info).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) {
                tracing::warn!(error = %e, "kill-group: SetInformationJobObject failed; process-tree reaping disabled");
                let _ = CloseHandle(job);
                return None;
            }
            if let Err(e) = AssignProcessToJobObject(job, HANDLE(raw)) {
                tracing::warn!(error = %e, "kill-group: AssignProcessToJobObject failed; process-tree reaping disabled");
                let _ = CloseHandle(job);
                return None;
            }
            Some(job)
        }
    }
}

#[cfg(unix)]
mod imp {
    use super::*;

    /// Holds the child's process-group id (root only). Killing it signals the
    /// whole group — the child and every descendant that stayed in its group
    /// (nested kill-group spawns deliberately do not create their own group).
    pub(super) struct Group {
        pgid: Option<libc::pid_t>,
    }

    impl Group {
        pub(super) fn is_root(&self) -> bool {
            self.pgid.is_some()
        }

        pub(super) fn kill(&mut self) {
            if let Some(pgid) = self.pgid.take() {
                // Negative pid → signal the whole process group.
                unsafe {
                    let _ = libc::kill(-pgid, libc::SIGKILL);
                }
            }
        }
    }

    impl Drop for Group {
        fn drop(&mut self) {
            self.kill();
        }
    }

    pub(super) fn spawn(cmd: &mut Command, is_root: bool) -> io::Result<GroupedChild> {
        // Unix already gives the child only its own stdio (dup2 + CLOEXEC), so no
        // handle hygiene is needed. The root becomes a process-group leader so the
        // whole tree can be killed with kill(-pgid); nested spawns inherit the
        // root's group (so they are reaped by it, not orphaned).
        if is_root {
            cmd.process_group(0);
        }
        let child = cmd.spawn()?;
        let group = if is_root {
            // process_group(0) makes the child its own group leader, so pgid == pid.
            Group {
                pgid: child.id().map(|id| id as libc::pid_t),
            }
        } else {
            Group { pgid: None }
        };
        Ok(GroupedChild { child, group })
    }
}
