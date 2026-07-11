//! `POST /v1/update-apply` cutover orchestration helpers: the consent gate, the
//! single-occupancy guard, the macOS destination pre-flight, and the OS-specific
//! actor spawn. The handler in `ipc.rs` sequences them (409 guard → consent →
//! app_dest+volume pre-flight (macOS) → marker → stage_payload → re-verify →
//! extract → spawn) and owns the HTTP status mapping. The marker is claimed
//! before staging so only the marker-winner touches the shared private staging
//! dir; verify+extract then run against that private copy.

use std::path::Path;

use crate::cutover::extract::ExtractedImages;

#[derive(Debug, PartialEq, Eq)]
pub enum ConsentError {
    Required,
}

/// Lockdown-off updates require explicit consent (a brief leak is accepted only
/// with informed consent); lockdown-on does not (the standing cover holds the
/// gap). Fails closed: no consent under lockdown-off is refused.
pub fn consent_gate(lockdown_on: bool, consent: bool) -> Result<(), ConsentError> {
    if !lockdown_on && !consent {
        return Err(ConsentError::Required);
    }
    Ok(())
}

/// Single-occupancy: a present marker means a cutover is already in flight, so a
/// second apply is a 409.
pub fn cutover_in_progress(log_dir: &Path) -> bool {
    hole_common::update_marker::read(log_dir).is_some()
}

/// macOS pre-flight: validate the GUI-supplied `.app` swap target is a genuine
/// `com.hole.app` bundle AND its volume can atomically swap. Runs BEFORE the
/// marker so a bad target is a clean 400, never a claimed cutover. The validated
/// bundle path is returned for the actor. An absent `app_dest` on macOS is itself
/// a rejection (the GUI must supply its bundle hint).
#[cfg(target_os = "macos")]
pub fn preflight_app_dest(app_dest: Option<&Path>) -> std::io::Result<std::path::PathBuf> {
    use crate::platform::swap::{rename_swap_gate, volume_supports_rename_swap, RenameSwapSupport};

    let dest = app_dest.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "macOS update requires an app_dest swap target",
        )
    })?;
    crate::cutover::app_dest::validate_app_dest(dest)?;

    // Gate on the destination volume's atomic-swap capability. A probe ERROR is
    // not unsupport — proceed with a warning rather than brick a legit APFS
    // update (the swap itself fail-closes via rollback if truly unsupported).
    let probe = volume_supports_rename_swap(dest).unwrap_or(RenameSwapSupport::ProbeFailed);
    if matches!(probe, RenameSwapSupport::ProbeFailed) {
        tracing::warn!(
            ?dest,
            "RENAME_SWAP volume probe failed; proceeding (swap fail-closes on rollback)"
        );
    }
    rename_swap_gate(probe)?;
    Ok(dest.to_path_buf())
}

/// Kick off the cutover actor and return immediately, BEFORE any self-restart.
///
/// - Windows: spawn the DETACHED LocalSystem `hole bridge cutover` child (a
///   service cannot SCM-restart itself); it outlives this process and drives
///   stop → swap → start. Returns once the child is spawned. `app_dest`/`log_dir`
///   are unused (the SCM install dir is canonical; the detached child leaves the
///   marker for the next bridge's post-bind sweep).
/// - macOS: build the inline actor and run it on a DETACHED tokio task so the
///   200 flushes before the actor SIGTERMs this very process. The task is never
///   joined — the process is about to be killed and the new bridge takes over.
///   `app_dest` is the bundle path already validated by `preflight_app_dest`;
///   `log_dir` is where the actor clears the marker on a pre-SIGTERM failure.
pub fn spawn_actor(
    staged: ExtractedImages,
    target_version: &str,
    app_dest: Option<&Path>,
    log_dir: &Path,
) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        let _ = app_dest;
        // Spawn the detached child SUSPENDED, stamp the frozen child's identity
        // into the marker, then resume it — the marker names the driver before the
        // child can act. Any pre-resume failure kills the child (logged) and
        // returns Err so the ipc.rs caller clears the marker and 500s; the child
        // never ran.
        let mut child = windows::spawn_suspended_child(&staged, target_version)?;
        let pid = child.id();
        if let Err(e) = windows::record_spawned_driver(log_dir, pid, hole_common::process::process_start_time(pid))
            .and_then(|()| windows::resume_main_thread(pid))
        {
            if let Err(ke) = child.kill() {
                tracing::warn!(pid, error = %ke, "failed to kill the suspended cutover child after a pre-resume failure");
            }
            return Err(e);
        }
        // Dropping `child` closes our handle without killing the now-running process.
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let dest = app_dest.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "macOS cutover requires a validated app_dest",
            )
        })?;
        macos::spawn_inline_task(staged, target_version, dest, log_dir.to_path_buf())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = (staged, target_version, app_dest, log_dir);
        Err(std::io::Error::other("cutover unsupported on this platform"))
    }
}

/// Whether the detached child should request `CREATE_BREAKAWAY_FROM_JOB`. Only
/// when this process is in a job AND that job permits breakaway — requesting it
/// unconditionally fails the spawn (`ACCESS_DENIED`) when the job forbids it.
#[cfg(target_os = "windows")]
pub fn breakaway_decision(in_job: bool, job_permits_breakaway: bool) -> bool {
    in_job && job_permits_breakaway
}

#[cfg(target_os = "windows")]
mod windows {
    //! Suspended-child spawn (so the initiator can stamp the frozen child's
    //! identity into the marker before it can act), the conditional job-breakaway
    //! probe, and the ToolHelp thread-resume. Raw JobObject/ToolHelp FFI is
    //! sanctioned here per the #165 isolation contract.
    #![allow(clippy::disallowed_methods)]

    use std::os::windows::process::CommandExt;

    use windows::core::BOOL;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        IsProcessInJob, JobObjectExtendedLimitInformation, QueryInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW, CREATE_SUSPENDED, DETACHED_PROCESS,
    };

    use super::breakaway_decision;
    use crate::cutover::extract::ExtractedImages;

    /// Overwrite the marker's driver identity with the freshly-spawned child's
    /// PID + start time. A real Windows creation FILETIME is never 0; a stamped
    /// `0` is the poisoned sentinel the GUI reads as unassessed (a permanent mask
    /// on a dead driver), so treat `Some(0)` (and `None`) as a failure — the
    /// caller then kills the child and clears the marker rather than stamping a
    /// poisoned identity. Table-testable.
    pub(super) fn record_spawned_driver(
        log_dir: &std::path::Path,
        child_pid: u32,
        start: Option<u64>,
    ) -> std::io::Result<()> {
        match start {
            Some(s) if s != 0 => hole_common::update_marker::stamp_driver(log_dir, child_pid, s),
            _ => Err(std::io::Error::other(
                "could not record a valid cutover child start time",
            )),
        }
    }

    /// The suspended-spawn creation flags: DETACHED + NO_WINDOW + SUSPENDED, plus
    /// CREATE_BREAKAWAY_FROM_JOB only when this process's job permits it.
    fn suspended_creation_flags() -> u32 {
        let mut flags = DETACHED_PROCESS.0 | CREATE_NO_WINDOW.0 | CREATE_SUSPENDED.0;
        if breakaway_decision(process_in_job(), job_permits_breakaway()) {
            flags |= CREATE_BREAKAWAY_FROM_JOB.0;
        }
        flags
    }

    /// Apply the suspended creation flags to `cmd` and spawn it. The single main
    /// thread is left suspended; the caller stamps the marker, then resumes it via
    /// [`resume_main_thread`].
    fn spawn_suspended(mut cmd: std::process::Command) -> std::io::Result<std::process::Child> {
        cmd.creation_flags(suspended_creation_flags()).spawn()
    }

    /// Spawn the detached LocalSystem `hole bridge cutover` child SUSPENDED. It
    /// outlives this process and drives stop -> swap -> start once resumed.
    pub(super) fn spawn_suspended_child(
        staged: &ExtractedImages,
        target_version: &str,
    ) -> std::io::Result<std::process::Child> {
        let exe = std::env::current_exe()?;
        let mut cmd = std::process::Command::new(exe);
        cmd.args([
            "bridge",
            "cutover",
            "--payload",
            &staged.staging_dir.to_string_lossy(),
            "--target-version",
            target_version,
        ]);
        spawn_suspended(cmd)
    }

    /// Spawn an arbitrary command line SUSPENDED. The first whitespace-delimited
    /// token is the program; the remainder is appended verbatim (`raw_arg`, no
    /// re-quoting). A test seam so the suspend->resume ordering can be driven with
    /// an observable command; the real cutover payload goes through
    /// [`spawn_suspended_child`].
    #[cfg(test)]
    pub(super) fn spawn_suspended_command(cmdline: &str) -> std::io::Result<std::process::Child> {
        let (program, rest) = match cmdline.split_once(char::is_whitespace) {
            Some((p, r)) => (p, r.trim_start()),
            None => (cmdline, ""),
        };
        let mut cmd = std::process::Command::new(program);
        if !rest.is_empty() {
            cmd.raw_arg(rest);
        }
        spawn_suspended(cmd)
    }

    /// Resume the (single) suspended main thread of `pid`. A `CREATE_SUSPENDED`
    /// process has exactly one thread, itself suspended; find it by owner PID via
    /// a ToolHelp thread snapshot, open it with `THREAD_SUSPEND_RESUME`, and
    /// `ResumeThread` (which returns `u32::MAX` on failure). `OpenThread` errors
    /// are surfaced too, so a resume that could not fire returns `Err` (the caller
    /// kills the still-suspended child rather than leaking it).
    pub(super) fn resume_main_thread(pid: u32) -> std::io::Result<()> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

        // SAFETY: the snapshot handle is checked and closed below.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }
            .map_err(|e| std::io::Error::other(format!("thread snapshot: {e}")))?;
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut outcome: std::io::Result<()> = Err(std::io::Error::other("cutover child's main thread not found"));
        // SAFETY: `snap` is a live snapshot; `entry.dwSize` is set per contract.
        if unsafe { Thread32First(snap, &mut entry) }.is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    // SAFETY: a valid thread id from the snapshot.
                    match unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) } {
                        Ok(h) => {
                            // SAFETY: `h` is a live thread handle; closed right after.
                            let prev = unsafe { ResumeThread(h) };
                            unsafe {
                                let _ = CloseHandle(h);
                            }
                            outcome = if prev == u32::MAX {
                                Err(std::io::Error::last_os_error())
                            } else {
                                Ok(())
                            };
                        }
                        Err(e) => outcome = Err(std::io::Error::other(format!("OpenThread: {e}"))),
                    }
                    break;
                }
                // SAFETY: `snap`/`entry` stay valid across the enumeration.
                if unsafe { Thread32Next(snap, &mut entry) }.is_err() {
                    break;
                }
            }
        }
        // SAFETY: `snap` is a live handle opened above.
        unsafe {
            let _ = CloseHandle(snap);
        }
        outcome
    }

    fn current_process() -> HANDLE {
        // SAFETY: returns the current-process pseudo-handle; nothing to free.
        unsafe { GetCurrentProcess() }
    }

    /// `IsProcessInJob` for the current process (jobhandle=None tests membership
    /// in the process's own job). A failed query => not in a job (no breakaway).
    fn process_in_job() -> bool {
        let mut in_job = BOOL(0);
        // SAFETY: a valid pseudo-handle + a live BOOL out-param.
        let ok = unsafe { IsProcessInJob(current_process(), None, &mut in_job) };
        ok.is_ok() && in_job.as_bool()
    }

    /// Whether the current process's job sets `JOB_OBJECT_LIMIT_BREAKAWAY_OK`. A
    /// failed query => assume it does not (no breakaway).
    fn job_permits_breakaway() -> bool {
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let len = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
        // SAFETY: hjob=None queries the current process's job; the buffer is a
        // live, correctly-sized struct; lpreturnlength=None is permitted.
        let ok = unsafe {
            QueryInformationJobObject(
                None,
                JobObjectExtendedLimitInformation,
                &mut info as *mut _ as *mut core::ffi::c_void,
                len,
                None,
            )
        };
        ok.is_ok()
            && info
                .BasicLimitInformation
                .LimitFlags
                .contains(JOB_OBJECT_LIMIT_BREAKAWAY_OK)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::path::{Path, PathBuf};

    use crate::cutover::extract::ExtractedImages;
    use crate::cutover::os::macos::MacosCutoverOs;
    use crate::cutover::os::run_cutover;
    use crate::platform::os::HELPER_PATH;
    use crate::platform::swap::plan_swap;

    /// `app_dest` is the bundle the handler already validated as a genuine
    /// `com.hole.app` (`preflight_app_dest`) — never trusted raw here. `log_dir`
    /// is the handler's marker dir, threaded in so the failure path clears the
    /// marker the handler wrote rather than re-resolving `service_log_dir()`.
    pub fn spawn_inline_task(
        staged: ExtractedImages,
        _target_version: &str,
        app_dest: &Path,
        log_dir: PathBuf,
    ) -> std::io::Result<()> {
        let plan = plan_swap(&staged.app, app_dest, &staged.helper, std::path::Path::new(HELPER_PATH));
        let mut os = MacosCutoverOs { plan };
        // The handler already wrote the cutover marker before the 200 — that
        // marker, not flush ordering, is the GUI's source of truth: it masks the
        // restart gap (`HoleAppState::update_in_progress`, state.rs) and the
        // version flip drives self-heal (`note_mismatch`). The detached
        // `tokio::spawn` only lets the 200 flush for a clean UX; correctness does
        // NOT depend on the actor running after the response.
        // Never joined — on success the actor SIGTERMs this process, so control
        // never returns here. The ONLY way past `run_cutover` is a swap failure
        // BEFORE the SIGTERM; clear the marker so the GUI stops masking
        // Disconnected (no new bridge will start to clear it).
        tokio::spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || run_cutover(&mut os)).await;
            let result = match outcome {
                Ok(r) => r,
                Err(e) => Err(std::io::Error::other(format!("cutover actor panicked: {e}"))),
            };
            clear_marker_on_actor_failure(result, &log_dir);
        });
        Ok(())
    }

    /// On a pre-SIGTERM cutover failure, clear the marker the handler wrote into
    /// `log_dir` so the GUI stops masking Disconnected (no new bridge will start
    /// to clear it). On success this is unreachable in practice (the actor
    /// SIGTERMs this process), so it is a no-op. Extracted so the failure path is
    /// table-testable without driving the real swap/launchctl.
    pub(super) fn clear_marker_on_actor_failure(result: std::io::Result<()>, log_dir: &Path) {
        let Err(e) = result else {
            return;
        };
        tracing::error!(error = %e, "macOS cutover failed before restart; clearing marker");
        if let Err(ce) = hole_common::update_marker::clear(log_dir) {
            tracing::warn!(error = %ce, "failed to clear cutover marker on error path");
        }
    }
}

#[cfg(test)]
#[path = "apply_tests.rs"]
mod apply_tests;
