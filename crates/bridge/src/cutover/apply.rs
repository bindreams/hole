//! `POST /v1/update-apply` cutover orchestration helpers: the consent gate, the
//! single-occupancy guard, the macOS destination pre-flight, and the OS-specific
//! actor spawn. The handler in `ipc.rs` sequences them (consent → 409 guard →
//! app_dest+volume pre-flight (macOS) → re-verify → marker → extract → spawn) and
//! owns the HTTP status mapping. Every pre-flight check sits before the marker.

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
/// marker so a bad target is a clean 422, never a claimed cutover. The validated
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
///   stop → swap → start. Returns once the child is spawned. `app_dest` is unused
///   (the SCM install dir is canonical).
/// - macOS: build the inline actor and run it on a DETACHED tokio task so the
///   200 flushes before the actor SIGTERMs this very process. The task is never
///   joined — the process is about to be killed and the new bridge takes over.
///   `app_dest` is the bundle path already validated by `preflight_app_dest`.
pub fn spawn_actor(staged: ExtractedImages, target_version: &str, app_dest: Option<&Path>) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        let _ = app_dest;
        windows::spawn_detached_child(&staged, target_version)
    }
    #[cfg(target_os = "macos")]
    {
        let dest = app_dest.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "macOS cutover requires a validated app_dest",
            )
        })?;
        macos::spawn_inline_task(staged, target_version, dest)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = (staged, target_version, app_dest);
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
    //! Detached-child spawn with the conditional job-breakaway probe. Raw
    //! JobObject FFI is sanctioned here per the #165 isolation contract.
    #![allow(clippy::disallowed_methods)]

    use std::os::windows::process::CommandExt;

    use windows::core::BOOL;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        IsProcessInJob, JobObjectExtendedLimitInformation, QueryInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW, DETACHED_PROCESS,
    };

    use super::breakaway_decision;
    use crate::cutover::extract::ExtractedImages;

    pub fn spawn_detached_child(staged: &ExtractedImages, target_version: &str) -> std::io::Result<()> {
        let exe = std::env::current_exe()?;
        let mut flags = DETACHED_PROCESS.0 | CREATE_NO_WINDOW.0;
        if breakaway_decision(process_in_job(), job_permits_breakaway()) {
            flags |= CREATE_BREAKAWAY_FROM_JOB.0;
        }
        std::process::Command::new(exe)
            .args([
                "bridge",
                "cutover",
                "--payload",
                &staged.staging_dir.to_string_lossy(),
                "--target-version",
                target_version,
            ])
            .creation_flags(flags)
            .spawn()?;
        Ok(())
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
    use std::path::Path;

    use crate::cutover::extract::ExtractedImages;
    use crate::cutover::os::macos::MacosCutoverOs;
    use crate::cutover::os::run_cutover;
    use crate::platform::os::HELPER_PATH;
    use crate::platform::swap::plan_swap;

    /// `app_dest` is the bundle the handler already validated as a genuine
    /// `com.hole.app` (`preflight_app_dest`) — never trusted raw here.
    pub fn spawn_inline_task(staged: ExtractedImages, _target_version: &str, app_dest: &Path) -> std::io::Result<()> {
        let plan = plan_swap(&staged.app, app_dest, &staged.helper, std::path::Path::new(HELPER_PATH));
        let mut os = MacosCutoverOs { plan };
        // Detached: the 200 must flush before the actor SIGTERMs this process.
        // Never joined — on success the actor SIGTERMs this process, so control
        // never returns here. The ONLY way past `run_cutover` is a swap failure
        // BEFORE the SIGTERM; clear the marker so the GUI stops masking
        // Disconnected (no new bridge will start to clear it).
        tokio::spawn(async move {
            let outcome = tokio::task::spawn_blocking(move || run_cutover(&mut os)).await;
            let failed = match outcome {
                Ok(Ok(())) => return, // unreachable in practice (SIGTERM'd above)
                Ok(Err(e)) => format!("{e}"),
                Err(e) => format!("cutover actor panicked: {e}"),
            };
            tracing::error!(error = %failed, "macOS cutover failed before restart; clearing marker");
            let _ = hole_common::update_marker::clear(&hole_common::update_marker::service_log_dir());
        });
        Ok(())
    }
}

#[cfg(test)]
#[path = "apply_tests.rs"]
mod apply_tests;
