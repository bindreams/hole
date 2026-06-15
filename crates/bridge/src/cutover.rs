//! Service-manager update cutover. The privileged bridge swaps its own running
//! binary by rename and restarts the bridge service; the standing lockdown cover
//! holds the gap and every GUI self-heals onto the new image. Pure planners live
//! in `plan`; the OS effects seam in `os`; the apply handler logic in `apply`;
//! binary extraction in `extract`.

pub mod apply;
pub mod extract;
pub mod os;
pub mod plan;

#[cfg(target_os = "windows")]
pub mod scm_wait;

use std::path::{Path, PathBuf};

/// The privileged service's state dir, where the lockdown intent + cover state
/// files live. `unlock` needs it without a running bridge, so it resolves the
/// same per-platform location `install()` provisions.
pub fn service_state_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
            .join("hole")
            .join("state")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/var/db/hole/state")
    }
}

/// Run the cutover from the detached `hole bridge cutover` child (Windows: the
/// bridge cannot SCM-restart itself, so it spawns this LocalSystem child). Swaps
/// the staged binaries into the install dir and SCM-restarts the service, then
/// clears the marker so the new bridge does not re-enter the no-flash window.
///
/// `payload` is the staging dir holding the extracted binaries; `target_version`
/// names the `.old-<ver>` rename-away path.
#[cfg(target_os = "windows")]
pub fn run_detached(payload: &Path, target_version: &str) -> std::io::Result<()> {
    use crate::cutover::os::run_cutover;
    use crate::cutover::os::windows::{ImageMove, WindowsCutoverOs};

    let install_dir = std::env::current_exe()?
        .parent()
        .ok_or_else(|| std::io::Error::other("current_exe has no parent dir"))?
        .to_path_buf();
    let staged_exe = extract::find_staged_exe(payload)?;
    let exe_name = staged_exe
        .file_name()
        .ok_or_else(|| std::io::Error::other("staged exe has no filename"))?;
    let images = vec![ImageMove {
        installed: install_dir.join(exe_name),
        staged: staged_exe.clone(),
    }];
    let mut os = WindowsCutoverOs {
        images,
        target_version: target_version.to_string(),
    };
    run_cutover(&mut os)?;
    // The new service is up; clear the marker so the GUI resumes truth-telling.
    hole_common::update_marker::clear(&hole_common::update_marker::service_log_dir())
}

#[cfg(not(target_os = "windows"))]
pub fn run_detached(_payload: &Path, _target_version: &str) -> std::io::Result<()> {
    // macOS runs the cutover inline (no detached child); the subcommand exists
    // only for the Windows path.
    Err(std::io::Error::other(
        "`bridge cutover` is a Windows-only detached entrypoint",
    ))
}

/// Disengage a standing lockdown cover and clear the persisted intent, with no
/// running bridge required. Last-writer-wins recovery hatch: sweep the cover,
/// then set the intent off so the next start does not re-engage it.
pub fn unlock() -> std::io::Result<()> {
    let state_dir = service_state_dir();
    tun_engine::routing::failclosed::recover_lockdown(tun_engine::routing::CoverRecovery::Sweep, &state_dir);
    tun_engine::routing::failclosed::lockdown_state::set_enabled(&state_dir, false)
}

#[cfg(test)]
#[path = "cutover_tests.rs"]
mod cutover_tests;
