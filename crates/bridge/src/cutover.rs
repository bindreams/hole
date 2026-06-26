//! Service-manager update cutover. The privileged bridge swaps its own running
//! binary by rename and restarts the bridge service; the standing lockdown cover
//! holds the gap and every GUI self-heals onto the new image. The OS effects seam
//! lives in `os`; the apply handler logic in `apply`; binary extraction in
//! `extract`; the macOS destination anchor in `app_dest`. The no-transient-cover
//! property is structural — the `os::CutoverOs` trait exposes no cover method.

pub mod app_dest;
pub mod apply;
pub mod extract;
pub mod os;

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
/// the staged binaries into the install dir and SCM-restarts the service. The
/// marker is left for the new bridge's post-bind sweep to clear (it is the
/// authoritative, always-runs clear once any new bridge binds).
///
/// `payload` is the staging dir holding the extracted binaries; `target_version`
/// names the `.old-<ver>` rename-away path.
#[cfg(target_os = "windows")]
pub fn run_detached(payload: &Path, target_version: &str) -> std::io::Result<()> {
    use crate::cutover::os::run_cutover;
    use crate::cutover::os::windows::WindowsCutoverOs;

    let install_dir = std::env::current_exe()?
        .parent()
        .ok_or_else(|| std::io::Error::other("current_exe has no parent dir"))?
        .to_path_buf();
    let names = xtask_lib::bindir::bindir_dest_names(xtask_lib::bindir::Os::Windows);
    let images = plan_windows_images(&install_dir, payload, &names)?;
    let mut os = WindowsCutoverOs {
        images,
        target_version: target_version.to_string(),
    };
    run_cutover(&mut os)
}

/// Build the rename-swap plan for every bundled binary: each `name` maps from
/// its staged copy under `payload` to its canonical path in `install_dir`.
/// `names` is the single source of truth (`bindir_dest_names`), so a release
/// that updates the plugin/driver swaps them too — not just `hole.exe`. Loaded
/// DLLs (wintun.dll) and the running plugin exe rename-swap fine via the same
/// FILE_SHARE_DELETE POSIX-rename path as `hole.exe`; no special handling.
#[cfg(target_os = "windows")]
fn plan_windows_images(
    install_dir: &Path,
    payload: &Path,
    names: &[String],
) -> std::io::Result<Vec<crate::cutover::os::windows::ImageMove>> {
    use crate::cutover::os::windows::ImageMove;

    let mut images = Vec::with_capacity(names.len());
    for name in names {
        images.push(ImageMove {
            installed: install_dir.join(name),
            staged: extract::find_staged(payload, name)?,
        });
    }
    Ok(images)
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
/// running bridge required. The escape hatch must actually disengage or FAIL
/// LOUD: it disengages FIRST and only flips the intent off after a confirmed
/// success. A swallowed failure (e.g. run unprivileged) would leave the cover
/// engaged — egress still blocked — while the intent reads "off", misleading the
/// user.
pub fn unlock() -> std::io::Result<()> {
    let state_dir = service_state_dir();
    unlock_with(&state_dir, || {
        tun_engine::routing::failclosed::disengage_lockdown(&state_dir).map_err(std::io::Error::other)
    })
}

/// `unlock`'s ordering, with the disengage step injected so tests can drive the
/// cannot-disengage path without touching the host firewall. Disengage → flip;
/// the intent flips off ONLY after the disengage confirms success.
fn unlock_with(state_dir: &Path, disengage: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> {
    disengage()?;
    tun_engine::routing::failclosed::lockdown_state::set_enabled(state_dir, false, None)
}

#[cfg(test)]
#[path = "cutover_tests.rs"]
mod cutover_tests;
