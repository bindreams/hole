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

    // Bring an install base predating the restart-on-failure SCM config up to date
    // as part of the update itself. Best-effort: a failure here must not abort the
    // cutover (the swap + restart still proceed), so log and continue.
    if let Err(e) = crate::platform::os::ensure_failure_actions() {
        tracing::warn!(error = %e, "cutover: could not ensure SCM restart-on-failure config");
    }

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
    let result = run_cutover(&mut os);
    clear_marker_on_cutover_failure(&result, &hole_common::update_marker::service_log_dir());
    result
}

/// On a graceful cutover failure clear the marker so a retry is not blocked by
/// the single-occupancy claim. Load-bearing for the stop/swap sub-case (no new
/// bridge binds to sweep it); an idempotent second clear for the start-failure
/// sub-case (the SCM's restart-on-failure also sweeps post-bind). A crash is
/// covered by the GUI liveness net.
#[cfg(target_os = "windows")]
fn clear_marker_on_cutover_failure(result: &std::io::Result<()>, log_dir: &Path) {
    if result.is_err() {
        if let Err(e) = hole_common::update_marker::clear(log_dir) {
            tracing::warn!(error = %e, "cutover child: failed to clear marker on graceful failure");
        }
    }
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
///
/// Refuses outright against a live bridge instance (#840): a running bridge
/// already reconciles the target itself, and racing it from an unrelated CLI
/// invocation is exactly the two-writer hazard `target::apply`'s locking
/// exists to prevent. The in-app "Unblock Network" action is the live-bridge
/// equivalent, so refusal names it as the alternative. The exclusion is
/// structural, not a point-in-time probe: see [`unlock_with`].
pub fn unlock() -> std::io::Result<()> {
    let state_dir = service_state_dir();
    unlock_with(&state_dir, || {
        tun_engine::routing::failclosed::disengage_lockdown(&state_dir).map_err(std::io::Error::other)
    })
}

/// `unlock`'s ordering, with the disengage step injected so tests can drive
/// the cannot-disengage path without touching the host firewall. Liveness
/// check → target off → disengage → intent flip; the intent flips off ONLY
/// after the disengage confirms success, and the target is recorded off
/// before the release call so a reconciler reading it mid-unlock never sees
/// a stale `Connected`/prior target.
///
/// The liveness check is [`crate::liveness::BridgeLiveness::try_acquire`] on
/// the SAME lock a running bridge holds for its whole lifetime, held across
/// this whole sequence rather than released after the check: a point-in-time
/// probe (the old `is_running`) can go stale before the first mutation runs,
/// letting a bridge that starts mid-unlock have its live cover restored away
/// and its intent flipped off underneath it. Holding the lock instead means
/// a bridge trying to start during this sequence contends on the same lock
/// (single-instance is separately enforced by the IPC socket bind, so no
/// second real bridge is racing this token itself) rather than interleaving
/// with it.
fn unlock_with(state_dir: &Path, disengage: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> {
    let Some(_liveness) = crate::liveness::BridgeLiveness::try_acquire(state_dir, None)? else {
        return Err(std::io::Error::other(
            "a bridge instance is running; use the in-app \"Unblock Network\" action instead of `hole bridge unlock`",
        ));
    };
    crate::target::apply(state_dir, None, |_| crate::target::Target::Off)
        .map_err(|e| std::io::Error::other(format!("could not record target off: {e}")))?;
    disengage()?;
    // Same reason `handle_unblock` clears it: `resolve_startup_target` feeds
    // the candidate to `AlwaysConnect` over an `Off` target, so leaving it
    // would let the next boot reconnect to the server this escape just freed
    // the host from.
    crate::target::apply_startup_preference(state_dir, None, |pref| pref.candidate = None)
        .map_err(|e| std::io::Error::other(format!("could not clear the auto-connect candidate: {e}")))?;
    tun_engine::routing::failclosed::lockdown_state::set_enabled(state_dir, false, None)
}

/// The uninstaller's escape: clear EVERY fail-closed cover and record the
/// target off, with no running bridge.
///
/// Wider than [`unlock`], which disengages only the STANDING cover because an
/// out-of-process clear of the transient one would desync a live bridge's
/// posture. Uninstall cannot leave that to the in-process escapes: there is no
/// next bridge start to sweep a transient cover stranded by an earlier crash,
/// and on Windows the filters are `FWPM_FILTER_FLAG_PERSISTENT` — the Base
/// Filtering Engine re-adds them every boot, and the uninstaller is about to
/// delete the only binary that could remove them (bindreams/hole#1003).
///
/// The desync hazard is answered structurally, not by ordering: like [`unlock`]
/// this REFUSES against a live bridge instance, so there is never an
/// in-process posture to leave claiming a cover that no longer exists.
/// `bridge uninstall` tears the service down first, which is what frees the
/// lock for it.
///
/// Fatality is deliberately narrower than [`unlock`]'s, because the MSI runs
/// this `Return="check"`: only the target write and the release itself abort.
/// The trailing bookkeeping warns instead, since failing there would roll an
/// uninstall back over a host that is in fact already open — trading a
/// permanent block for a permanently unremovable product. Recording the target
/// off BEFORE the release is what makes that safe: whatever happens after, a
/// later start reconciles toward `Off` and sweeps.
pub fn release_covers() -> std::io::Result<()> {
    let state_dir = service_state_dir();
    release_covers_with(&state_dir, || {
        tun_engine::routing::failclosed::release_all(&state_dir).map_err(std::io::Error::other)
    })
}

/// `release_covers`' ordering, with the release injected so tests can drive the
/// cannot-release path without touching the host firewall.
fn release_covers_with(state_dir: &Path, release: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> {
    let Some(_liveness) = crate::liveness::BridgeLiveness::try_acquire(state_dir, None)? else {
        return Err(std::io::Error::other(
            "a bridge instance is running; stop the bridge before releasing its fail-closed covers",
        ));
    };
    crate::target::apply(state_dir, None, |_| crate::target::Target::Off)
        .map_err(|e| std::io::Error::other(format!("could not record target off: {e}")))?;
    release()?;

    // Best-effort from here — see the fatality note on `release_covers`.
    if let Err(e) = crate::target::apply_startup_preference(state_dir, None, |pref| pref.candidate = None) {
        tracing::warn!(error = %e, "covers released, but the auto-connect candidate could not be cleared");
    }
    if let Err(e) = tun_engine::routing::failclosed::lockdown_state::set_enabled(state_dir, false, None) {
        tracing::warn!(error = %e, "covers released, but the legacy lockdown intent could not be recorded off");
    }
    Ok(())
}

#[cfg(test)]
#[path = "cutover_tests.rs"]
mod cutover_tests;
