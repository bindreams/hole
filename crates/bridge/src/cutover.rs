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

#[cfg(any(target_os = "windows", test))]
mod windows_profiles;

use std::path::{Path, PathBuf};

use tun_engine::routing::failclosed::Clearance;

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
///
/// **`Ok` means "nothing failed", not "the host is clear."** The returned
/// [`Clearance`] carries the difference and the caller must not collapse it.
/// A `FWPM_FILTER_FLAG_BOOTTIME` key answers `FWP_E_FILTER_NOT_FOUND` on any
/// boot where its runtime object is not live — indistinguishable from never
/// having been installed. On the boot this function matters most (lockdown
/// armed in an earlier session, the user uninstalls without ever connecting)
/// every such key answers empty, and a bare `Ok` told the MSI it was safe to
/// delete the only binary that could act on it.
///
/// That does NOT make it an error. See [`Clearance`] for the bound on the
/// harm: a stranded boot-time record blocks egress across the boot→BFE window
/// only (a bounded window whose length is unmeasured), so failing the
/// uninstall over it would trade a bounded early-boot block for a permanently
/// unremovable product — the exact trade the paragraph above refuses for the
/// bookkeeping. The gate stops claiming proof it does not
/// have; it does not withhold the uninstall. `hole bridge release-covers`
/// turns an unproven clearance into something an operator can act on.
pub fn release_covers() -> std::io::Result<Clearance> {
    let state_dir = service_state_dir();
    let others = peer_state_dirs();
    release_covers_with(
        &state_dir,
        &others,
        // The free function, not `Routing::release_all_covers`: there is no
        // bridge here, so no `Routing` handle to reach the trait method
        // through. `reconciler_tests.rs`'s sanctioned-caller guard matches both
        // forms so this site is visible to it.
        || tun_engine::routing::failclosed::release_all(&state_dir).map_err(std::io::Error::other),
    )
}

/// The operator's last word on a cover release, or `None` when the sweep
/// proved every key it touched empty.
///
/// Pure, so the wording is testable, and living here rather than in the CLI so
/// `bridge release-covers` and `bridge uninstall` cannot drift into telling
/// two different stories about the same clearance.
///
/// This runs at the one moment `hole.exe` still exists on an uninstalling
/// host: the exit code is 0 either way (see [`release_covers`] for why an
/// unproven key must not fail an uninstall), so this message IS the
/// qualification. Without it the `Ok` is silent again and the installer reads
/// it as proof (bindreams/hole#1003).
///
/// It deliberately does NOT assert that a cover is present. An unproven key is
/// equally consistent with never having been installed — which is what it will
/// be on almost every uninstall — and crying leftover every time is how the
/// one host where it is real gets ignored.
///
/// The remedy it names has to be one that exists. `netsh wfp` is a
/// **diagnostics-only** context — its verbs are `capture`, `dump`, `help`,
/// `set` and `show`, with no `delete`
/// (<https://learn.microsoft.com/windows-server/administration/windows-commands/netsh-wfp>)
/// — so the message says so outright rather than sending the reader to a
/// command that cannot help in the one state where they have nothing else.
/// The diagnostic it does name is `show boottimepolicy`, the subcommand for
/// exactly this key class; `show filters` lists what is active *now*, which by
/// definition excludes a boot-time filter once BFE has started, i.e. at every
/// moment this message is read.
///
/// Removing a WFP filter takes an FWPM call, and `RemoveFiles` just deleted
/// the only caller on the host. So the only honest remedy is to put one back.
pub fn release_clearance_report(clearance: &Clearance) -> Option<String> {
    if clearance.is_proven() {
        return None;
    }
    Some(format!(
        "covers released, but {} boot-time filter key(s) could not be proven empty: {}. \
         A boot-time filter is live only between kernel start and Base Filtering Engine start, \
         so a delete-by-key finds nothing on any later boot whether or not a policy record \
         survives behind it. To check after this uninstall, run `netsh wfp show boottimepolicy` \
         elevated and look for these keys; if egress is blocked early in boot, that is where it \
         would show. `netsh wfp` cannot remove one — it has no delete verb, only capture/dump/\
         set/show — and removing a WFP filter takes an FWPM call, which no binary left on this \
         host can make. Reinstalling Hole and running `hole bridge release-covers` elevated puts \
         back the only tool that addresses these keys.",
        clearance.unproven_keys().len(),
        clearance.unproven_keys().join(", "),
    ))
}

/// Every state dir OTHER than the service's that a bridge on this host could be
/// holding its liveness lock in.
///
/// The lock is per-state-dir, but the covers `release_all` sweeps are not: on
/// Windows they are keyed on compile-time GUIDs and are machine-wide, so a
/// release that only consulted the service's dir would clear the filters of a
/// bridge started with a different `--state-dir` while that bridge's posture
/// still claims them — and its next covered start would skip re-engagement and
/// run uncovered. `cli.rs` defaults foreground and elevated non-`--service`
/// runs to a per-user dir, which is that bridge in practice.
///
/// Disclosed residual: a bridge given an explicit `--state-dir` outside this
/// set is still undetectable here. `bridge release-covers` is hidden and
/// uninstall-only for that reason.
fn peer_state_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![hole_common::paths::default_state_dir()];
    dirs.extend(other_account_state_dirs());
    dirs
}

/// The per-user state dirs belonging to accounts other than this process's
/// own, which `default_state_dir` cannot reach.
///
/// Both platforms have the indirection; they just have different shapes of it,
/// and NEITHER may answer with a silent empty set on a failure — an empty peer
/// list is indistinguishable from "no other bridges", which is exactly the
/// unconditional pass this probe exists to prevent. So a failure to enumerate
/// warns, at the level an operator reading an uninstall's output will see.
///
/// - **macOS**: one indirection, `sudo`. The effective user is root while the
///   bridge's own state dir is the invoking user's, so the real user behind
///   the elevation is resolved and mapped.
/// - **Windows**: elevation does NOT switch profiles, so an elevated
///   non-`--service` bridge uses the interactive user's own `%LOCALAPPDATA%`
///   — while the MSI's custom actions run as SYSTEM, which has a profile of
///   its own. There is no "real user behind the elevation" to resolve; the
///   answer is every profile on the host (see the `windows_profiles`
///   submodule).
fn other_account_state_dirs() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        match crate::group::resolve_real_user() {
            Ok(u) => vec![hole_common::paths::user_state_dir(&u.home)],
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not resolve the real user behind this elevation; a bridge running under \
                     that account would not be seen by the liveness probe"
                );
                Vec::new()
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        match windows_profiles::profile_dirs() {
            Ok(profiles) => profiles
                .iter()
                .map(|p| hole_common::paths::windows_profile_state_dir(p))
                .collect(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not enumerate this host's user profiles; a bridge running under another \
                     account would not be seen by the liveness probe"
                );
                Vec::new()
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

/// `release_covers`' ordering, with the release injected so tests can drive the
/// cannot-release path without touching the host firewall.
///
/// `peers` are the other state dirs a bridge could be alive in; a lock held in
/// any of them refuses the release just as the service's own does. Every peer
/// is locked, including one whose dir is not there yet: the exclusion IS this
/// function, and a peer left unlocked because it looked absent is a peer
/// nothing excludes. `release_all` sweeps Windows' covers machine-wide, so a
/// bridge starting under that account mid-release would engage a cover, record
/// the posture, lose the filters to this sweep, and skip re-engagement on its
/// next covered start — running uncovered.
///
/// `try_acquire` creates what it locks, so that costs an empty state dir
/// holding a lock file on every account that never ran a bridge. **That litter
/// stays.** Removing it would have to happen after this call releases the peer
/// locks, and every bridge takes its own with the BLOCKING
/// `BridgeLiveness::acquire` — so the bridge the exclusion exists to keep out
/// is *woken by that release*, engages a standing cover, records it, and would
/// have the record deleted from under it. A persistent WFP cover with no record
/// is the end state this whole path exists to prevent, and it has no in-band
/// recovery; an empty directory has no consequence at all. The choice is where
/// to pay, never whether to lock.
///
/// The same answer covers the service's own state dir, which this does NOT
/// clean up either. Its records are not this call's: `bridge-routes.json` and
/// `bridge-dns{,.superseded}.json` are what `scripts/network-reset.py` reads to
/// undo a leaked bypass route or a rewritten adapter's DNS, and
/// `bridge-plugins.json` may be deleted only by something that has accounted
/// for every plugin in it. An uninstall is the moment those become the ONLY
/// escape. Nor is the directory itself this call's: `install()` pre-creates it
/// on both platforms, so the only host where `try_acquire` provisions it is one
/// that never installed — and what stays there is an empty `hole/state`, the
/// same litter the peers keep.
fn release_covers_with(
    state_dir: &Path,
    peers: &[PathBuf],
    release: impl FnOnce() -> std::io::Result<Clearance>,
) -> std::io::Result<Clearance> {
    let Some(liveness) = crate::liveness::BridgeLiveness::try_acquire(state_dir, None)? else {
        return Err(std::io::Error::other(
            "a bridge instance is running; stop the bridge before releasing its fail-closed covers",
        ));
    };
    let mut held = vec![liveness];
    let mut probed: Vec<&Path> = vec![state_dir];
    for peer in peers {
        // Skip a path already probed. The lock contends per open handle, not
        // per owning process (`tun_engine::exclusive`'s module doc), so
        // probing one twice would answer "a bridge is running" against this
        // call's own guard — and duplicates are ordinary, not exotic: an
        // un-elevated run resolves `default_state_dir` and the real user's dir
        // to the same path.
        if probed.contains(&peer.as_path()) {
            continue;
        }
        probed.push(peer.as_path());
        match crate::liveness::BridgeLiveness::try_acquire(peer, None) {
            Ok(Some(guard)) => held.push(guard),
            Ok(None) => {
                return Err(std::io::Error::other(
                    "a bridge instance is running; stop the bridge before releasing its fail-closed covers",
                ))
            }
            // Not evidence of a bridge — an unreadable peer dir (another
            // account's home) says nothing either way, and refusing on it would
            // make the uninstall unrunnable on a multi-user host.
            Err(e) => tracing::warn!(error = %e, "could not probe a peer state dir for a live bridge"),
        }
    }

    crate::target::apply(state_dir, None, |_| crate::target::Target::Off)
        .map_err(|e| std::io::Error::other(format!("could not record target off: {e}")))?;
    let clearance = release()?;

    // Best-effort from here — see the fatality note on `release_covers`.
    if let Err(e) = crate::target::apply_startup_preference(state_dir, None, |pref| pref.candidate = None) {
        tracing::warn!(error = %e, "covers released, but the auto-connect candidate could not be cleared");
    }
    if let Err(e) = tun_engine::routing::failclosed::lockdown_state::set_enabled(state_dir, false, None) {
        tracing::warn!(error = %e, "covers released, but the legacy lockdown intent could not be recorded off");
    }

    drop(held);
    Ok(clearance)
}

#[cfg(test)]
#[path = "cutover_tests.rs"]
mod cutover_tests;
