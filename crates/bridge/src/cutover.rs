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

#[cfg(any(target_os = "windows", test))]
mod windows_profiles;

use std::path::{Path, PathBuf};

use tun_engine::routing::failclosed::{Clearance, CoverLock, UnprovenKey};

/// The privileged service's state dir (Windows: `C:\ProgramData\hole\state`),
/// where the crash-recovery state and the lockdown intent and cover state live.
/// `unlock` needs it without a running bridge, so it resolves the same
/// per-platform location `install()` provisions.
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
/// authoritative, always-runs clear once any new bridge binds), except where no
/// bridge will bind: a failure, or a service an administrator disabled, which
/// is left stopped and reported as success.
///
/// `payload` is the staging dir holding the extracted binaries; `target_version`
/// names the `.old-<ver>` rename-away path.
///
/// The child carries the service's SID, so a retirement or install that holds
/// the start-type lock waits for the child to exit (it scans for the service's
/// processes). The child therefore never waits for the lock: it tries it once,
/// and if a change holds it the update is abandoned. A child that took it first
/// holds it for the whole cutover, and the other change waits for the child. No
/// other process that carries the service's SID takes the lock: the service
/// itself and the plugins it starts never do.
///
/// The update marker is settled by how the whole run ended (see
/// [`run_while_holding`]).
#[cfg(target_os = "windows")]
pub fn run_detached(payload: &Path, target_version: &str) -> std::io::Result<()> {
    run_while_holding(
        crate::platform::os::try_hold_start_type,
        &hole_common::update_marker::service_log_dir(),
        || run_held(payload, target_version),
    )
    .map(|_| ())
}

/// Runs `run` while holding the start-type lock `try_hold` takes, and settles
/// the update marker in `log_dir` by how the whole run ended: it stays only for
/// a cutover that started a new bridge to sweep it, and any other ending
/// (a failed `try_hold`, a lock another change holds, an error out of `run`, a
/// service left disabled) clears it, since the old bridge may keep serving and
/// no new one would bind. A lock another change holds is not waited for: `run`
/// does not run and this fails with `WouldBlock`. The lock belongs to this
/// thread, so every step of `run` takes it again on this thread without waiting.
#[cfg(target_os = "windows")]
fn run_while_holding<H>(
    try_hold: impl FnOnce() -> std::io::Result<Option<H>>,
    log_dir: &Path,
    run: impl FnOnce() -> std::io::Result<crate::cutover::os::CutoverOutcome>,
) -> std::io::Result<crate::cutover::os::CutoverOutcome> {
    let _held = match try_hold() {
        Ok(Some(held)) => held,
        Ok(None) => {
            clear_marker(log_dir);
            tracing::warn!(
                "cutover: an uninstall, install, repair or enable holds the service's start type, so this update is abandoned"
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "a change to the service holds its start type, so the update was abandoned",
            ));
        }
        Err(e) => {
            clear_marker(log_dir);
            return Err(e);
        }
    };
    let result = run();
    settle_marker(&result, log_dir);
    result
}

#[cfg(target_os = "windows")]
fn run_held(payload: &Path, target_version: &str) -> std::io::Result<crate::cutover::os::CutoverOutcome> {
    use crate::cutover::os::CutoverOutcome;

    // Bring an install base predating the restart-on-failure SCM config up to date
    // as part of the update itself. Best-effort: a failure here must not abort the
    // cutover (the swap + restart still proceed), so log and continue.
    if let Err(e) = crate::platform::os::ensure_failure_actions() {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "cutover: could not ensure SCM restart-on-failure config"
        );
    }

    let install_dir = std::env::current_exe()?
        .parent()
        .ok_or_else(|| std::io::Error::other("current_exe has no parent dir"))?
        .to_path_buf();
    let outcome = run_in(&install_dir, payload, target_version)?;
    if outcome == CutoverOutcome::LeftDisabled {
        tracing::info!(
            "cutover: the new files are installed, but the Hole service is disabled on this computer, so it was not started; enable it to run the new version"
        );
    }
    Ok(outcome)
}

/// Plans the swap of every bundled binary from `payload` into `install_dir`,
/// then runs it.
#[cfg(target_os = "windows")]
fn run_in(
    install_dir: &Path,
    payload: &Path,
    target_version: &str,
) -> std::io::Result<crate::cutover::os::CutoverOutcome> {
    use crate::cutover::os::run_cutover;
    use crate::cutover::os::windows::WindowsCutoverOs;

    let names = xtask_lib::bindir::bindir_dest_names(xtask_lib::bindir::Os::Windows);
    let images = plan_windows_images(install_dir, payload, &names)?;
    let mut os = WindowsCutoverOs {
        images,
        target_version: target_version.to_string(),
    };
    run_cutover(&mut os)
}

/// Clear the marker unless a new bridge will bind and sweep it. A graceful
/// failure clears it so a retry is not blocked by the single-occupancy claim
/// (load-bearing for the stop/swap sub-case; an idempotent second clear for the
/// start-failure sub-case, which the SCM's restart-on-failure also sweeps
/// post-bind). A service left disabled starts no bridge, so its outcome clears
/// it too. A crash is covered by the GUI liveness net.
#[cfg(target_os = "windows")]
fn settle_marker(result: &std::io::Result<crate::cutover::os::CutoverOutcome>, log_dir: &Path) {
    let leaves_marker = match result {
        Ok(outcome) => outcome.leaves_marker_for_new_bridge(),
        Err(_) => false,
    };
    if leaves_marker {
        return;
    }
    clear_marker(log_dir);
}

/// Clear the marker no new bridge will sweep; a failure is logged, not fatal.
#[cfg(target_os = "windows")]
fn clear_marker(log_dir: &Path) {
    if let Err(e) = hole_common::update_marker::clear(log_dir) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "cutover child: failed to clear the marker no new bridge will sweep"
        );
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
/// running bridge required.
///
/// The escape hatch must disengage or FAIL LOUD. A failed disengage returns the
/// error and leaves the target off, the cover engaged and the intent on; a
/// swallowed failure (e.g. run unprivileged) would instead leave the cover
/// engaged, egress still blocked, while the intent reads "off".
///
/// Refuses while a bridge is running on the service state dir
/// ([`service_state_dir`]): a running bridge reconciles the target itself, and the
/// state files' own locks are in-process only, so racing it from a CLI invocation
/// would be a two-writer hazard. The refusal names the in-app "Unblock Network"
/// action, the live-bridge equivalent. A foreground `hole bridge run` on another
/// state dir (its default is the per-user one) is not seen:
/// bindreams/hole#1214.
///
/// **`Ok` is qualified, and the caller must surface it.** The returned
/// [`Clearance`] is what the disengage could not prove (on Windows, the two
/// boot-time twins on any boot where no bridge engaged). `hole bridge unlock`
/// prints it with [`release_clearance_report`].
pub fn unlock() -> std::io::Result<Clearance> {
    let state_dir = service_state_dir();
    unlock_with(&state_dir, |lock| {
        tun_engine::routing::failclosed::disengage_lockdown(lock).map_err(std::io::Error::other)
    })
}

/// `unlock`'s ordering, with the disengage step injected so tests can drive
/// the cannot-disengage path without touching the host firewall.
///
/// Liveness check, target off, disengage, clear the auto-connect candidate,
/// intent off; the first failure returns. The target is recorded off before the
/// release call, so a reconciler reading it mid-unlock never sees a stale
/// `Connected`; the intent flips off only after the disengage confirms success.
///
/// The liveness check is [`crate::liveness::BridgeLiveness::try_acquire`] on the
/// lock a bridge on `state_dir` holds for its whole lifetime, and it is held across the
/// whole sequence rather than released after the check. A point-in-time probe
/// could go stale before the first mutation, letting a bridge that starts
/// mid-unlock have its live cover restored away and its intent flipped off
/// underneath it. A bridge starting during the sequence contends on the same lock.
fn unlock_with(
    state_dir: &Path,
    disengage: impl FnOnce(&CoverLock) -> std::io::Result<Clearance>,
) -> std::io::Result<Clearance> {
    let Some(_liveness) = crate::liveness::BridgeLiveness::try_acquire(state_dir, None)? else {
        return Err(std::io::Error::other(
            "a bridge instance is running; use the in-app \"Unblock Network\" action instead of `hole bridge unlock`",
        ));
    };
    let lock = CoverLock::acquire(state_dir);
    crate::target::apply(state_dir, None, |_| crate::target::Target::Off)
        .map_err(|e| std::io::Error::other(format!("could not record target off: {e}")))?;
    let clearance = disengage(&lock)?;
    // Same reason `handle_unblock` clears it: `resolve_startup_target` feeds
    // the candidate to `AlwaysConnect` over an `Off` target, so leaving it
    // would let the next boot reconnect to the server this escape just freed
    // the host from.
    crate::target::apply_startup_preference(state_dir, None, |pref| pref.candidate = None)
        .map_err(|e| std::io::Error::other(format!("could not clear the auto-connect candidate: {e}")))?;
    tun_engine::routing::failclosed::lockdown_state::set_enabled(&lock, false, None)
        .map_err(|e| std::io::Error::other(format!("could not record the lockdown intent off: {e}")))?;
    // On success the clearance is handed back, never dropped. If the candidate
    // or the intent write fails, it is lost with the error: bindreams/hole#1325.
    Ok(clearance)
}

/// The uninstaller's escape: clear EVERY fail-closed cover and record the target
/// off, with no running bridge.
///
/// Wider than [`unlock`], which disengages only the standing cover. Like
/// [`unlock`] it REFUSES against a live bridge instance, so no in-process posture
/// is left claiming a cover that no longer exists (`release_covers_with` names
/// which state dirs it probes). The refusal is best-effort: a peer state dir whose
/// lock cannot be probed is warned about and skipped, and other accounts' dirs
/// are not probed when enumerating profiles or looking up the real user fails
/// (bindreams/hole#1326). A caller therefore stops the service first: the MSI
/// runs `bridge uninstall --keep-covers` before its separate
/// `bridge release-covers` action.
///
/// Only the target write and the release itself abort the call: the MSI runs it
/// `Return="check"`, and failing on the trailing bookkeeping would roll back an
/// uninstall over a host that is already open. The target is recorded off BEFORE
/// the release, so whatever fails after, a later start reconciles toward `Off`
/// and sweeps.
///
/// **`Ok` means "nothing failed", not "the host is clear."** The returned
/// [`Clearance`] carries the difference and the caller must not collapse it: a
/// boot-time key answers not-found on any boot where its object is not live. That
/// is not an error ([`Clearance`] bounds the harm), but the caller prints
/// [`release_clearance_report`]. A filter the OS REFUSED to delete
/// ([`Clearance::refused_strangers`]) does not fail the call either; it is
/// reported with its GUID and code, and arms the boot-time witness
/// (`bridge-boottime.json`).
///
/// The reasoning is in `docs/contributing/architecture/kill-switch-uninstall.md`.
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
        |lock| tun_engine::routing::failclosed::release_all(lock).map_err(std::io::Error::other),
    )
}

/// The operator's last word on a cover release, or `None` when the sweep proved
/// every key it touched empty.
///
/// Pure, so the wording is testable, and shared by `bridge release-covers` and
/// `bridge uninstall` so they cannot tell two stories about one clearance. The
/// exit code is 0 either way (see [`release_covers`]), so at the one moment
/// `hole.exe` still exists on an uninstalling host this message IS the
/// qualification.
///
/// It reads [`Clearance::leftover_keys`], not [`Clearance::unproven_keys`]: the
/// twins go unproven on every boot where no bridge engaged, so the unproven set
/// would fire on essentially every Windows uninstall and carry no information.
/// `leftover_keys` reports when EITHER the standing cover's `PERSISTENT` siblings
/// in this sweep (`failclosed::KeyRole`) or the persisted
/// `failclosed::boottime_witness` says a twin could be outstanding. The union is
/// load-bearing: the sibling is consumed by the first sweep that removes it, and
/// the record is lost with a wiped `state_dir`; silence requires losing both.
///
/// It does NOT assert that a cover is present, since an unproven key is equally
/// consistent with never having been installed. Two kinds of key pass the gate,
/// worded apart:
/// - A filter key ([`Clearance::leftover_filters`]) is always a boot-time twin or
///   stranger here, never a `Persistent` key: an unproven `Persistent` key fails
///   the sweep, so it never reaches this function as `Ok`. The message states what
///   such keys are instead of hedging
///   (`an_unproven_release_calls_its_keys_boot_time_ones_because_that_is_all_it_can_name`).
///   A boot-time stranger whose delete was refused does not fail any sweep; it is
///   worded on its own line, with its code when the OS gave one, and a remedy.
/// - A view the sweep could not enumerate ([`Clearance::unenumerated_views`]) is
///   no filter at all: it is worded as a look that did not happen and names no
///   `netsh` lookup.
///
/// The remedy has to exist. `netsh wfp` is diagnostics-only, with no `delete`
/// verb (<https://learn.microsoft.com/windows-server/administration/windows-commands/netsh-wfp>),
/// and removing a WFP filter takes an FWPM call that `RemoveFiles` has just
/// deleted the only caller of, so the remedy is to put one back. The diagnostic
/// it names is `show boottimepolicy`; `show filters` excludes a boot-time filter
/// once BFE has started, i.e. at every moment this message is read.
///
/// `running_version` is the build making the report, and the remedy names it: a
/// key that answered not-found is not live, so no enumeration sees it and only a
/// build whose list names the key can address it. The running build's list names
/// every key it installs, so a key a later release adds needs no edit here.
pub fn release_clearance_report(clearance: &Clearance, running_version: &str) -> Option<String> {
    let filters: Vec<&str> = clearance.leftover_filters().map(UnprovenKey::label).collect();
    let unenumerated: Vec<&str> = clearance.unenumerated_views().map(UnprovenKey::label).collect();
    let mut parts = Vec::new();
    if let Some(refused) = refused_strangers_line(clearance) {
        parts.push(format!("{refused}. {REFUSED_STRANGER_REMEDY}"));
    }
    if !filters.is_empty() {
        parts.push(format!(
            "{} boot-time filter key(s) could not be proven empty: {}. \
             A boot-time filter is live only between kernel start and Base Filtering Engine start, \
             so a delete-by-key finds nothing on any later boot whether or not a policy record \
             survives behind it. To check after this uninstall, run `netsh wfp show boottimepolicy` \
             elevated and look for these keys; if egress is blocked early in boot, that is where it \
             would show. `netsh wfp` cannot remove one — it has no delete verb, only capture/dump/\
             help/set/show — and removing a WFP filter takes an FWPM call, which no binary left on this \
             host can make. Reinstalling this release, {running_version}, or later (a build can delete a boot-time \
             key only if its own list names it) and running `hole bridge release-covers` elevated puts back the \
             only tool that addresses these keys.",
            filters.len(),
            filters.join(", "),
        ));
    }
    if !unenumerated.is_empty() {
        parts.push(format!(
            "the sweep could not enumerate {}, so a filter another build left there was not looked for. \
             Running `hole bridge release-covers` elevated again repeats the sweep \
             (reinstall this release, {running_version}, or later first if `hole` is gone).",
            unenumerated.join(", "),
        ));
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!("covers released, but {}", parts.join(" Also, ")))
}

/// What the operator can do about filters the OS refused to delete: a refusal may be transient, so the sweep may
/// succeed later; failing that, an external tool, since `netsh wfp` has no delete verb.
const REFUSED_STRANGER_REMEDY: &str = "Boot-time filters are live only between kernel start and Base Filtering Engine \
     start, so they block nothing now, but one that survives can block egress early in the next boot. A refusal may \
     be transient: after a reboot, or on a later `hole bridge unlock`, the sweep may delete what it refused. Failing \
     that, remove each by its key with an elevated tool that calls `FwpmFilterDeleteByKey0` (`netsh wfp` has no \
     delete verb).";

/// One line naming each filter under Hole's provider that no key list names and the OS refused to delete, with the
/// code it answered when it did, or `None` when there is none.
fn refused_strangers_line(clearance: &Clearance) -> Option<String> {
    let lines: Vec<String> = clearance
        .refused_strangers()
        .map(|(label, code)| match code {
            Some(code) => format!("the OS refused to delete {label} (code 0x{code:08x})"),
            None => format!("the OS refused to delete {label}"),
        })
        .collect();
    if lines.is_empty() {
        return None;
    }
    Some(lines.join("; "))
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
                    error = &e as &dyn std::error::Error,
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
                    error = &e as &dyn std::error::Error,
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
/// any of them refuses the release just as the service's own does. Every peer is
/// locked, including one whose dir does not exist yet: the exclusion IS this
/// function, and `release_all` sweeps Windows' covers machine-wide, so a bridge
/// starting under that account mid-release would engage a cover, record the
/// posture, lose the filters to this sweep, and skip re-engagement on its next
/// covered start.
///
/// **The litter stays.** `try_acquire` creates what it locks, leaving an empty
/// state dir holding a lock file on every account that never ran a bridge.
/// Removing it would have to follow the release of the peer locks, which wakes the
/// bridge the exclusion exists to keep out: it would engage a standing cover and
/// have its record deleted from under it, and a persistent WFP cover with no
/// record has no in-band recovery.
///
/// Likewise it deletes no record in the service's own state dir.
/// `bridge-routes.json` and `bridge-dns{,.superseded}.json` are what
/// `scripts/network-reset.py` reads to undo a leaked bypass route or a rewritten
/// adapter's DNS, and `bridge-plugins.json` may be deleted only by something that
/// has accounted for every plugin in it; an uninstall is when those become the
/// only escape. The directory itself is `install()`'s.
fn release_covers_with(
    state_dir: &Path,
    peers: &[PathBuf],
    release: impl FnOnce(&CoverLock) -> std::io::Result<Clearance>,
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
        // per owning process (`file_lock::Exclusive`'s module doc), so
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
            Err(e) => {
                tracing::warn!(
                    error = &e as &dyn std::error::Error,
                    "could not probe a peer state dir for a live bridge"
                )
            }
        }
    }

    let lock = CoverLock::acquire(state_dir);
    crate::target::apply(state_dir, None, |_| crate::target::Target::Off)
        .map_err(|e| std::io::Error::other(format!("could not record target off: {e}")))?;
    let mut clearance = release(&lock)?;
    // The boot-time record is per-state-dir; the WFP filters it describes are
    // machine-wide. An elevated non-`--service` bridge keeps its state in the
    // interactive user's profile, so a twin IT armed is recorded where this
    // SYSTEM-context call would never look. Fold in every peer already probed
    // above — the same set, so a dir outside it is invisible to the record for
    // exactly the reason it is invisible to the liveness probe, and
    // `peer_state_dirs` discloses it once for both.
    for peer in &probed {
        clearance = clearance.corroborate(tun_engine::routing::failclosed::boottime_witness::load(peer));
    }

    // Best-effort from here — see the fatality note on `release_covers`.
    if let Err(e) = crate::target::apply_startup_preference(state_dir, None, |pref| pref.candidate = None) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "covers released, but the auto-connect candidate could not be cleared"
        );
    }
    if let Err(e) = tun_engine::routing::failclosed::lockdown_state::set_enabled(&lock, false, None) {
        tracing::warn!(
            error = &e as &dyn std::error::Error,
            "covers released, but the legacy lockdown intent could not be recorded off"
        );
    }

    drop(held);
    Ok(clearance)
}

#[cfg(test)]
#[path = "cutover_tests.rs"]
mod cutover_tests;
