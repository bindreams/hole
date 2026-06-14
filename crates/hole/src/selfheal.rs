//! GUI ↔ bridge version-lockstep self-heal.
//!
//! When the GUI detects (via the `X-Hole-Bridge-Version` header) that the
//! bridge runs a different version, it must not operate the mismatched pair.
//! [`decide`] is the pure, `#[cfg]`-free policy; the OS-specific bits live
//! behind the [`canonical_install_exe`](capture_startup_identity)/identity
//! seam and [`crate::relaunch`]. Inert until an update produces a mismatch.

use std::path::{Path, PathBuf};

/// What the GUI should do about an observed version mismatch.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SelfHealAction {
    /// Versions match — operate normally.
    Operate,
    /// The installed image changed under us (an update) — relaunch it.
    Relaunch,
    /// We are the installed image but the bridge differs — genuine
    /// misconfiguration; prompt the user to reinstall.
    Reinstall,
    /// The installed file is transiently absent (mid-swap) — retry later.
    Transient,
}

/// Pure self-heal policy. `bridge` is the bridge's reported version, or
/// `None` for an old bridge predating the version stamp (treated as a
/// mismatch). `running` is our startup image identity; `canonical` is the
/// identity of the file at that same path *now*, or `None` if it is
/// transiently absent. Generic over the identity token so it is fully
/// table-testable without touching the filesystem.
pub fn decide<T: PartialEq>(own: &str, bridge: Option<&str>, running: T, canonical: Option<T>) -> SelfHealAction {
    if bridge == Some(own) {
        return SelfHealAction::Operate;
    }
    match canonical {
        None => SelfHealAction::Transient,
        Some(c) if c != running => SelfHealAction::Relaunch,
        Some(_) => SelfHealAction::Reinstall,
    }
}

/// The GUI image identity captured at startup, before any update can rename
/// it. Compared later against the file at the same path: a difference means
/// an update swapped the binary underneath us. The path is derived from
/// `current_exe` (not a hardcoded `Program Files` location), so a custom
/// install directory is handled automatically.
pub struct StartupIdentity {
    pub exe: PathBuf,
    pub id: same_file::Handle,
}

/// Capture the running image's identity once at startup. Returns `None` for
/// dev/snapshot builds (built in lockstep — never self-heal) or if the exe
/// identity cannot be read.
pub fn capture_startup_identity() -> Option<StartupIdentity> {
    if is_dev_build() {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let id = same_file::Handle::from_path(&exe).ok()?;
    Some(StartupIdentity { exe, id })
}

/// Dev/snapshot builds are built in lockstep and must never self-heal.
fn is_dev_build() -> bool {
    matches!(
        hole_common::version::ReleaseVersion::from_build_version(crate::version::VERSION),
        Ok((_, true)) // is_snapshot
    )
}

/// File identity via the cross-platform `same_file` crate (volume serial +
/// file index on Windows; device + inode on Unix). No FFI, no `#[cfg]`.
pub fn file_identity(p: &Path) -> std::io::Result<same_file::Handle> {
    same_file::Handle::from_path(p)
}

/// Show the path-free "please reinstall" dialog (the `Reinstall` action). The
/// running-image-vs-canonical path detail is logged to `gui.log` at the
/// trigger, never shown — PII stays out of the dialog.
pub fn show_reinstall_dialog(app: &tauri::AppHandle) {
    use tauri_plugin_dialog::DialogExt;
    app.dialog()
        .message("Hole is in an inconsistent state and needs to be reinstalled.")
        .title("Hole")
        .show(|_| {});
}

use std::sync::atomic::{AtomicBool, Ordering};

/// Installed image identity, snapshotted at startup via [`init_startup`].
/// `None` ⇒ a dev build that never self-heals.
static STARTUP: std::sync::OnceLock<Option<StartupIdentity>> = std::sync::OnceLock::new();

/// Snapshot the startup image identity. Called once at GUI launch, while
/// `current_exe` is still the installed path (before any update renames it).
pub fn init_startup() {
    let _ = STARTUP.set(capture_startup_identity());
}

/// At most one self-heal evaluation in flight — bounds thread spawns so a
/// stuck `Transient` cannot spawn a thread per poll. A terminal action exits
/// the process; `Operate`/`Transient`/relaunch-spawn-failure release it.
static EVALUATING: AtomicBool = AtomicBool::new(false);

/// Seam for unit-testing the action dispatch without a real relaunch /
/// dialog / process exit.
pub trait SelfHealOs {
    fn spawn_successor(&mut self) -> std::io::Result<()>;
    fn show_reinstall_dialog(&mut self);
    fn request_exit(&mut self);
}

/// Unit-tested core: decide, then dispatch via the injected seam.
pub fn run_with<T: PartialEq>(
    own: &str,
    bridge: Option<&str>,
    running: T,
    canonical: Option<T>,
    os: &mut impl SelfHealOs,
) -> SelfHealAction {
    let action = decide(own, bridge, running, canonical);
    match action {
        SelfHealAction::Relaunch => {
            if os.spawn_successor().is_ok() {
                os.request_exit();
            }
        }
        SelfHealAction::Reinstall => {
            os.show_reinstall_dialog();
            os.request_exit();
        }
        SelfHealAction::Operate | SelfHealAction::Transient => {}
    }
    action
}

/// Production driver, fired on every observed version mismatch. Decides once
/// with the *real* startup-vs-now image identities and dispatches directly
/// (it does NOT call [`run_with`] — that is the separately-tested core).
/// `decide`'s quick stat runs inline; only the blocking relaunch goes to a
/// thread, which is intentionally never joined (the process exits).
pub fn trigger(app: &tauri::AppHandle, bridge: Option<String>) {
    let Some(Some(startup)) = STARTUP.get() else {
        return; // dev build (or pre-init) — never self-heal
    };
    if EVALUATING.swap(true, Ordering::SeqCst) {
        return; // an evaluation is already in flight
    }

    let now = file_identity(&startup.exe).ok();
    match decide(crate::version::VERSION, bridge.as_deref(), &startup.id, now.as_ref()) {
        SelfHealAction::Relaunch => {
            tracing::warn!(exe = %startup.exe.display(), "self-heal: installed image changed under us; relaunching");
            let (app, exe) = (app.clone(), startup.exe.clone());
            std::thread::spawn(move || {
                if crate::relaunch::spawn_successor(&exe).is_ok() {
                    app.exit(0); // EVALUATING stays set; the process is exiting
                } else {
                    EVALUATING.store(false, Ordering::SeqCst); // spawn failed → allow retry next poll
                }
            });
        }
        SelfHealAction::Reinstall => {
            tracing::warn!(exe = %startup.exe.display(), "self-heal: version mismatch, image unchanged; prompting reinstall");
            show_reinstall_dialog(app);
            app.exit(0); // EVALUATING stays set; the process is exiting
        }
        SelfHealAction::Operate | SelfHealAction::Transient => {
            EVALUATING.store(false, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
#[path = "selfheal_tests.rs"]
mod selfheal_tests;
