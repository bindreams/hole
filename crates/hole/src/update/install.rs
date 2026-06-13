// Platform-specific installer execution.

use std::path::Path;

use super::error::UpdateError;

/// How the update installer runs after this process exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMode {
    /// Full installer UI; the installer handles its own elevation (tray).
    Interactive,
    /// No installer UI; the helper itself is spawned elevated (CLI).
    Quiet,
}

// Windows =============================================================================================================

#[cfg(target_os = "windows")]
pub(crate) mod intermediary;

/// Arm the update and transfer ownership of the download dir.
///
/// Spawns a detached helper that waits (kernel wait, no timeout) for this
/// process to exit and only then runs msiexec, so the MSI never sees a
/// running Hole (#468). On Ok the caller must exit promptly. The dir is
/// persisted: the helper removes it on success; the orphan sweep collects
/// it otherwise. On Err nothing was armed and the dir is already cleaned.
///
/// `Interactive`: helper spawned non-elevated with a stdout-pipe handshake;
/// msiexec shows its own UI and UAC. `Quiet`: helper spawned elevated up
/// front (UAC consent happens HERE, while we are alive; decline =>
/// `ElevationDeclined`) with a named-event handshake, then runs msiexec
/// /quiet directly.
#[cfg(target_os = "windows")]
pub fn install_for_exit(
    download_dir: tempfile::TempDir,
    msi_path: &Path,
    mode: InstallMode,
) -> Result<(), UpdateError> {
    let kept_dir = download_dir.keep();
    tracing::info!(msi = %msi_path.display(), ?mode, "arming detached MSI install");
    cleanup_for_outcome(&kept_dir, arm_installer(&kept_dir, msi_path, mode))
}

/// Result of arming the detached helper, distinguishing who owns the
/// persisted download dir afterwards.
#[cfg(target_os = "windows")]
enum ArmOutcome {
    /// A helper is running and will run the MSI and remove the dir on success.
    Armed,
    /// Nothing was armed; the caller must remove the dir.
    NotArmed(UpdateError),
    /// The kernel wait failed, so we can no longer tell whether a helper is
    /// live; leave the dir for it / the orphan sweep rather than risk
    /// deleting the MSI from under a running installer.
    Uncertain(UpdateError),
}

/// Apply the dir-ownership decision from [`ArmOutcome`]: delete only when
/// nothing was armed.
#[cfg(target_os = "windows")]
fn cleanup_for_outcome(kept_dir: &Path, outcome: ArmOutcome) -> Result<(), UpdateError> {
    match outcome {
        ArmOutcome::Armed => Ok(()),
        ArmOutcome::NotArmed(e) => {
            let _ = std::fs::remove_dir_all(kept_dir);
            Err(e)
        }
        ArmOutcome::Uncertain(e) => Err(e),
    }
}

#[cfg(target_os = "windows")]
fn arm_installer(kept_dir: &Path, msi_path: &Path, mode: InstallMode) -> ArmOutcome {
    match mode {
        InstallMode::Interactive => {
            let spec = intermediary::IntermediarySpec {
                wait_pid: std::process::id(),
                installer_argv: msiexec_argv(msi_path, false),
                rendezvous: intermediary::Rendezvous::Stdout,
                cleanup_dir: kept_dir.to_path_buf(),
            };
            // launch kills the helper on handshake failure, so an Err means
            // nothing is armed.
            match intermediary::launch(&spec) {
                Ok(()) => ArmOutcome::Armed,
                Err(e) => ArmOutcome::NotArmed(e),
            }
        }
        InstallMode::Quiet => {
            // Same-session rendezvous: the elevated helper shares this
            // process's session (UAC preserves the session), so a Local
            // event needs no privilege and is visible across the integrity
            // boundary.
            let event_name = format!("Local\\com.hole.app-upgrade-ready-{}", std::process::id());
            let event = match intermediary::create_ready_event(&event_name) {
                Ok(e) => e,
                Err(e) => return ArmOutcome::NotArmed(e),
            };
            let spec = intermediary::IntermediarySpec {
                wait_pid: std::process::id(),
                installer_argv: msiexec_argv(msi_path, true),
                rendezvous: intermediary::Rendezvous::Event { name: event_name },
                cleanup_dir: kept_dir.to_path_buf(),
            };
            let encoded = intermediary::encode_command(&intermediary::build_script(&spec));
            let ps = intermediary::powershell_path();
            let args = [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                &encoded,
            ];
            let helper = match crate::setup::spawn_elevated(&ps, &args) {
                Ok(h) => h,
                Err(crate::setup::SetupError::Cancelled) => {
                    return ArmOutcome::NotArmed(UpdateError::ElevationDeclined)
                }
                Err(e) => return ArmOutcome::NotArmed(UpdateError::Io(std::io::Error::other(e.to_string()))),
            };
            match intermediary::wait_ready_event_handle(&event, helper.handle()) {
                Ok(intermediary::ReadyOutcome::Ready) => ArmOutcome::Armed,
                Ok(intermediary::ReadyOutcome::HelperExited) => ArmOutcome::NotArmed(UpdateError::HelperNotReady),
                // Kernel wait failed; we can no longer tell whether the
                // helper is parked in WaitForExit. Don't risk deleting the
                // MSI from under it.
                Err(e) => ArmOutcome::Uncertain(e),
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn msiexec_argv(path: &Path, quiet: bool) -> Vec<String> {
    let exe = match std::env::var("SystemRoot") {
        Ok(root) => format!(r"{root}\System32\msiexec.exe"),
        Err(_) => "msiexec.exe".to_string(),
    };
    let mut argv = vec![exe];
    argv.extend(msiexec_args(path, quiet));
    argv
}

#[cfg(target_os = "windows")]
pub(crate) fn msiexec_args(path: &Path, quiet: bool) -> Vec<String> {
    let path_str = path.to_string_lossy().to_string();
    let mut args = vec!["/i".to_string(), path_str.clone()];

    if quiet {
        args.push("/quiet".to_string());
        args.push("/norestart".to_string());
    }

    // Log next to the MSI for post-detach diagnostics. The value is its own
    // token (documented msiexec form) so temp paths with spaces survive quoting.
    args.push("/L*v".to_string());
    args.push(format!("{path_str}.log"));

    args
}

// macOS ===============================================================================================================

/// Blocking install of the .app bundle, then release of the download dir.
/// Ok means the copy completed; the caller must then exit. `mode` does not
/// apply: the DMG copy has no UI and elevates via run_elevated.
#[cfg(target_os = "macos")]
pub fn install_for_exit(
    download_dir: tempfile::TempDir,
    dmg_path: &Path,
    _mode: InstallMode,
) -> Result<(), UpdateError> {
    let result = run_installer(dmg_path);
    drop(download_dir);
    result
}

#[cfg(target_os = "macos")]
pub(crate) fn run_installer(path: &Path) -> Result<(), UpdateError> {
    let mount_dir = tempfile::TempDir::with_prefix("hole-dmg-mount-")?;

    // Mount the DMG. Use `.output()` (not `.status()`) so a mount failure's
    // stderr reaches the tracing file log — in GUI-background installs there
    // is no inherited stdio to catch it.
    let attach_args = hdiutil_attach_args(path, mount_dir.path());
    let attach_args_ref: Vec<&str> = attach_args.iter().map(|s| s.as_str()).collect();
    let output = std::process::Command::new("hdiutil").args(&attach_args_ref).output()?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!(
            %stdout,
            %stderr,
            status = ?output.status,
            "hdiutil attach failed",
        );
        return Err(UpdateError::InstallerFailed(output.status.code().unwrap_or(-1)));
    }

    // Everything after a successful attach must go through detach.
    let result = install_from_mount(mount_dir.path());

    // Always unmount. Failure here is logged but not propagated (we already
    // have the install result).
    let detach_output = std::process::Command::new("hdiutil")
        .args(["detach", &mount_dir.path().to_string_lossy()])
        .output();
    match detach_output {
        Ok(o) if !o.status.success() => {
            tracing::warn!(
                stdout = %String::from_utf8_lossy(&o.stdout),
                stderr = %String::from_utf8_lossy(&o.stderr),
                "hdiutil detach failed",
            );
        }
        Err(e) => tracing::warn!(error = %e, "hdiutil detach spawn failed"),
        _ => {}
    }

    result
}

#[cfg(target_os = "macos")]
fn install_from_mount(mount_dir: &Path) -> Result<(), UpdateError> {
    let app_entry = std::fs::read_dir(mount_dir)?
        .filter_map(|e| e.ok())
        .find(|e| e.path().extension().is_some_and(|ext| ext == "app"));

    let Some(app_entry) = app_entry else {
        return Err(UpdateError::Io(std::io::Error::other("no .app bundle found in DMG")));
    };

    let app_src = app_entry.path();
    let app_name = app_src
        .file_name()
        .expect("read_dir entry always has a filename")
        .to_string_lossy()
        .to_string();
    let app_dest = format!("/Applications/{app_name}");

    let cp_path = Path::new("/bin/cp");
    let src_str = app_src.to_string_lossy().to_string();
    let cp_args = ["-R", &src_str, &app_dest];
    match crate::setup::run_elevated(cp_path, &cp_args) {
        Ok(()) => Ok(()),
        Err(crate::setup::SetupError::ExitCode { code, .. }) => Err(UpdateError::InstallerFailed(code)),
        Err(e) => Err(UpdateError::Io(std::io::Error::other(e.to_string()))),
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn hdiutil_attach_args(dmg: &Path, mountpoint: &Path) -> Vec<String> {
    vec![
        "attach".to_string(),
        "-nobrowse".to_string(),
        "-quiet".to_string(),
        "-mountpoint".to_string(),
        mountpoint.to_string_lossy().to_string(),
        dmg.to_string_lossy().to_string(),
    ]
}

#[cfg(test)]
#[path = "install_tests.rs"]
mod install_tests;
