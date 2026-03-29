// Platform-specific installer execution.

use std::path::Path;

use super::error::UpdateError;

// Windows =============================================================================================================

#[cfg(target_os = "windows")]
pub fn run_installer(path: &Path, quiet: bool) -> Result<(), UpdateError> {
    let args = msiexec_args(path, quiet);
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    if quiet {
        // Quiet mode skips UAC, so we must elevate explicitly.
        let status = crate::setup::run_elevated(Path::new("msiexec"), &args_ref)
            .map_err(|e| UpdateError::Io(std::io::Error::other(e.to_string())))?;
        if !status.success() {
            return Err(UpdateError::InstallerFailed(status.code().unwrap_or(-1)));
        }
    } else {
        // Interactive mode: msiexec shows its own UAC prompt.
        let status = std::process::Command::new("msiexec").args(&args_ref).status()?;
        if !status.success() {
            return Err(UpdateError::InstallerFailed(status.code().unwrap_or(-1)));
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn msiexec_args(path: &Path, quiet: bool) -> Vec<String> {
    let path_str = path.to_string_lossy().to_string();
    let mut args = vec!["/i".to_string(), path_str.clone()];

    if quiet {
        args.push("/quiet".to_string());
        args.push("/norestart".to_string());
        // Log file for diagnostics next to the MSI.
        let log_path = format!("{path_str}.log");
        args.push(format!("/L*v{log_path}"));
    }

    args
}

// macOS ===============================================================================================================

#[cfg(target_os = "macos")]
pub fn run_installer(path: &Path, _quiet: bool) -> Result<(), UpdateError> {
    let mount_dir = tempfile::TempDir::with_prefix("hole-dmg-mount-")?;

    // Mount the DMG
    let attach_args = hdiutil_attach_args(path, mount_dir.path());
    let attach_args_ref: Vec<&str> = attach_args.iter().map(|s| s.as_str()).collect();
    let status = std::process::Command::new("hdiutil").args(&attach_args_ref).status()?;
    if !status.success() {
        return Err(UpdateError::InstallerFailed(status.code().unwrap_or(-1)));
    }

    // Everything after a successful attach must go through detach.
    let result = install_from_mount(mount_dir.path());

    // Always unmount
    let _ = std::process::Command::new("hdiutil")
        .args(["detach", &mount_dir.path().to_string_lossy()])
        .status();

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
    let app_name = app_src.file_name().unwrap().to_string_lossy().to_string();
    let app_dest = format!("/Applications/{app_name}");

    let cp_path = Path::new("/bin/cp");
    let src_str = app_src.to_string_lossy().to_string();
    let cp_args = ["-R", &src_str, &app_dest];
    let status = crate::setup::run_elevated(cp_path, &cp_args)
        .map_err(|e| UpdateError::Io(std::io::Error::other(e.to_string())))?;
    if !status.success() {
        return Err(UpdateError::InstallerFailed(status.code().unwrap_or(-1)));
    }

    Ok(())
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
