// macOS: launchd bridge management.

use std::path::Path;
use tracing::info;

// Constants ===========================================================================================================

pub const LAUNCHD_LABEL: &str = "com.hole.bridge";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.hole.bridge.plist";
pub const HELPER_PATH: &str = "/Library/PrivilegedHelperTools/com.hole.bridge";
pub const SERVICE_LOG_DIR: &str = "/var/log/hole";
/// System state directory for the launchd daemon (Apple convention:
/// `/var/db/<daemon>`). Holds the route-recovery state file.
pub const SERVICE_STATE_DIR: &str = "/var/db/hole/state";

// Plist generation ====================================================================================================

/// Generate the launchd plist XML for the bridge.
pub fn generate_plist(binary_path: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary_path}</string>
        <string>bridge</string>
        <string>run</string>
        <string>--service</string>
        <string>--log-dir</string>
        <string>{log_dir}</string>
        <string>--state-dir</string>
        <string>{state_dir}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_dir}/bridge.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/bridge.stderr.log</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        binary_path = binary_path,
        log_dir = SERVICE_LOG_DIR,
        state_dir = SERVICE_STATE_DIR,
    )
}

// Install/uninstall ===================================================================================================

/// Install the bridge: copy binary to a stable location and register with launchd.
///
/// The binary is copied atomically to `/Library/PrivilegedHelperTools/com.hole.bridge`
/// and the plist references that stable path.
pub fn install(source_binary: &Path) -> std::io::Result<()> {
    let helper_dir = Path::new("/Library/PrivilegedHelperTools");
    std::fs::create_dir_all(helper_dir)?;

    // Create the service log + state dirs (running elevated here, so
    // LaunchDaemons can write to them later).
    std::fs::create_dir_all(SERVICE_LOG_DIR)?;
    std::fs::create_dir_all(SERVICE_STATE_DIR)?;

    // Atomic copy: write to temp file, then rename
    let tmp_path = helper_dir.join("com.hole.bridge.tmp");
    std::fs::copy(source_binary, &tmp_path)?;

    // Preserve executable permissions
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))?;

    std::fs::rename(&tmp_path, HELPER_PATH)?;

    let plist = generate_plist(HELPER_PATH);
    std::fs::write(PLIST_PATH, plist)?;

    // Use modern launchctl bootstrap (replaces deprecated `load -w`)
    let status = std::process::Command::new("launchctl")
        .args(["bootstrap", "system", PLIST_PATH])
        .status()?;

    if !status.success() {
        return Err(std::io::Error::other("launchctl bootstrap failed"));
    }

    info!("launchd bridge installed and loaded");
    Ok(())
}

/// Stop, unload, and remove the bridge.
pub fn uninstall() -> std::io::Result<()> {
    // bootout stops and unregisters
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &format!("system/{LAUNCHD_LABEL}")])
        .status();

    if Path::new(PLIST_PATH).exists() {
        std::fs::remove_file(PLIST_PATH)?;
    }
    if Path::new(HELPER_PATH).exists() {
        std::fs::remove_file(HELPER_PATH)?;
    }

    info!("launchd bridge uninstalled");
    Ok(())
}

// Start/stop ==========================================================================================================

/// Start the bridge (bootstrap the plist if not already loaded).
pub fn start() -> std::io::Result<()> {
    let status = std::process::Command::new("launchctl")
        .args(["bootstrap", "system", PLIST_PATH])
        .status()?;

    if !status.success() {
        return Err(std::io::Error::other("launchctl bootstrap failed"));
    }
    info!("launchd bridge started");
    Ok(())
}

/// Stop the bridge without unregistering it.
pub fn stop() -> std::io::Result<()> {
    let status = std::process::Command::new("launchctl")
        .args(["kill", "SIGTERM", &format!("system/{LAUNCHD_LABEL}")])
        .status()?;

    if !status.success() {
        return Err(std::io::Error::other("launchctl kill failed"));
    }
    info!("launchd bridge stopped");
    Ok(())
}

// Query ===============================================================================================================

/// Check whether the bridge plist is installed.
pub fn is_installed() -> bool {
    Path::new(PLIST_PATH).exists()
}

/// Check whether the bridge is currently running.
pub fn is_running() -> bool {
    std::process::Command::new("launchctl")
        .args(["print", &format!("system/{LAUNCHD_LABEL}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run the bridge directly (called by launchd).
pub fn run(socket_path: &std::path::Path, state_dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(crate::proxy_manager::ProxyManager::new(
            crate::proxy_manager::RealBackend,
            state_dir.to_path_buf(),
        )));
        let proxy_shutdown = std::sync::Arc::clone(&proxy);

        // Bind BEFORE recovery — a second instance's bind() fails before it
        // can touch routing state.
        let server = crate::ipc::IpcServer::bind(socket_path, proxy)?;
        crate::routing::recover_routes(state_dir);

        tokio::select! {
            result = server.run() => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "IPC server error");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received shutdown signal");
            }
        }

        // Clean shutdown: stop proxy before exiting
        let mut pm = proxy_shutdown.lock().await;
        if let Err(e) = pm.stop().await {
            tracing::error!(error = %e, "error stopping proxy during shutdown");
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
