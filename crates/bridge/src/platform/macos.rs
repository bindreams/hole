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
///
/// Note: we deliberately do NOT set `StandardOutPath` / `StandardErrorPath`.
/// The bridge installs an FD-level stdio redirect in
/// [`hole_common::logging::init`] that captures FD 1 and FD 2 into the
/// `tracing` pipeline and writes them to the rolling daily file under
/// `{log_dir}/bridge.log`. A launchd-side capture would only produce
/// duplicate files.
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
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        binary_path = binary_path,
        log_dir = SERVICE_LOG_DIR,
        state_dir = SERVICE_STATE_DIR,
    )
}

// launchctl helper ====================================================================================================

/// Run `launchctl` with captured stdout/stderr. Logs captured output via
/// tracing on both success (debug level) and failure (level chosen by
/// caller). Returns Ok iff the exit status was success; the caller gets a
/// structured `io::Error::other(...)` with the operation label baked in.
///
/// Historically these calls used `.status()` with inherited stdio, so any
/// launchctl error (bad plist, permissions, missing service) went straight
/// to the bridge's terminal — lost in service mode. Capturing the output
/// lets the file log explain what actually went wrong.
///
/// Failure severity is an argument because some call sites are best-effort
/// (e.g. `uninstall` runs `bootout` on a service that may not be loaded, and
/// a failure there is acceptable) — those use `BestEffort` to avoid spamming
/// `ERROR`-level lines in `bridge.log`.
#[derive(Clone, Copy)]
enum LaunchctlFailLevel {
    Error,
    BestEffort,
}

fn run_launchctl(label: &str, args: &[&str], fail_level: LaunchctlFailLevel) -> std::io::Result<std::process::Output> {
    let output = std::process::Command::new("launchctl").args(args).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        match fail_level {
            LaunchctlFailLevel::Error => {
                tracing::error!(
                    %stdout,
                    %stderr,
                    status = ?output.status,
                    "launchctl {label} failed",
                );
            }
            LaunchctlFailLevel::BestEffort => {
                tracing::debug!(
                    %stdout,
                    %stderr,
                    status = ?output.status,
                    "launchctl {label} best-effort call did not succeed",
                );
            }
        }
        return Err(std::io::Error::other(format!("launchctl {label} failed: {stderr}")));
    }
    tracing::debug!(%stdout, "launchctl {label} ok");
    Ok(output)
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
    run_launchctl(
        "bootstrap",
        &["bootstrap", "system", PLIST_PATH],
        LaunchctlFailLevel::Error,
    )?;

    info!("launchd bridge installed and loaded");
    Ok(())
}

/// Stop, unload, and remove the bridge.
pub fn uninstall() -> std::io::Result<()> {
    // bootout stops and unregisters. Best-effort: ignore the Result because
    // uninstall must succeed even if the plist isn't currently loaded.
    let system_label = format!("system/{LAUNCHD_LABEL}");
    let _ = run_launchctl("bootout", &["bootout", &system_label], LaunchctlFailLevel::BestEffort);

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
    run_launchctl(
        "bootstrap",
        &["bootstrap", "system", PLIST_PATH],
        LaunchctlFailLevel::Error,
    )?;
    info!("launchd bridge started");
    Ok(())
}

/// Stop the bridge without unregistering it.
pub fn stop() -> std::io::Result<()> {
    let system_label = format!("system/{LAUNCHD_LABEL}");
    run_launchctl("kill", &["kill", "SIGTERM", &system_label], LaunchctlFailLevel::Error)?;
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
        let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::proxy_manager::ProxyManager::new(
                crate::proxy::ShadowsocksProxy::new(),
                tun_engine::routing::SystemRouting::new(state_dir.to_path_buf()),
            )
            .with_state_dir(state_dir.to_path_buf()),
        ));
        let proxy_shutdown = std::sync::Arc::clone(&proxy);

        // Bind BEFORE recovery — a second instance's bind() fails before it
        // can touch routing state. Route recovery is offloaded via
        // spawn_blocking so a hung netsh/route command cannot wedge the
        // runtime while the IPC socket is bound but not yet serving.
        let server = crate::ipc::IpcServer::bind(socket_path, proxy)?;
        let state_dir_routes = state_dir.to_path_buf();
        if let Err(e) =
            tokio::task::spawn_blocking(move || tun_engine::routing::recover_routes(&state_dir_routes)).await
        {
            tracing::warn!(error = %e, "recover_routes task panicked");
        }
        let state_dir_plugins = state_dir.to_path_buf();
        if let Err(e) =
            tokio::task::spawn_blocking(move || crate::plugin_recovery::recover_plugins(&state_dir_plugins)).await
        {
            tracing::warn!(error = %e, "recover_plugins task panicked");
        }

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
