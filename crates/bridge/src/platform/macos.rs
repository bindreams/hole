// macOS: launchd bridge management.

use std::path::Path;
use tracing::info;

// Constants ===========================================================================================================

pub const LAUNCHD_LABEL: &str = "com.hole.bridge";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.hole.bridge.plist";
pub const HELPER_PATH: &str = "/Library/PrivilegedHelperTools/com.hole.bridge";
pub const SERVICE_LOG_DIR: &str = "/var/log/hole";
/// System state directory for the launchd daemon (Apple convention:
/// `/var/db/<daemon>`). Holds the bridge crash-recovery state files
/// (DNS, routes, plugins).
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
/// Output is captured (not inherited) so launchctl errors (bad plist,
/// permissions, missing service) land in bridge.log instead of a terminal
/// nobody sees in service mode.
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
///
/// `log_dir` is the directory the crash-marker sweep reads (markers land
/// next to `bridge.log`; see bindreams/hole#438).
pub fn run(
    socket_path: &std::path::Path,
    state_dir: &std::path::Path,
    log_dir: &std::path::Path,
    version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::proxy_manager::ProxyManager::new(
                crate::proxy::ShadowsocksProxy::new(),
                tun_engine::routing::SystemRouting::new(state_dir.to_path_buf(), None),
            )
            .with_state_dir(state_dir.to_path_buf()),
        ));
        let proxy_shutdown = std::sync::Arc::clone(&proxy);

        // Bind BEFORE recovery — a second instance's bind() fails before it
        // can touch routing state. Route recovery is offloaded via
        // spawn_blocking so a hung netsh/route command cannot wedge the
        // runtime while the IPC socket is bound but not yet serving.
        let server = crate::ipc::IpcServer::bind_with_dirs(
            socket_path,
            proxy,
            version,
            log_dir.to_path_buf(),
            state_dir.to_path_buf(),
            // The `--service` daemon runs as root and its dirs are root-owned by
            // design; no real user to chown writes back to.
            None,
        )?;
        // DNS recovery runs first; see crate::dns::recovery docs for ordering.
        let state_dir_dns = state_dir.to_path_buf();
        if let Err(e) =
            tokio::task::spawn_blocking(move || crate::dns::recovery::recover_dns_config(&state_dir_dns)).await
        {
            tracing::warn!(error = %e, "recover_dns_config task panicked");
        }
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
        // Native-crash observability (bindreams/hole#438): sweep crash
        // markers left by a previously-crashed bridge. Offloaded to a
        // blocking thread to match the sibling recover_* calls.
        let log_dir_sweep = log_dir.to_path_buf();
        if let Err(e) = tokio::task::spawn_blocking(move || tombstone::sweep(&log_dir_sweep)).await {
            tracing::warn!(error = %e, "crash sweep task panicked");
        }
        // The new bridge is authoritative once it has bound: any update marker is
        // a completed cutover, so clear it unconditionally (remove-by-path).
        let log_dir_marker = log_dir.to_path_buf();
        if let Err(e) = tokio::task::spawn_blocking(move || sweep_marker(&log_dir_marker)).await {
            tracing::warn!(error = %e, "marker sweep task panicked");
        }

        // launchd stops the daemon with SIGTERM; awaiting only ctrl_c (SIGINT)
        // here would skip the pm.stop() teardown below and leak routes/DNS.
        // `shutdown_signal()` handles SIGINT *and* SIGTERM (foreground.rs).
        serve_until_signal(server.run(), crate::foreground::shutdown_signal()).await;

        // Clean shutdown: stop proxy before exiting. A cutover-driven shutdown
        // (marker present) disarms the standing cover so the persistent pf
        // ruleset survives the restart; an ordinary stop disengages it.
        let mut pm = proxy_shutdown.lock().await;
        let reason = shutdown_reason(hole_common::update_marker::read(log_dir).is_some());
        if let Err(e) = pm.stop_with(reason).await {
            tracing::error!(error = %e, "error stopping proxy during shutdown");
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

/// Map an update-in-progress marker's presence to the stop reason: present
/// means a cutover is mid-flight, so the standing cover is disarmed (persists)
/// rather than disengaged. Pure so the decision is table-testable.
pub(crate) fn shutdown_reason(marker_present: bool) -> crate::proxy_manager::StopReason {
    if marker_present {
        crate::proxy_manager::StopReason::Cutover
    } else {
        crate::proxy_manager::StopReason::UserStop
    }
}

/// Clear a stale update-in-progress marker on the new bridge's post-bind sweep.
/// The marker's presence is co-extensive with "a cutover during which no bridge
/// answered"; once this bridge binds, the cutover is done. Remove-by-path so a
/// from->to schema bump across the cutover cannot strand it.
pub(crate) fn sweep_marker(log_dir: &std::path::Path) {
    if let Err(e) = hole_common::update_marker::clear(log_dir) {
        tracing::warn!(error = %e, "failed to clear update-in-progress marker");
    }
}

/// Drive the IPC server until it finishes or a shutdown signal arrives,
/// whichever comes first. Extracted from `run` so the select can be
/// unit-tested without delivering real OS signals.
pub(crate) async fn serve_until_signal(
    server: impl std::future::Future<Output = std::io::Result<()>>,
    shutdown: impl std::future::Future<Output = ()>,
) {
    tokio::select! {
        result = server => {
            if let Err(e) = result {
                tracing::error!(error = %e, "IPC server error");
            }
        }
        _ = shutdown => {
            info!("received shutdown signal");
        }
    }
}

/// A valid marker for the post-bind-sweep test.
#[cfg(test)]
fn test_marker() -> hole_common::update_marker::MarkerInfo {
    hole_common::update_marker::MarkerInfo {
        version: hole_common::update_marker::MARKER_VERSION,
        from_version: "0.2.0".into(),
        to_version: "0.3.0".into(),
        driver_pid: 1,
        started_at_unix: 0,
        driver_start_unix_ms: 0,
    }
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
