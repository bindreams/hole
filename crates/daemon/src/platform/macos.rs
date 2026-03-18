// macOS: launchd daemon management.

use tracing::info;

// Constants =====

pub const LAUNCHD_LABEL: &str = "com.hole.daemon";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.hole.daemon.plist";

// Plist generation =====

/// Generate the launchd plist XML for the daemon.
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
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/hole/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/hole/daemon.err</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        binary_path = binary_path,
    )
}

// Install/uninstall =====

/// Install the daemon launchd plist and load it.
pub fn install_daemon(binary_path: &str) -> std::io::Result<()> {
    let plist = generate_plist(binary_path);
    std::fs::write(PLIST_PATH, plist)?;

    std::process::Command::new("launchctl")
        .args(["load", "-w", PLIST_PATH])
        .status()?;

    info!("launchd daemon installed and loaded");
    Ok(())
}

/// Unload and remove the daemon launchd plist.
pub fn uninstall_daemon() -> std::io::Result<()> {
    let _ = std::process::Command::new("launchctl")
        .args(["unload", PLIST_PATH])
        .status();

    if std::path::Path::new(PLIST_PATH).exists() {
        std::fs::remove_file(PLIST_PATH)?;
    }

    info!("launchd daemon uninstalled");
    Ok(())
}

/// Run the daemon directly (called by launchd).
pub fn run_daemon() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(crate::proxy_manager::ProxyManager::new(
            crate::proxy_manager::RealBackend,
        )));
        let proxy_shutdown = std::sync::Arc::clone(&proxy);

        let server = crate::ipc::IpcServer::bind(crate::ipc::SOCKET_NAME, proxy)?;

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

        Ok(())
    })?;
    Ok(())
}

#[cfg(test)]
#[path = "macos_tests.rs"]
mod macos_tests;
