// Foreground bridge runner for development.

use crate::proxy_manager::ProxyBackend;
use std::path::Path;

/// Run the bridge in foreground mode (for development).
/// Bypasses the platform service manager. Shuts down on Ctrl+C.
///
/// When `no_tun` is true, uses `NoTunBackend` (no elevation needed).
/// When `no_tun` is false, uses `RealBackend` (requires elevation for TUN/routing).
pub fn run(socket_path: &Path, no_tun: bool) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    if no_tun {
        rt.block_on(run_inner(socket_path, crate::proxy_manager::NoTunBackend))
    } else {
        rt.block_on(run_inner(socket_path, crate::proxy_manager::RealBackend))
    }
}

async fn run_inner<B: ProxyBackend + 'static>(
    socket_path: &Path,
    backend: B,
) -> Result<(), Box<dyn std::error::Error>> {
    let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(crate::proxy_manager::ProxyManager::new(
        backend,
    )));
    let proxy_shutdown = std::sync::Arc::clone(&proxy);

    let server = crate::ipc::IpcServer::bind_dev(socket_path, proxy)?;

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "IPC server error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown signal received");
        }
    }

    let mut pm = proxy_shutdown.lock().await;
    if let Err(e) = pm.stop().await {
        tracing::error!(error = %e, "error stopping proxy during shutdown");
    }

    Ok(())
}

#[cfg(test)]
#[path = "foreground_tests.rs"]
mod foreground_tests;
