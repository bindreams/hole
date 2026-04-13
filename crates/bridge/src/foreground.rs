// Foreground bridge runner for development.

use crate::proxy::ShadowsocksProxy;
use crate::proxy_manager::ProxyManager;
use crate::routing::SystemRouting;
use std::path::Path;

/// Run the bridge in foreground mode (for development).
///
/// Bypasses the platform service manager and shuts down on Ctrl+C. Uses
/// the production `IpcServer::bind` + `apply_socket_permissions` path, so
/// dev exercises the real DACL/group/SDDL code — see the `dev.py` /
/// `bridge grant-access` orchestration. Requires elevation for TUN +
/// routing.
pub fn run(socket_path: &Path, state_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_inner(socket_path, state_dir))
}

async fn run_inner(socket_path: &Path, state_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(
        ProxyManager::new(ShadowsocksProxy::new(), SystemRouting::new(state_dir.to_path_buf()))
            .with_state_dir(state_dir.to_path_buf()),
    ));
    let proxy_shutdown = std::sync::Arc::clone(&proxy);

    // Bind BEFORE recovery. If a second bridge instance tries to run, the
    // bind() fails and we exit without touching any routing state.
    let server = crate::ipc::IpcServer::bind(socket_path, proxy)?;

    // Offload route recovery to a blocking thread so a hung netsh/route
    // command cannot wedge the runtime while the IPC socket is bound but
    // not yet serving.
    let state_dir_routes = state_dir.to_path_buf();
    if let Err(e) = tokio::task::spawn_blocking(move || crate::routing::recover_routes(&state_dir_routes)).await {
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
