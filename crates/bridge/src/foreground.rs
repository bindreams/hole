// Foreground bridge runner for development.

use std::path::Path;

use tun_engine::routing::{self, SystemRouting};

use crate::proxy::ShadowsocksProxy;
use crate::proxy_manager::ProxyManager;

/// Run the bridge in foreground mode (for development).
///
/// Bypasses the platform service manager and shuts down on Ctrl+C. Uses
/// the production `IpcServer::bind` + `apply_socket_permissions` path, so
/// dev exercises the real DACL/group/SDDL code — see the `dev.py` /
/// `bridge grant-access` orchestration. Requires elevation for TUN +
/// routing.
///
/// `log_dir` is used as the destination for diagnostic artefacts (e.g.
/// the `netsh trace` ETL on Windows). It is the same directory that the
/// global tracing subscriber writes `bridge.log` into — so all
/// bridge-owned files land in one place and the CI artifact-upload step
/// can glob for them.
pub fn run(socket_path: &Path, state_dir: &Path, log_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_inner(socket_path, state_dir, log_dir))
}

async fn run_inner(socket_path: &Path, state_dir: &Path, log_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
    if let Err(e) = tokio::task::spawn_blocking(move || routing::recover_routes(&state_dir_routes)).await {
        tracing::warn!(error = %e, "recover_routes task panicked");
    }
    let state_dir_plugins = state_dir.to_path_buf();
    if let Err(e) =
        tokio::task::spawn_blocking(move || crate::plugin_recovery::recover_plugins(&state_dir_plugins)).await
    {
        tracing::warn!(error = %e, "recover_plugins task panicked");
    }

    // Capture WFP + NDIS state after recovery has had a chance to clean
    // up. Each probe emits a one-line INFO (always) + WARN on anomaly +
    // DEBUG detail (gated). See #200.
    #[cfg(target_os = "windows")]
    {
        if let Err(e) = tokio::task::spawn_blocking(|| crate::diagnostics::wfp::log_snapshot("startup")).await {
            tracing::warn!(error = %e, "wfp startup snapshot task panicked");
        }
        if let Err(e) = tokio::task::spawn_blocking(|| crate::diagnostics::ndis::log_snapshot("startup")).await {
            tracing::warn!(error = %e, "ndis startup snapshot task panicked");
        }
    }

    // Start the always-on ETW consumer. Held for the server's lifetime;
    // Drop stops the session and joins the processing thread. Failure
    // logs at error (not warn) — a silent ETW-broken customer machine
    // is the opposite of the diagnostic goal. See diagnostics::etw.
    #[cfg(target_os = "windows")]
    let _etw_guard = match crate::diagnostics::etw::start_consumer() {
        Ok(g) => Some(g),
        Err(e) => {
            tracing::error!(error = %e, "etw consumer failed to start");
            None
        }
    };

    // Start the netsh-trace ETL capture (packet-level wire capture
    // scoped to this process). Dropped alongside `_etw_guard`. Requires
    // admin elevation — in CI the bridge child inherits the runneradmin
    // token; on local dev without elevation this fails and we continue.
    #[cfg(target_os = "windows")]
    let _netsh_trace_guard = match crate::diagnostics::netsh_trace::start(log_dir) {
        Ok(g) => Some(g),
        Err(e) => {
            tracing::error!(error = %e, "netsh trace capture failed to start");
            None
        }
    };
    #[cfg(not(target_os = "windows"))]
    let _ = log_dir; // suppress unused warning on non-Windows builds

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
