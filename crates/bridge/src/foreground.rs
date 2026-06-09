//! Foreground bridge runner for development.

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
/// `log_dir` is the same directory that the global tracing subscriber
/// writes `bridge.log` into — so all bridge-owned files land in one
/// place and the CI artifact-upload step can glob for them.
pub fn run(socket_path: &Path, state_dir: &Path, log_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_inner(socket_path, state_dir, log_dir))
}

/// Resolve when a shutdown signal arrives: Ctrl+C (SIGINT) everywhere, or
/// SIGTERM on Unix. dev.py terminates the bridge with SIGTERM (relayed
/// through sudo); without a SIGTERM handler the bridge would die on the
/// default disposition and leak routes/DNS (bindreams/hole#452).
///
/// Returns a future but installs the SIGTERM handler EAGERLY when called
/// (not lazily on first poll), so a caller that raises SIGTERM immediately
/// after still observes it. Must be called within a Tokio runtime — it is,
/// from `run_inner` and the test's `block_on`.
// On non-unix the `#[cfg(unix)] let sigterm = …` line below is cfg'd out,
// leaving a bare `async move` body, so clippy's `manual_async_fn` suggests
// `async fn`. But on unix the function MUST stay `fn -> impl Future` so the
// SIGTERM handler installs eagerly (before the future is first polled). Keep
// one shape across platforms and silence the lint only where it misfires.
#[cfg_attr(not(unix), allow(clippy::manual_async_fn))]
fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    #[cfg(unix)]
    let sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    async move {
        #[cfg(unix)]
        match sigterm {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => tracing::info!("shutdown signal (SIGINT) received"),
                    _ = sigterm.recv() => tracing::info!("shutdown signal (SIGTERM) received"),
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler; Ctrl+C only");
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("shutdown signal (SIGINT) received");
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal (Ctrl+C) received");
        }
    }
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

    // DNS recovery runs *before* route recovery. Rationale: mid-recovery
    // crash leaves the user with functional DNS + broken routes (easier
    // diagnosis path) instead of broken DNS + functional routes. See
    // crate::dns::recovery module docs.
    let state_dir_dns = state_dir.to_path_buf();
    if let Err(e) = tokio::task::spawn_blocking(move || crate::dns::recovery::recover_dns_config(&state_dir_dns)).await
    {
        tracing::warn!(error = %e, "recover_dns_config task panicked");
    }

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
    // DEBUG detail (gated).
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

    // Native-crash observability (bindreams/hole#438): report + delete any
    // crash marker a previously-crashed bridge left in log_dir. Offloaded to
    // a blocking thread to match the sibling recover_* calls (it is pure file
    // I/O — no netsh/route hazard — but spawn_blocking keeps the pattern
    // uniform and off the runtime worker). The marker is written next to
    // bridge.log, NOT in state_dir.
    let log_dir_sweep = log_dir.to_path_buf();
    if let Err(e) = tokio::task::spawn_blocking(move || tombstone::sweep(&log_dir_sweep)).await {
        tracing::warn!(error = %e, "crash sweep task panicked");
    }

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "IPC server error");
            }
        }
        _ = shutdown_signal() => {}
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
