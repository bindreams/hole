// Windows: service management via windows-service crate.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use tracing::{error, info};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

// Constants ===========================================================================================================

pub const SERVICE_NAME: &str = "HoleBridge";
pub const SERVICE_DISPLAY_NAME: &str = "Hole Bridge";
pub const SERVICE_DESCRIPTION: &str = "Transparent proxy bridge for the Hole application";

// Service entry =======================================================================================================

/// Socket path override set by the CLI before service dispatch.
static SOCKET_PATH_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();
/// State directory override set by the CLI before service dispatch.
static STATE_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();
/// Log directory override set by the CLI before service dispatch.
/// Used by diagnostic artefacts to land alongside `bridge.log` in the
/// same directory.
static LOG_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();
/// GUI build version override set by the CLI before service dispatch. The
/// `bind` runs inside `service_main` (a SCM callback with no access to
/// `run`'s args), so the version is threaded through this static.
static VERSION_OVERRIDE: OnceLock<String> = OnceLock::new();

/// Run as a Windows Service (called by the service control manager).
pub fn run(socket_path: &Path, state_dir: &Path, log_dir: &Path, version: &str) -> Result<(), windows_service::Error> {
    let default = hole_common::protocol::default_bridge_socket_path();
    if socket_path != default {
        SOCKET_PATH_OVERRIDE.set(socket_path.to_owned()).ok();
    }
    STATE_DIR_OVERRIDE.set(state_dir.to_owned()).ok();
    LOG_DIR_OVERRIDE.set(log_dir.to_owned()).ok();
    VERSION_OVERRIDE.set(version.to_owned()).ok();
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!(error = %e, "service failed");
    }
}

fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = std::sync::Mutex::new(Some(shutdown_tx));

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Ok(mut guard) = shutdown_tx.lock() {
                    if let Some(tx) = guard.take() {
                        let _ = tx.send(());
                    }
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Report running
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;

    info!("Windows service started");

    // Build and run the tokio runtime
    let rt = tokio::runtime::Runtime::new()?;
    let run_result: Result<(), Box<dyn std::error::Error>> = rt.block_on(async {
        let state_dir = STATE_DIR_OVERRIDE
            .get()
            .cloned()
            .unwrap_or_else(hole_common::paths::default_state_dir);
        let log_dir = LOG_DIR_OVERRIDE.get().cloned().unwrap_or_else(service_log_dir);
        let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::proxy_manager::ProxyManager::new(
                crate::proxy::ShadowsocksProxy::new(),
                tun_engine::routing::SystemRouting::new(state_dir.clone()),
            )
            .with_state_dir(state_dir.clone()),
        ));
        let proxy_shutdown = std::sync::Arc::clone(&proxy);

        let socket_path = SOCKET_PATH_OVERRIDE
            .get()
            .cloned()
            .unwrap_or_else(hole_common::protocol::default_bridge_socket_path);
        // Bind BEFORE recovery — a second instance's bind() fails before it
        // can touch routing state. Route recovery is offloaded via
        // spawn_blocking so a hung netsh/route command cannot wedge the
        // runtime while the IPC socket is bound but not yet serving.
        let version = VERSION_OVERRIDE.get().cloned().unwrap_or_else(|| "unknown".to_string());
        let server =
            crate::ipc::IpcServer::bind_with_dirs(&socket_path, proxy, &version, log_dir.clone(), state_dir.clone())?;
        // DNS recovery runs first; see crate::dns::recovery docs for ordering.
        let state_dir_for_dns = state_dir.clone();
        if let Err(e) =
            tokio::task::spawn_blocking(move || crate::dns::recovery::recover_dns_config(&state_dir_for_dns)).await
        {
            tracing::warn!(error = %e, "recover_dns_config task panicked");
        }
        let state_dir_for_recover = state_dir.clone();
        if let Err(e) =
            tokio::task::spawn_blocking(move || tun_engine::routing::recover_routes(&state_dir_for_recover)).await
        {
            tracing::warn!(error = %e, "recover_routes task panicked");
        }
        let state_dir_for_plugins = state_dir.clone();
        if let Err(e) =
            tokio::task::spawn_blocking(move || crate::plugin_recovery::recover_plugins(&state_dir_for_plugins)).await
        {
            tracing::warn!(error = %e, "recover_plugins task panicked");
        }
        // Native-crash observability (bindreams/hole#438): sweep crash
        // markers left by a previously-crashed service bridge. Markers land
        // in the service log dir (C:\ProgramData\hole\logs), NOT state_dir.
        let log_dir_sweep = log_dir.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || tombstone::sweep(&log_dir_sweep)).await {
            tracing::warn!(error = %e, "crash sweep task panicked");
        }
        // The new bridge is authoritative once it has bound: any update marker is
        // a completed cutover, so clear it unconditionally (remove-by-path).
        let log_dir_marker = log_dir.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || sweep_marker(&log_dir_marker)).await {
            tracing::warn!(error = %e, "marker sweep task panicked");
        }

        // Capture WFP + NDIS state after recovery; see
        // `diagnostics::{wfp,ndis}`.
        if let Err(e) = tokio::task::spawn_blocking(|| crate::diagnostics::wfp::log_snapshot("startup")).await {
            tracing::warn!(error = %e, "wfp startup snapshot task panicked");
        }
        if let Err(e) = tokio::task::spawn_blocking(|| crate::diagnostics::ndis::log_snapshot("startup")).await {
            tracing::warn!(error = %e, "ndis startup snapshot task panicked");
        }

        // Always-on ETW consumer. Held for the service's run lifetime;
        // Drop stops the session and joins the processing thread.
        let _etw_guard = match crate::diagnostics::etw::start_consumer() {
            Ok(g) => Some(g),
            Err(e) => {
                tracing::error!(error = %e, "etw consumer failed to start");
                None
            }
        };

        tokio::select! {
            result = server.run() => {
                if let Err(e) = result {
                    error!(error = %e, "IPC server error");
                }
            }
            _ = shutdown_rx => {
                info!("shutdown signal received");
            }
        }

        // Clean shutdown: stop proxy before exiting. A cutover-driven shutdown
        // (marker present) disarms the standing cover so the persistent WFP
        // filters survive the restart; an ordinary stop disengages it.
        let mut pm = proxy_shutdown.lock().await;
        let reason = shutdown_reason(hole_common::update_marker::read(&log_dir).is_some());
        if let Err(e) = pm.stop_with(reason).await {
            error!(error = %e, "error stopping proxy during shutdown");
        }

        Ok(())
    });

    if let Err(e) = &run_result {
        error!(error = %e, "bridge runtime error");
    }

    // Always report stopped to SCM, even on error.
    // Use a non-zero exit code if the runtime failed.
    let exit_code = if run_result.is_err() { 1 } else { 0 };
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    });

    run_result
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
pub(crate) fn sweep_marker(log_dir: &Path) {
    if let Err(e) = hole_common::update_marker::clear(log_dir) {
        tracing::warn!(error = %e, "failed to clear update-in-progress marker");
    }
}

// Install/uninstall ===================================================================================================

/// System log directory for the Windows service (`C:\ProgramData\hole\logs`).
/// Deduped to the single cross-privilege resolver the GUI also reads from.
fn service_log_dir() -> PathBuf {
    hole_common::update_marker::service_log_dir()
}

/// System state directory for the Windows service (`C:\ProgramData\hole\state`).
///
/// Holds the bridge crash-recovery state files (`bridge-dns.json`,
/// `bridge-routes.json`, `bridge-plugins.json`). Writable by LocalSystem;
/// pre-created by `install()` so the service has somewhere to write on its
/// first run.
fn service_state_dir() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
        .join("hole")
        .join("state")
}

/// Install the bridge as a Windows Service.
///
/// The service is registered to run
/// `<binary_path> bridge run --service --log-dir <log> --state-dir <state>`
/// with auto-start.
pub fn install(binary_path: &Path) -> Result<(), windows_service::Error> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;

    let log_dir = service_log_dir();
    let state_dir = service_state_dir();
    // Create log + state dirs during install (running elevated) so the service
    // itself (running as LocalSystem) can write to them on its first run.
    let _ = std::fs::create_dir_all(&log_dir);
    let _ = std::fs::create_dir_all(&state_dir);

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: binary_path.to_path_buf(),
        launch_arguments: vec![
            "bridge".into(),
            "run".into(),
            "--service".into(),
            "--log-dir".into(),
            log_dir.into_os_string(),
            "--state-dir".into(),
            state_dir.into_os_string(),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;

    service.set_description(SERVICE_DESCRIPTION)?;
    info!("Windows service installed");
    Ok(())
}

/// Stop and uninstall the bridge Windows Service.
pub fn uninstall() -> Result<(), windows_service::Error> {
    // Stop first (ignore errors — service may not be running)
    let _ = stop();

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;
    info!("Windows service uninstalled");
    Ok(())
}

// Start/stop ==========================================================================================================

/// Start the Windows Service via SCM.
pub fn start() -> Result<(), windows_service::Error> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start::<&str>(&[])?;
    info!("Windows service started");
    Ok(())
}

/// Send a stop control to the service and wait until it is really stopped via
/// `NotifyServiceStatusChangeW` — a kernel rendezvous on the STOPPED transition,
/// not a sleep-poll. Returns immediately when already stopped.
pub fn stop() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)?;
    if service.query_status()?.current_state == ServiceState::Stopped {
        return Ok(());
    }
    drop(service);

    info!("stop signal sent, waiting for service to stop");
    let mut actor = crate::cutover::scm_wait::SystemScmActor::open(SERVICE_NAME)?;
    crate::cutover::scm_wait::stop_via_notify(&mut actor)?;
    info!("Windows service stopped");
    Ok(())
}

// Query ===============================================================================================================

/// Check whether the service is registered in SCM.
pub fn is_installed() -> bool {
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
        return false;
    };
    manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).is_ok()
}

/// Check whether the service is registered and currently running.
pub fn is_running() -> bool {
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
        return false;
    };
    let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) else {
        return false;
    };
    let Ok(status) = service.query_status() else {
        return false;
    };
    status.current_state == ServiceState::Running
}

/// A valid marker for the post-bind-sweep test.
#[cfg(test)]
fn test_marker() -> hole_common::update_marker::MarkerInfo {
    hole_common::update_marker::MarkerInfo {
        version: hole_common::update_marker::MARKER_VERSION,
        from_version: "0.2.0".into(),
        to_version: "0.3.0".into(),
        pid: 1,
        started_at_unix: 0,
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
