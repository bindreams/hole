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
/// Used by `netsh trace` ETL to land the capture file alongside
/// `bridge.log` in the same directory.
static LOG_DIR_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Run as a Windows Service (called by the service control manager).
pub fn run(socket_path: &Path, state_dir: &Path, log_dir: &Path) -> Result<(), windows_service::Error> {
    let default = hole_common::protocol::default_bridge_socket_path();
    if socket_path != default {
        SOCKET_PATH_OVERRIDE.set(socket_path.to_owned()).ok();
    }
    STATE_DIR_OVERRIDE.set(state_dir.to_owned()).ok();
    LOG_DIR_OVERRIDE.set(log_dir.to_owned()).ok();
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
        let server = crate::ipc::IpcServer::bind(&socket_path, proxy)?;
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

        // Capture WFP + NDIS state after recovery. See #200 and
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

        // Clean shutdown: stop proxy before exiting
        let mut pm = proxy_shutdown.lock().await;
        if let Err(e) = pm.stop().await {
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

// Install/uninstall ===================================================================================================

/// System log directory for the Windows service (`C:\ProgramData\hole\logs`).
fn service_log_dir() -> PathBuf {
    PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
        .join("hole")
        .join("logs")
}

/// System state directory for the Windows service (`C:\ProgramData\hole\state`).
///
/// Used for the route-recovery state file (`bridge-routes.json`). Writable by
/// LocalSystem; pre-created by `install()` so the service has somewhere to
/// write on its first run.
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

/// Send a stop control to the service and wait for it to stop (up to 10s).
pub fn stop() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;

    // Check current state before sending stop
    let status = service.query_status()?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }

    service.stop()?;
    info!("stop signal sent, waiting for service to stop");

    // Poll until stopped or timeout
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let status = service.query_status()?;
        if status.current_state == ServiceState::Stopped {
            info!("Windows service stopped");
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            return Err(format!("service did not stop within 10s (state: {:?})", status.current_state).into());
        }
    }
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

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
