// Windows: service management via windows-service crate.

use std::ffi::OsString;
use std::time::Duration;
use tracing::{error, info};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

// Constants =====

pub const SERVICE_NAME: &str = "HoleDaemon";
pub const SERVICE_DISPLAY_NAME: &str = "Hole Daemon";
pub const SERVICE_DESCRIPTION: &str = "Transparent proxy daemon for the Hole application";

// Service entry =====

/// Register and run as a Windows Service.
/// Called from main() when running as a service.
pub fn run_as_service() -> Result<(), windows_service::Error> {
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
    rt.block_on(async {
        let proxy = std::sync::Arc::new(tokio::sync::Mutex::new(crate::proxy_manager::ProxyManager::new(
            crate::proxy_manager::RealBackend,
        )));
        let proxy_shutdown = std::sync::Arc::clone(&proxy);

        let server = crate::ipc::IpcServer::bind(crate::ipc::SOCKET_NAME, proxy).expect("failed to bind IPC socket");

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
    });

    // Report stopped
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    })?;

    Ok(())
}

// Install/uninstall =====

/// Install the daemon as a Windows Service.
pub fn install_service(binary_path: &std::path::Path) -> Result<(), windows_service::Error> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: binary_path.to_path_buf(),
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let _service = manager.create_service(&service_info, ServiceAccess::empty())?;
    info!("Windows service installed");
    Ok(())
}

/// Uninstall the daemon Windows Service.
pub fn uninstall_service() -> Result<(), windows_service::Error> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;
    info!("Windows service uninstalled");
    Ok(())
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
