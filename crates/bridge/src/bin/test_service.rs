//! No-op Windows service helper for the privileged SCM-restart test
//! (`tests/cutover_privileged.rs`). It is a GENUINE SCM service — it reports
//! RUNNING on start and STOPPED when SCM sends STOP — but does nothing else (no
//! IPC, no TUN), so the test can drive the REAL `scm_wait`
//! `NotifyServiceStatusChange` restart sequence against a real service without
//! the full Hole bridge. The test self-provisions a `HoleBridge` service pointing
//! here and tears it down, so this helper owns no install/uninstall logic.

#[cfg(target_os = "windows")]
fn main() -> Result<(), windows_service::Error> {
    windows_service::service_dispatcher::start(hole_bridge::platform::os::SERVICE_NAME, ffi_service_main)
}

#[cfg(target_os = "windows")]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(target_os = "windows")]
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    use std::sync::mpsc;
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let stop_tx = std::sync::Mutex::new(Some(stop_tx));
    let event_handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Ok(mut guard) = stop_tx.lock() {
                if let Some(tx) = guard.take() {
                    let _ = tx.send(());
                }
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };

    let Ok(status_handle) = service_control_handler::register(hole_bridge::platform::os::SERVICE_NAME, event_handler)
    else {
        return;
    };
    let report = |state, accepts| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepts,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    };
    if status_handle
        .set_service_status(report(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ))
        .is_err()
    {
        return;
    }
    let _ = stop_rx.recv(); // park until SCM sends STOP
    let _ = status_handle.set_service_status(report(ServiceState::Stopped, ServiceControlAccept::empty()));
}

#[cfg(not(target_os = "windows"))]
fn main() {}
