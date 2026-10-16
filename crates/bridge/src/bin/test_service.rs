//! Windows service helper for the privileged SCM tests
//! (`tests/cutover_privileged.rs`). It is a GENUINE SCM service — it reports
//! RUNNING on start and STOPPED when SCM sends STOP — but does nothing else (no
//! IPC, no TUN), so the tests can drive the REAL `scm_wait`
//! `NotifyServiceStatusChange` restart sequence against a real service without
//! the full Hole bridge. The test self-provisions a `HoleBridge` service pointing
//! here and tears it down, so this helper owns no install/uninstall logic.
//!
//! Optional arguments (the service's ImagePath) for the control-delivery test:
//! - `--control-log <path>`: append the `Debug` form of every control the
//!   handler receives to `<path>`, one per line, before the handler returns.
//! - `--release-event <name>`: on STOP, report STOP_PENDING and hold there until
//!   the named event is signalled, then report STOPPED.

#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[cfg(target_os = "windows")]
#[derive(Default)]
struct Args {
    control_log: Option<PathBuf>,
    release_event: Option<String>,
}

#[cfg(target_os = "windows")]
static ARGS: std::sync::OnceLock<Args> = std::sync::OnceLock::new();

#[cfg(target_os = "windows")]
fn parse_args(mut raw: impl Iterator<Item = OsString>) -> Args {
    let mut args = Args::default();
    while let Some(flag) = raw.next() {
        let value = raw.next().expect("every flag takes a value");
        match flag.to_str() {
            Some("--control-log") => args.control_log = Some(PathBuf::from(value)),
            Some("--release-event") => args.release_event = Some(value.into_string().expect("event name is UTF-8")),
            _ => panic!("unknown flag {flag:?}"),
        }
    }
    args
}

#[cfg(target_os = "windows")]
fn main() -> Result<(), windows_service::Error> {
    ARGS.set(parse_args(std::env::args_os().skip(1))).ok();
    windows_service::service_dispatcher::start(hole_bridge::platform::os::SERVICE_NAME, ffi_service_main)
}

#[cfg(target_os = "windows")]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(target_os = "windows")]
fn service_main(_arguments: Vec<OsString>) {
    use std::io::Write;
    use std::sync::{mpsc, Arc, Mutex, OnceLock};
    use std::time::Duration;
    use windows::core::HSTRING;
    use windows::Win32::System::Threading::{OpenEventW, WaitForSingleObject, INFINITE, SYNCHRONIZATION_SYNCHRONIZE};
    use windows_service::service::{ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};

    use hole_bridge::service_ctrl::{self, Control, StatusHandle};

    let args = ARGS.get().expect("set in main");
    let report = |state, accepts, checkpoint, wait_hint| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepts,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint,
        wait_hint,
        process_id: None,
    };

    // Opened before registering, so a bad name fails the start.
    let release = args.release_event.as_ref().map(|name| {
        // SAFETY: plain FFI call; the name is a valid HSTRING that outlives it.
        unsafe { OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, false, &HSTRING::from(name.as_str())) }
            .expect("open the release event")
    });

    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let stop_tx = Mutex::new(Some(stop_tx));
    // The handler runs on an SCM thread, and the status handle only exists once
    // `register` returns; no Stop arrives before RUNNING, which is reported after.
    let status_cell: Arc<OnceLock<StatusHandle>> = Arc::new(OnceLock::new());
    let handler_status = Arc::clone(&status_cell);
    let hold = release.is_some();
    let control_log = args.control_log.clone();
    let event_handler = move |control: Control| {
        if let Some(path) = &control_log {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("open the control log");
            writeln!(file, "{control:?}").expect("write the control log");
        }
        control.handle(|| {
            if hold {
                if let Some(handle) = handler_status.get() {
                    let _ = handle.set_service_status(&report(
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        1,
                        Duration::from_secs(60),
                    ));
                }
            }
            if let Ok(mut guard) = stop_tx.lock() {
                if let Some(tx) = guard.take() {
                    let _ = tx.send(());
                }
            }
        })
    };

    let Ok(status_handle) = service_ctrl::register(hole_bridge::platform::os::SERVICE_NAME, event_handler) else {
        return;
    };
    let _ = status_cell.set(status_handle);
    if status_handle
        .set_service_status(&report(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
            Duration::ZERO,
        ))
        .is_err()
    {
        return;
    }
    let _ = stop_rx.recv(); // park until SCM sends STOP
    if let Some(release) = release {
        // SAFETY: `release` is the live event handle opened above.
        unsafe { WaitForSingleObject(release, INFINITE) };
    }
    let _ = status_handle.set_service_status(&report(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        0,
        Duration::ZERO,
    ));
}

#[cfg(not(target_os = "windows"))]
fn main() {}
