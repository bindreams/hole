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
//! - `--release-event <name>`: on STOP, hold until the named event is signalled,
//!   then report STOPPED.
//! - `--on-stop <stop-pending|stay-running>`: what the held service reports on
//!   STOP. With `--release-event`, `stop-pending` (the default) reports
//!   STOP_PENDING; `stay-running`, or no release event, makes that report fail,
//!   so the service still reports RUNNING with STOP accepted. The control handler is the bridge's own
//!   (`platform::os::register_stop_handler`); only the report and the control
//!   log are the helper's.
//! - `--hold-start <event>`: after attaching to the SCM, report START_PENDING
//!   and hold there until the named event is signalled, then report RUNNING.
//! - `--delay-attach <event>`: before attaching to the SCM at all, hold until
//!   the named event is signalled. The SCM has created the process and is
//!   waiting for it, so the service reads START_PENDING with nothing attached.
//!   The SCM gives up on a process that never attaches (~30 s), so signal it
//!   promptly.
//! - `--pid-log <path>`: append this process's id to `<path>` at start, one per
//!   line, so a test can tell afterwards whether any process the service ran is
//!   still alive.
//! - `--sid-repair-log <path>`: before reporting RUNNING, run the bridge's own
//!   startup repairs (`platform::os::registration::run_startup_repairs`, the
//!   function `run_service` calls) and append the SID type repair's outcome
//!   (`Applied`, `AlreadySet`, or `Failed: <cause>`) to `<path>`, one line per
//!   start. Without the flag the helper never touches the SID type, so the
//!   tests that need a service without one keep it.
//! - `--parked-event <event>`: signalled once the process is parked by one of
//!   the two flags above, so a test can tell the hold is in force without
//!   guessing at timing.
//! - `--crash-on-first-stop <marker>`: on the first Stop any instance of the
//!   service takes, create `<marker>` and exit without reporting STOPPED, so
//!   the SCM sees the service fail and applies its failure actions. Later
//!   instances (the marker exists) stop as usual.
//! - `--running-event <event>`: signalled right after the service reports
//!   RUNNING, once per start. A test that resets it before it kills the service
//!   learns the SCM's restarted instance is up from the signal.
//!
//! A first argument of `--scan-sid` makes this a one-shot scanner instead of a
//! service: `--scan-sid <service> <out-file> [done-event]` looks for the
//! processes whose token carries `NT SERVICE\<service>`, as the uninstaller's
//! hold does, writes what it measured to `<out-file>` and signals `done-event`
//! (when given) whichever way it ended. A test runs it as itself and as
//! LocalSystem (a scheduled task) to measure what each caller can read.

#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::path::PathBuf;

/// What the held service reports to the SCM when it takes a Stop.
#[cfg(target_os = "windows")]
#[derive(Default, Clone, Copy)]
enum OnStop {
    #[default]
    ReportStopPending,
    StayRunning,
}

#[cfg(target_os = "windows")]
impl OnStop {
    fn reports_stop_pending(self) -> bool {
        match self {
            OnStop::ReportStopPending => true,
            OnStop::StayRunning => false,
        }
    }
}

#[cfg(target_os = "windows")]
#[derive(Default)]
struct Args {
    control_log: Option<PathBuf>,
    release_event: Option<String>,
    on_stop: OnStop,
    hold_start: Option<String>,
    delay_attach: Option<String>,
    parked_event: Option<String>,
    running_event: Option<String>,
    crash_on_first_stop: Option<PathBuf>,
    pid_log: Option<PathBuf>,
    sid_repair_log: Option<PathBuf>,
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
            Some("--pid-log") => args.pid_log = Some(PathBuf::from(value)),
            Some("--sid-repair-log") => args.sid_repair_log = Some(PathBuf::from(value)),
            Some("--crash-on-first-stop") => args.crash_on_first_stop = Some(PathBuf::from(value)),
            Some("--hold-start") => args.hold_start = Some(value.into_string().expect("event name is UTF-8")),
            Some("--parked-event") => args.parked_event = Some(value.into_string().expect("event name is UTF-8")),
            Some("--running-event") => args.running_event = Some(value.into_string().expect("event name is UTF-8")),
            Some("--delay-attach") => args.delay_attach = Some(value.into_string().expect("event name is UTF-8")),
            Some("--on-stop") => {
                args.on_stop = match value.to_str() {
                    Some("stop-pending") => OnStop::ReportStopPending,
                    Some("stay-running") => OnStop::StayRunning,
                    _ => panic!("unknown --on-stop value {value:?}"),
                }
            }
            _ => panic!("unknown flag {flag:?}"),
        }
    }
    args
}

#[cfg(target_os = "windows")]
#[path = "test_service/scan.rs"]
mod scan;

#[cfg(target_os = "windows")]
fn main() -> Result<(), windows_service::Error> {
    let mut raw = std::env::args_os().skip(1).peekable();
    if raw.peek().is_some_and(|first| first == "--scan-sid") {
        raw.next();
        scan::run(raw);
        return Ok(());
    }
    ARGS.set(parse_args(std::env::args_os().skip(1))).ok();
    let args = ARGS.get().expect("set above");
    if let Some(path) = &args.pid_log {
        use std::io::Write;
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open the pid log");
        writeln!(log, "{}", std::process::id()).expect("write the pid log");
    }
    if let Some(name) = args.delay_attach.as_deref() {
        park_until(args.parked_event.as_deref(), name);
    }
    windows_service::service_dispatcher::start(hole_bridge::platform::os::SERVICE_NAME, ffi_service_main)
}

/// Signals `parked` (when given), then blocks until `release` is signalled.
/// A bad event name panics, which fails the start.
#[cfg(target_os = "windows")]
fn park_until(parked: Option<&str>, release: &str) {
    use windows::core::HSTRING;
    use windows::Win32::System::Threading::{
        OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE, INFINITE, SYNCHRONIZATION_SYNCHRONIZE,
    };

    // SAFETY: plain FFI calls; each name is a valid HSTRING that outlives its
    // call, and each handle is the live one just opened.
    unsafe {
        let release =
            OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, false, &HSTRING::from(release)).expect("open the release event");
        if let Some(parked) = parked {
            let parked = OpenEventW(EVENT_MODIFY_STATE, false, &HSTRING::from(parked)).expect("open the parked event");
            SetEvent(parked).expect("signal the parked event");
        }
        WaitForSingleObject(release, INFINITE);
    }
}

/// Signals the named event. A bad event name panics.
#[cfg(target_os = "windows")]
fn signal(event: &str) {
    use windows::core::HSTRING;
    use windows::Win32::System::Threading::{OpenEventW, SetEvent, EVENT_MODIFY_STATE};

    // SAFETY: plain FFI calls; the name is a valid HSTRING that outlives its
    // call, and the handle is the live one just opened.
    unsafe {
        let event = OpenEventW(EVENT_MODIFY_STATE, false, &HSTRING::from(event)).expect("open the event to signal");
        SetEvent(event).expect("signal the event");
    }
}

#[cfg(target_os = "windows")]
windows_service::define_windows_service!(ffi_service_main, service_main);

#[cfg(target_os = "windows")]
fn service_main(_arguments: Vec<OsString>) {
    use std::io::Write;
    use std::sync::Mutex;
    use std::time::Duration;
    use windows::core::HSTRING;
    use windows::Win32::System::Threading::{OpenEventW, WaitForSingleObject, INFINITE, SYNCHRONIZATION_SYNCHRONIZE};
    use windows_service::service::{ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};

    use hole_bridge::platform::os::{register_stop_handler, report_stop_pending, RegisteredStop};
    use hole_bridge::service_ctrl::{Control, StatusHandle};

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

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let report_stop_pending_to_scm = release.is_some() && args.on_stop.reports_stop_pending();
    let send = move |handle: &StatusHandle, phase| {
        if report_stop_pending_to_scm {
            report_stop_pending(handle, phase)
        } else {
            Err(std::io::Error::other("this service does not report StopPending"))
        }
    };
    let control_log = args.control_log.clone();
    let observe = move |control: Control| {
        if let Some(path) = &control_log {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("open the control log");
            writeln!(file, "{control:?}").expect("write the control log");
        }
    };

    let Ok(RegisteredStop { status_handle, .. }) = register_stop_handler(Mutex::new(Some(stop_tx)), send, observe)
    else {
        return;
    };
    if let Some(path) = &args.sid_repair_log {
        let line = match hole_bridge::platform::os::registration::run_startup_repairs().service_sid {
            Ok(outcome) => format!("{outcome:?}"),
            Err(e) => format!("Failed: {e}"),
        };
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open the sid repair log");
        writeln!(log, "{line}").expect("write the sid repair log");
    }
    if let Some(name) = &args.hold_start {
        if status_handle
            .set_service_status(&report(
                ServiceState::StartPending,
                ServiceControlAccept::empty(),
                1,
                Duration::from_secs(60),
            ))
            .is_err()
        {
            return;
        }
        park_until(args.parked_event.as_deref(), name);
    }
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
    if let Some(name) = args.running_event.as_deref() {
        signal(name);
    }
    let _ = stop_rx.blocking_recv(); // park until SCM sends STOP
    if let Some(marker) = &args.crash_on_first_stop {
        // `create_new` fails once the marker exists, so only one instance crashes.
        if std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(marker)
            .is_ok()
        {
            std::process::exit(1);
        }
    }
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
