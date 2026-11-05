//! Probe P1 of the service-retirement design: does the SCM's own recovery
//! restart start a service whose start type is DISABLED?
//!
//! Microsoft's `ChangeServiceConfig2W` Remarks already answer it ("A queued
//! restart action cannot be canceled ... The service must be explicitly
//! disabled to prevent it from restarting"). This probe can only FALSIFY that
//! answer: a restart that happens is read off a positive event (the service's
//! start count, its state), while a restart that does not happen has no event
//! to read, and no verdict below claims one from the absence.
//!
//! Two services, S (disabled) and C (the control), run the same helper with a
//! restart-on-failure action. S is crashed, then C. C's restarted instance
//! signals an event, and that event, not a delay, is what the test waits for:
//! it bounds the read of S from above, because S's action was due well before
//! C's: C is killed only after S's queued restart was read off the log, so C's
//! is due `C_RESTART_DELAY` after that read and S's `S_RESTART_DELAY` after the
//! SCM queued it. S's disable is written either while its restart is queued
//! (variant `queued`) or before the crash (variant `running`).
//!
//! The `queued` variant needs the disable to land before the SCM's restart
//! timer fires, which the test cannot guarantee: only the SCM runs that timer.
//! S's state is read just BEFORE the disable is written: S not STOPPED then
//! means the restart had already fired, so the attempt is abandoned and rerun
//! on fresh services, never reported as a verdict. A restart after that read
//! counts as a restart of a disabled service and fails loudly, even if it fell
//! in the instant before the disable; the RESULT line carries the state before
//! and after the disable and the SCM's entries for S, which tell the two apart.

use std::ffi::OsString;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    ChangeServiceConfigW, ENUM_SERVICE_TYPE, SC_HANDLE, SERVICE_DISABLED, SERVICE_ERROR, SERVICE_NO_CHANGE,
    SERVICE_START_TYPE,
};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::named_event::NamedEvent;
use super::{scm_deletion, scm_probe, GLOBAL_NET_STATE, TUN};

/// How long the SCM waits before it restarts S, and C. C's is the longer, and C
/// is killed only after the read of S's queued restart, so S's action is due
/// well before the control's restart is up. S's must outlast the event-log read
/// before the disable (measured ~6 s on a loaded runner); a loss is rerun, not
/// failed.
const S_RESTART_DELAY: Duration = Duration::from_secs(30);
const C_RESTART_DELAY: Duration = Duration::from_secs(40);

/// A throwaway auto-start service running the helper, under its own name so it
/// can run beside another. Deleted on drop, once its process is gone.
struct ProbeService {
    name: String,
    display_name: String,
    service: Option<Service>,
}

impl ProbeService {
    fn create(name: String, display_name: String, launch_arguments: Vec<OsString>, restart_after: Duration) -> Self {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .expect("open SCM with CREATE_SERVICE (the TUN lane runs elevated)");
        let info = ServiceInfo {
            name: OsString::from(&name),
            display_name: OsString::from(&display_name),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: std::path::PathBuf::from(env!("CARGO_BIN_EXE_test_service")),
            launch_arguments,
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let service = manager
            .create_service(
                &info,
                ServiceAccess::START
                    | ServiceAccess::STOP
                    | ServiceAccess::QUERY_STATUS
                    | ServiceAccess::QUERY_CONFIG
                    | ServiceAccess::DELETE
                    | ServiceAccess::CHANGE_CONFIG,
            )
            .unwrap_or_else(|e| panic!("create the probe service {name} (a leftover of a killed run?): {e}"));
        service
            .update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
                reboot_msg: None,
                command: None,
                actions: Some(vec![ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: restart_after,
                }]),
            })
            .expect("configure the probe service to restart on failure");
        ProbeService {
            name,
            display_name,
            service: Some(service),
        }
    }

    fn handle(&self) -> &Service {
        self.service.as_ref().expect("the service is open until drop")
    }

    fn start(&self) {
        self.handle().start::<&str>(&[]).expect("start the probe service");
    }

    /// The service's process id, valid while it is RUNNING.
    fn process_id(&self) -> u32 {
        self.handle()
            .query_status()
            .expect("query the probe service")
            .process_id
            .expect("a running service has a process")
    }

    fn state(&self) -> ServiceState {
        self.handle()
            .query_status()
            .expect("query the probe service")
            .current_state
    }

    fn start_type(&self) -> ServiceStartType {
        self.handle()
            .query_config()
            .expect("read the probe service's configuration")
            .start_type
    }

    /// `SERVICE_DISABLED`, and nothing else changed.
    fn disable(&self) {
        // SAFETY: the handle is the live one `handle()` owns; every pointer is
        // null or `None`, which with `SERVICE_NO_CHANGE` leaves that setting alone.
        unsafe {
            ChangeServiceConfigW(
                SC_HANDLE(self.handle().raw_handle()),
                ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                SERVICE_START_TYPE(SERVICE_DISABLED.0),
                SERVICE_ERROR(SERVICE_NO_CHANGE),
                PCWSTR::null(),
                PCWSTR::null(),
                None,
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
                PCWSTR::null(),
            )
        }
        .expect("disable the probe service");
    }
}

impl Drop for ProbeService {
    fn drop(&mut self) {
        let Some(service) = self.service.take() else { return };
        // Nothing may restart it while it is stopped and deleted.
        scm_probe::forbid_restart(&service);
        // Refused when it is not running, which is fine.
        let _ = service.stop();
        if let Err(e) = service.delete() {
            eprintln!(
                "teardown: deleting {} failed (awaiting deletion anyway): {e}",
                self.name
            );
        }
        // A panicking probe leaves the process running; deletion waits on its exit.
        scm_probe::kill_process_of(&service);
        // An open handle keeps the deletion pending.
        drop(service);
        if let Err(e) = scm_deletion::wait_until_deleted(&self.name) {
            eprintln!("teardown: waiting for {} to be deleted failed: {e}", self.name);
        }
    }
}

/// The System event log, for the SCM's own account of what it did to a service.
mod system_log {
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::EventLog::{CloseEventLog, NotifyChangeEventLog, OpenEventLogW};
    use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};

    /// An open System log and an event the log signals when something is
    /// written to it.
    pub struct Watch {
        log: HANDLE,
        written: HANDLE,
    }

    impl Watch {
        pub fn open() -> Self {
            // SAFETY: plain FFI calls; the source name is a valid wide string.
            unsafe {
                let log = OpenEventLogW(PCWSTR::null(), w!("System")).expect("open the System event log");
                let written = CreateEventW(None, false, false, PCWSTR::null()).expect("create the log event");
                NotifyChangeEventLog(log, written).expect("ask the System log to signal writes");
                Watch { log, written }
            }
        }

        /// Returns once `found` is true. `found` reads the log itself; a write
        /// to the log only wakes the next read, and the registration is made
        /// again before each read so a write after it is never missed.
        pub fn wait_until(&self, mut found: impl FnMut() -> bool) {
            loop {
                // SAFETY: both handles are the live ones `self` owns. A failed
                // re-registration only means the first one still stands.
                let _ = unsafe { NotifyChangeEventLog(self.log, self.written) };
                if found() {
                    return;
                }
                // SAFETY: as above.
                unsafe { WaitForSingleObject(self.written, INFINITE) };
            }
        }
    }

    impl Drop for Watch {
        fn drop(&mut self) {
            // SAFETY: both handles are the live ones created in `open`.
            unsafe {
                let _ = CloseEventLog(self.log);
                let _ = CloseHandle(self.written);
            }
        }
    }

    /// One Service Control Manager entry that names a service.
    pub struct Entry {
        pub event_id: u32,
        pub text: String,
    }

    /// The newest Service Control Manager entries whose text contains
    /// `needle`, read with the OS's `wevtutil`.
    pub fn scm_entries_naming(needle: &str) -> Vec<Entry> {
        let out = std::process::Command::new("wevtutil.exe")
            .args([
                "qe",
                "System",
                "/q:*[System[Provider[@Name='Service Control Manager']]]",
                "/c:300",
                "/rd:true",
                "/f:text",
            ])
            .output()
            .expect("run wevtutil.exe");
        assert!(
            out.status.success(),
            "wevtutil failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.split("Event[")
            .filter(|block| block.contains(needle))
            .filter_map(|block| {
                let event_id = block
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("Event ID:"))?
                    .trim()
                    .parse()
                    .ok()?;
                let summary: Vec<&str> = block
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with("Log Name") && !line.starts_with("Source"))
                    .collect();
                Some(Entry {
                    event_id,
                    text: summary.join(" | "),
                })
            })
            .collect()
    }
}

/// How many times the helper logged a start: one line per process.
fn starts_in(pid_log: &std::path::Path) -> usize {
    std::fs::read_to_string(pid_log).unwrap_or_default().lines().count()
}

/// SCM event 7031: the service ended unexpectedly and a corrective action is
/// taken, which the SCM writes once it has queued the restart.
const CORRECTIVE_ACTION_EVENT: u32 = 7031;

/// Where S's disable is written relative to the crash.
#[derive(Clone, Copy)]
enum Variant {
    /// After the crash, while the SCM's restart is queued.
    Queued,
    /// Before the crash.
    Running,
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Variant::Queued => "queued",
            Variant::Running => "running",
        }
    }

    fn disables_before_the_crash(self) -> bool {
        match self {
            Variant::Queued => false,
            Variant::Running => true,
        }
    }

    /// Whether the disable is still to meet the variant's scenario, given S's
    /// state read just before it is written. A `queued` disable meets a queued
    /// restart only if S is still STOPPED, so one that reads otherwise lost the
    /// race with the timer. A `running` disable precedes the crash by
    /// construction: a restarted S there is a restart of a disabled service,
    /// not a lost race.
    fn disable_meets_its_scenario(self, state_before_disable: ServiceState) -> bool {
        match self {
            Variant::Queued => state_before_disable == ServiceState::Stopped,
            Variant::Running => true,
        }
    }
}

/// How one attempt of a probe ended.
enum AttemptOutcome {
    /// The scenario held and the verdict was asserted.
    Measured,
    /// The SCM restarted S before the disable was written; nothing was measured.
    RaceLost {
        /// S's state, read just before the disable was due.
        state_before_disable: ServiceState,
        /// The SCM's log entries naming S, as `scm_entries_dump` writes them.
        scm_entries: String,
    },
}

/// Runs the probe until an attempt measures its scenario. Unbounded on purpose:
/// each attempt is independent, and an environment that loses every one is
/// bounded by the nextest terminate-after on these tests.
fn run_probe(variant: Variant) {
    for attempt in 1.. {
        match restart_probe(variant) {
            AttemptOutcome::Measured => return,
            AttemptOutcome::RaceLost {
                state_before_disable,
                scm_entries,
            } => eprintln!(
                "P1 {}: attempt {attempt} lost the race with the SCM's restart timer: \
                 S was {state_before_disable:?} when its disable was due, so its restart had already fired; \
                 rerunning. \
                 SCM log entries naming S, newest first: {scm_entries}",
                variant.name()
            ),
        }
    }
}

/// The SCM's log entries naming the service `display_name`, newest first, on one line.
fn scm_entries_dump(display_name: &str) -> String {
    system_log::scm_entries_naming(display_name)
        .iter()
        .map(|entry| format!("[{}: {}]", entry.event_id, entry.text))
        .collect::<Vec<_>>()
        .join(" ")
}

/// One attempt, on services and events named for it: the SCM log keeps every
/// earlier attempt's and run's entries, which a name any of them used would
/// read as this one's. The id (variant, a random nonce, fixed-width) is unique
/// to the attempt, and each display name closes in `]`, so no name is a prefix
/// of another.
fn restart_probe(variant: Variant) -> AttemptOutcome {
    use rand::RngExt;
    let name = variant.name();
    let id = format!("{name}-{:016x}", rand::rng().random::<u64>());
    let dir = tempfile::tempdir().unwrap();
    let (s_log, c_log) = (dir.path().join("s.log"), dir.path().join("c.log"));
    // `NamedEvent` appends the process id to the tag, so the tag ends in a separator.
    let s_running = NamedEvent::create(&format!("RestartProbeSRunning-{id}-"));
    let c_running = NamedEvent::create(&format!("RestartProbeCRunning-{id}-"));
    let arguments = |log: &std::path::Path, running: &NamedEvent| -> Vec<OsString> {
        vec![
            "--pid-log".into(),
            log.as_os_str().to_owned(),
            "--running-event".into(),
            running.name().into(),
        ]
    };
    let s = ProbeService::create(
        format!("HoleProbeS-{id}"),
        format!("Hole probe S [{id}]"),
        arguments(&s_log, &s_running),
        S_RESTART_DELAY,
    );
    let c = ProbeService::create(
        format!("HoleProbeC-{id}"),
        format!("Hole probe C [{id}]"),
        arguments(&c_log, &c_running),
        C_RESTART_DELAY,
    );

    s.start();
    s_running.wait();
    c.start();
    c_running.wait();
    let (s_pid, c_pid) = (s.process_id(), c.process_id());
    // The next signal of C's event is its restarted instance's.
    c_running.reset();

    let log = system_log::Watch::open();
    // Reads S's state, then disables it unless that read shows the variant's
    // scenario already lost: a disable written after the restart fired measures
    // nothing.
    let disable_s = || -> Result<ServiceState, ServiceState> {
        let state_before_disable = s.state();
        if !variant.disable_meets_its_scenario(state_before_disable) {
            return Err(state_before_disable);
        }
        s.disable();
        Ok(state_before_disable)
    };
    let disabled_before_the_crash = variant.disables_before_the_crash().then(&disable_s);
    scm_probe::terminate_process(s_pid);
    eprintln!("P1 {name}: killed S (process {s_pid}); waiting for the SCM to log that it queued S's restart");
    log.wait_until(|| {
        system_log::scm_entries_naming(&s.display_name)
            .iter()
            .any(|entry| entry.event_id == CORRECTIVE_ACTION_EVENT)
    });
    let state_before_disable = match disabled_before_the_crash.unwrap_or_else(disable_s) {
        Ok(state) => state,
        Err(state_before_disable) => {
            return AttemptOutcome::RaceLost {
                state_before_disable,
                scm_entries: scm_entries_dump(&s.display_name),
            }
        }
    };
    let state_after_disable = s.state();
    scm_probe::terminate_process(c_pid);
    eprintln!("P1 {name}: S disabled; killed C (process {c_pid}); waiting for C's restarted instance");
    c_running.wait();

    let (s_state, s_starts, c_starts) = (s.state(), starts_in(&s_log), starts_in(&c_log));
    let restarted = s_starts > 1 || s_state != ServiceState::Stopped;
    eprintln!(
        "P1 {name} RESULT: S's start type read back {:?}; S state before the disable was \
         written {state_before_disable:?}, after {state_after_disable:?}; \
         S state when C's restarted instance was up {s_state:?}; S starts {s_starts} (1 is the original); \
         C starts {c_starts} (2 is the original and its restart). \
         SCM log entries naming S, newest first: {}",
        s.start_type(),
        scm_entries_dump(&s.display_name)
    );
    let verdict = if restarted {
        "FALSIFIED: the disabled service was restarted"
    } else {
        "NOT FALSIFIED: S was not restarted by the time C's restart was up. This probe cannot show that S will never \
         restart; the documented basis (ChangeServiceConfig2W Remarks) stands unless a run falsifies it"
    };
    eprintln!("P1 {name} VERDICT: {verdict}.");
    assert!(!restarted, "P1 {name}: the disabled service was restarted");
    AttemptOutcome::Measured
}

/// S is disabled while its restart is queued.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_probe_disabled_refuses_a_queued_recovery_restart() {
    run_probe(Variant::Queued);
}

/// S is disabled while running, then crashes.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_probe_disabled_refuses_the_recovery_restart_of_a_crash() {
    run_probe(Variant::Running);
}
