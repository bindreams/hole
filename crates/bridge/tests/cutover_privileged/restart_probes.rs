//! Probe P1 of the service-retirement design: does the SCM's own recovery
//! restart start a service whose start type is DISABLED?
//!
//! Microsoft's `ChangeServiceConfig2W` Remarks already answer it ("A queued
//! restart action cannot be canceled ... The service must be explicitly
//! disabled to prevent it from restarting"). This probe can only FALSIFY that
//! answer: a restart that happens is read off a positive event (the service's
//! start count), while a restart that does not happen has no event to read, and
//! no verdict below claims one from the absence.
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
//! In the `running` variant any restart of S is a falsification.
//!
//! The `queued` variant needs the disable to land before the SCM's restart
//! timer fires, which the test cannot guarantee: only the SCM runs that timer.
//! No read of S's state can place a restart against the disable (the disable
//! writes no event, and a state read leaves the restart on the other side of it
//! open), so the restart is placed by when it happened. The system time is read
//! just before the disable is written (`t0`) and just after it returns (`t1`),
//! and the creation time of S's restarted instance is read from the process
//! list, by the last process id in S's pid log:
//! - created before `t0`: the timer fired first, nothing was measured: rerun;
//! - created after `t1`: the SCM started a disabled service: FALSIFIED;
//! - created within `[t0, t1]`: the order is unknowable, so it is no
//!   measurement either: rerun.
//!
//! The OS's creation stamp may lag the true time (tick clock against the
//! precise one) but is never ahead of it, and `t1` is never behind it, so an
//! error moves a restart into the window or before `t0`, toward a rerun, and
//! never toward a verdict. The restarted instance is alive when it is read (the
//! helper exits only when killed, and only teardown kills it), so no creation
//! time recorded by the helper is needed; an instance the list does not have
//! fails the probe.

use std::ffi::OsString;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hole_bridge::disable_record::Stamp;
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
use super::{left_behind, scm_deletion, scm_probe, GLOBAL_NET_STATE, TUN};

/// How long the SCM waits before it restarts S, and C. C's is the longer, and C
/// is killed only after the read of S's queued restart, so S's action is due
/// well before the control's restart is up. A longer one for S makes a lost
/// race rarer (the event-log read before the disable measured ~6 s on a loaded
/// runner); a loss is rerun, not failed.
const S_RESTART_DELAY: Duration = Duration::from_secs(30);
const C_RESTART_DELAY: Duration = Duration::from_secs(40);

/// What a probe service's name starts with, by role. A killed run skips
/// teardown and leaves its services behind (`assert_no_leftover_probe_services`).
const S_NAME_PREFIX: &str = "HoleProbeS-";
const C_NAME_PREFIX: &str = "HoleProbeC-";

/// The system time as a `FILETIME`: 100 ns ticks since 1601, the unit the OS
/// stamps a process's creation in.
fn filetime_now() -> u64 {
    const UNIX_EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system time is after 1970");
    UNIX_EPOCH_AS_FILETIME + (since_epoch.as_nanos() / 100) as u64
}

/// When a disable was written: the system time read just before the write
/// (`before`) and just after it returned (`after`), as `FILETIME`s.
#[derive(Clone, Copy)]
struct DisableWindow {
    before: u64,
    after: u64,
}

/// When a restart happened, against a disable's [`DisableWindow`].
enum RestartTiming {
    /// Before the write began: the disable met no queued restart.
    Before,
    /// Inside the write: which came first cannot be told.
    During,
    /// After the write returned: the restart ignored the disable.
    After,
}

impl DisableWindow {
    fn timing_of(self, created: u64) -> RestartTiming {
        if created < self.before {
            RestartTiming::Before
        } else if created > self.after {
            RestartTiming::After
        } else {
            RestartTiming::During
        }
    }

    /// `t0`, `t1` and `created` for a log line, with `created` in milliseconds
    /// from `t0`.
    fn describe(self, created: u64) -> String {
        let from_t0_ms = (i128::from(created) - i128::from(self.before)) / 10_000;
        format!(
            "t0 {}, t1 {} (FILETIME, 100 ns), restarted instance created {created} ({from_t0_ms} ms from t0)",
            self.before, self.after
        )
    }
}

/// The creation time of the live process `pid`, from the process list.
fn creation_time_of(pid: u32) -> u64 {
    Stamp::of_listed_process(pid)
        .expect("read the process list")
        .unwrap_or_else(|| panic!("the restarted instance (process {pid}) is not in the process list"))
        .created()
}

/// Fails if a probe service from an earlier run is still registered. A run the
/// nextest terminate-after killed skips `ProbeService::drop`, leaving an
/// AutoStart LocalSystem service that restarts on failure, and nothing else
/// would notice: the names are new each attempt. Detection only; the test
/// deletes only what it created.
fn assert_no_leftover_probe_services() {
    let services = windows_registry::LOCAL_MACHINE
        .open(r"SYSTEM\CurrentControlSet\Services")
        .expect("open HKLM\\SYSTEM\\CurrentControlSet\\Services");
    let leftovers: Vec<String> = services
        .keys()
        .expect("list the registered services")
        .filter(|name| {
            let name = name.to_ascii_lowercase();
            [S_NAME_PREFIX, C_NAME_PREFIX]
                .iter()
                .any(|prefix| name.starts_with(&prefix.to_ascii_lowercase()))
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "probe services of an earlier run are still registered: {leftovers:?}. Each is AutoStart, runs as LocalSystem \
         and restarts on failure. Remove each with `sc stop <name>` and `sc delete <name>`, then rerun"
    );
}

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
            .unwrap_or_else(|e| panic!("create the probe service {name}: {e}"));
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

    /// `SERVICE_DISABLED`, and nothing else changed. Returns when the write was
    /// made, bracketed by the system time.
    fn disable(&self) -> DisableWindow {
        let before = filetime_now();
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
        DisableWindow {
            before,
            after: filetime_now(),
        }
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
    left_behind::logged(pid_log).len()
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
}

/// How one attempt of a probe ended.
enum AttemptOutcome {
    /// The scenario held and the verdict was asserted.
    Measured,
    /// S's restart was created before the disable was written, or too close to
    /// it to tell which came first (`DisableWindow`): the disable did not meet
    /// a queued restart, so nothing was measured.
    RaceLost {
        /// What was read, for the one line printed per lost attempt.
        evidence: String,
    },
}

/// Runs the probe until an attempt measures its scenario. Unbounded on purpose:
/// each attempt is independent, and an environment that loses every one is
/// bounded by the nextest terminate-after on these tests.
fn run_probe(variant: Variant) {
    for attempt in 1u32.. {
        match restart_probe(variant, attempt) {
            AttemptOutcome::Measured => return,
            AttemptOutcome::RaceLost { evidence } => {
                eprintln!(
                    "P1 {}: attempt {attempt} measured nothing, rerunning: {evidence}",
                    variant.name()
                )
            }
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
/// read as this one's. The id (variant, test process id, attempt, and the
/// system time at the attempt's start, the last three fixed-width) is unique to
/// the attempt, and each display name closes in `]`, so no name is a prefix of
/// another.
fn restart_probe(variant: Variant, attempt: u32) -> AttemptOutcome {
    assert_no_leftover_probe_services();
    let name = variant.name();
    let id = format!(
        "{name}-{:08x}-{attempt:08x}-{:016x}",
        std::process::id(),
        filetime_now()
    );
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
        format!("{S_NAME_PREFIX}{id}"),
        format!("Hole probe S [{id}]"),
        arguments(&s_log, &s_running),
        S_RESTART_DELAY,
    );
    let c = ProbeService::create(
        format!("{C_NAME_PREFIX}{id}"),
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
    if variant.disables_before_the_crash() {
        s.disable();
    }
    scm_probe::terminate_process(s_pid);
    eprintln!("P1 {name}: killed S (process {s_pid}); waiting for the SCM to log that it queued S's restart");
    log.wait_until(|| {
        system_log::scm_entries_naming(&s.display_name)
            .iter()
            .any(|entry| entry.event_id == CORRECTIVE_ACTION_EVENT)
    });
    let disable_window = (!variant.disables_before_the_crash()).then(|| s.disable());
    scm_probe::terminate_process(c_pid);
    eprintln!("P1 {name}: S disabled; killed C (process {c_pid}); waiting for C's restarted instance");
    c_running.wait();

    let (s_state, s_starts, c_starts) = (s.state(), starts_in(&s_log), starts_in(&c_log));
    let restarted = s_starts > 1 || s_state != ServiceState::Stopped;
    let timing_line = match (disable_window, restarted) {
        (None, _) => String::from("S disabled before the crash, no timing read"),
        (Some(window), false) => format!(
            "no restarted instance of S, disable written between t0 {} and t1 {}",
            window.before, window.after
        ),
        (Some(window), true) => {
            // S has a restarted instance in the log only if it logged one: a
            // restart caught before its helper logged cannot be placed.
            let restarted_pid = left_behind::logged(&s_log)
                .last()
                .copied()
                .filter(|_| s_starts > 1)
                .unwrap_or_else(|| {
                    panic!(
                        "S is {s_state:?} but its pid log names one process: its restarted instance cannot be placed"
                    )
                });
            let created = creation_time_of(restarted_pid);
            let timing_line = window.describe(created);
            let loss = match window.timing_of(created) {
                RestartTiming::Before => {
                    Some("S's restart was created before the disable began: the SCM's timer fired first")
                }
                RestartTiming::During => {
                    Some("S's restart was created while the disable was being written: which came first is unknowable")
                }
                RestartTiming::After => None,
            };
            if let Some(loss) = loss {
                return AttemptOutcome::RaceLost {
                    evidence: format!(
                        "{loss}; {timing_line}; SCM log entries naming S, newest first: {}",
                        scm_entries_dump(&s.display_name)
                    ),
                };
            }
            timing_line
        }
    };
    eprintln!(
        "P1 {name} RESULT: S's start type read back {:?}; {timing_line}; S state when C's restarted instance was up \
         (read after the crash and the log wait, not at the disable) {s_state:?}; S starts {s_starts} (1 is the \
         original); C starts {c_starts} (2 is the original and its restart). \
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
