//! Probe P1 of the service-retirement design: does the SCM's own recovery
//! restart start a service whose start type is DISABLED?
//!
//! Microsoft's `ChangeServiceConfig2W` Remarks already answer it ("A queued
//! restart action cannot be canceled ... The service must be explicitly
//! disabled to prevent it from restarting"). This probe can only FALSIFY that
//! answer: a restart that happens is read off a positive event (the SCM's 7036
//! for S entering the running state) and a refusal off another (a 7032 carrying
//! error 1058), and no verdict below claims either from the absence of an event.
//!
//! S runs the helper with a restart-on-failure action and is crashed. Its
//! disable is written either while its restart is queued (variant `queued`) or
//! before the crash (variant `running`). The read of S waits for the SCM's own
//! account of S's restart, not for a delay: after S's corrective-action entry
//! (7031) the SCM logs either that the restart failed (7032) or that S entered
//! the running state (7036). A STOPPED S read before one of them is not a
//! measurement, so it is never read.
//!
//! The log is read as XML, one query per wake, and only through its typed
//! fields: the event id, the record id and the event data values. A 7032 is a
//! refusal by the disable only when its data holds `%%1058`, the message-table
//! reference to error 1058 (`ERROR_SERVICE_DISABLED`); a 7036 is a start only
//! when its data holds `running`. Other entries naming S (a 7036 for another
//! state, a 7040 to another start type) are not an outcome and are ignored; a
//! 7032 without `%%1058` is an outcome the probe has no reading for and fails
//! the probe with its XML. Only records newer than the newest SCM record before
//! the crash are read.
//!
//! The `queued` variant needs the disable to land before the SCM's restart
//! timer fires, which the test cannot guarantee: only the SCM runs that timer.
//! A refused restart (7032) proves the disable landed first. The disable logs
//! its own entry (7040), so a restart's 7036 recorded before that 7040 means the
//! timer fired first: rerun. A 7036 recorded after it does not place the
//! restart's creation, which is placed by when it happened: the system time is
//! read just before the disable is written (`t0`) and just after it returns
//! (`t1`), and the restarted instance's creation time is compared against them:
//! - created before `t0`: the timer fired first, nothing was measured: rerun;
//! - created after `t1`: the SCM started a disabled service: FALSIFIED;
//! - created within `[t0, t1]`: the order is unknowable, so it is no
//!   measurement either: rerun.
//!
//! Two residuals remain. The creation time is when the process was created, not
//! when the SCM decided to restart: a restart decided before `t0` can be created
//! after `t1` (the SCM's decision-to-creation delay), and is then read as a
//! false FALSIFIED, never as a silent pass. What keeps the timer away from `t0`
//! is the margin, S's 30 s delay against the ~6 s the event-log read before the
//! disable took on a loaded runner. And `t0`, `t1` and the creation stamp are
//! wall-clock readings, so a clock step between them reorders them, in either
//! direction: a lost race can read as FALSIFIED, and a real FALSIFIED as a
//! rerun (creation reads before `t0`). A FALSIFIED is therefore read against the
//! `t0`, `t1` and creation time the probe prints.
//!
//! S is read once, after the SCM logged the outcome of its restart: its state,
//! then a started instance's creation time at once, before its pid can be
//! reused, then its pid log. A log that says S restarted while S is STOPPED, has
//! no process id or is not listed (unplaceable), or whose pid log shows no second
//! instance, or that says the restart was refused while S ran, fails the probe,
//! never a rerun, so none can pass for a lost race.

use std::ffi::OsString;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hole_bridge::disable_record::Stamp;
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    ChangeServiceConfigW, ENUM_SERVICE_TYPE, SC_HANDLE, SERVICE_DISABLED, SERVICE_ERROR, SERVICE_NO_CHANGE,
    SERVICE_START_TYPE, SERVICE_STOPPED,
};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::named_event::NamedEvent;
use super::raw_scm;
use super::{left_behind, scm_deletion, scm_probe, GLOBAL_NET_STATE, TUN};

/// How long the SCM waits before it restarts S. The margin over the event-log
/// read before the disable keeps the timer from winning; a lost race is rerun.
const S_RESTART_DELAY: Duration = Duration::from_secs(30);

/// What S's name starts with. A killed run skips teardown and leaves its
/// service behind (`assert_no_leftover_probe_services`).
const S_NAME_PREFIX: &str = "HoleProbeS-";

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

    fn describe_window(self) -> String {
        format!("t0 {}, t1 {} (FILETIME, 100 ns)", self.before, self.after)
    }

    /// With `created` in ms from `t0`.
    fn describe(self, created: u64) -> String {
        let from_t0_ms = (i128::from(created) - i128::from(self.before)) / 10_000;
        format!(
            "{}, restarted instance created {created} ({from_t0_ms} ms from t0)",
            self.describe_window()
        )
    }
}

/// The creation time of the live process `pid`, from the process list. `read`
/// is what was read of the service, for the failure.
fn creation_time_of(pid: u32, read: &str) -> u64 {
    assert_ne!(pid, 0, "the service is not STOPPED but reports no process: {read}");
    Stamp::of_listed_process(pid)
        .expect("read the process list")
        .unwrap_or_else(|| panic!("the restarted instance (process {pid}) is not in the process list: {read}"))
        .created()
}

/// Fails if a probe service from an earlier run is still registered. A run the
/// nextest terminate-after killed skips `ProbeService::drop`, leaving an
/// AutoStart LocalSystem service that restarts on failure, and nothing else
/// would notice: the names are new each attempt.
fn assert_no_leftover_probe_services() {
    let services = windows_registry::LOCAL_MACHINE
        .open(r"SYSTEM\CurrentControlSet\Services")
        .expect("open HKLM\\SYSTEM\\CurrentControlSet\\Services");
    let leftovers: Vec<String> = services
        .keys()
        .expect("list the registered services")
        .filter(|name| {
            name.to_ascii_lowercase()
                .starts_with(&S_NAME_PREFIX.to_ascii_lowercase())
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "probe services of an earlier run are still registered: {leftovers:?}. Each is AutoStart, runs as LocalSystem \
         and restarts on failure. Remove each with `sc stop <name>` and `sc delete <name>`, then rerun"
    );
}

/// A throwaway auto-start service running the helper, under a name of its own.
/// Deleted on drop, once its process is gone.
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

    /// One Service Control Manager entry that names a service, by its typed fields.
    pub struct Entry {
        pub event_id: u32,
        pub record_id: u64,
        /// The values of the entry's event data, in order.
        pub data: Vec<String>,
        /// The entry as the log renders it, for a failure.
        pub xml: String,
    }

    impl Entry {
        /// Whether one of the entry's event data values is `value`.
        pub fn has_data(&self, value: &str) -> bool {
            self.data.iter().any(|data| data == value)
        }
    }

    /// The record id of the newest Service Control Manager entry, or 0 when the
    /// log holds none.
    pub fn newest_scm_record() -> u64 {
        query(
            "*[System[Provider[@Name='Service Control Manager']]]",
            &["/c:1", "/rd:true"],
        )
        .first()
        .map_or(0, |entry| entry.record_id)
    }

    /// The Service Control Manager entries after record `after_record` whose
    /// event data names the service `display_name`, oldest first: one
    /// `wevtutil` query, uncapped.
    pub fn scm_entries_naming(display_name: &str, after_record: u64) -> Vec<Entry> {
        query(
            &format!(
                "*[System[Provider[@Name='Service Control Manager'] and EventRecordID>{after_record}] \
                 and EventData[Data='{display_name}']]"
            ),
            &[],
        )
    }

    fn query(xpath: &str, extra_args: &[&str]) -> Vec<Entry> {
        let out = std::process::Command::new("wevtutil.exe")
            .args(["qe", "System", &format!("/q:{xpath}"), "/f:xml"])
            .args(extra_args)
            .output()
            .expect("run wevtutil.exe");
        assert!(
            out.status.success(),
            "wevtutil failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // The events come as sibling roots with no wrapper.
        let xml = format!("<Events>{}</Events>", String::from_utf8_lossy(&out.stdout));
        let document = roxmltree::Document::parse(&xml).unwrap_or_else(|e| panic!("parse wevtutil's XML ({e}): {xml}"));
        document
            .root_element()
            .children()
            .filter(|node| node.is_element())
            .map(|event| {
                let text_of = |name: &str| {
                    event
                        .descendants()
                        .find(|node| node.has_tag_name(name))
                        .and_then(|node| node.text())
                        .unwrap_or_else(|| panic!("an entry without {name}: {}", &xml[event.range()]))
                };
                Entry {
                    event_id: text_of("EventID")
                        .parse()
                        .unwrap_or_else(|e| panic!("an EventID that is no number ({e}): {}", &xml[event.range()])),
                    record_id: text_of("EventRecordID").parse().unwrap_or_else(|e| {
                        panic!("an EventRecordID that is no number ({e}): {}", &xml[event.range()])
                    }),
                    data: event
                        .descendants()
                        .filter(|node| node.has_tag_name("Data"))
                        .map(|node| node.text().unwrap_or_default().to_owned())
                        .collect(),
                    xml: xml[event.range()].to_owned(),
                }
            })
            .collect()
    }
}

/// SCM event 7031: the service ended unexpectedly and a corrective action is
/// taken, which the SCM writes once it has queued the restart.
const CORRECTIVE_ACTION_EVENT: u32 = 7031;

/// SCM event 7032: the corrective action was taken and failed. The error it
/// failed with is in the entry's event data.
const CORRECTIVE_ACTION_FAILED_EVENT: u32 = 7032;

/// SCM event 7036: a service entered a state; after S's 7031 it is the
/// restarted instance's running state.
const SERVICE_STATE_EVENT: u32 = 7036;

/// SCM event 7040: a service's start type changed. S's own is its disable.
const START_TYPE_CHANGED_EVENT: u32 = 7040;

/// The data value of a 7032 for a failure with error 1058,
/// `ERROR_SERVICE_DISABLED`: the message-table reference the SCM stores the
/// error as.
const ERROR_SERVICE_DISABLED_DATA: &str = "%%1058";

/// The data value of a 7036 for the running state.
const RUNNING_STATE_DATA: &str = "running";

/// The data value of a 7040 for a start type of disabled.
const DISABLED_START_TYPE_DATA: &str = "disabled";

/// What the SCM logged about S's restart after it queued it.
#[derive(Clone, Copy)]
enum RestartOutcome {
    /// S entered the running state again.
    Started,
    /// The restart was attempted and failed with error 1058: the service is disabled.
    Refused,
}

impl RestartOutcome {
    fn restarted(self) -> bool {
        match self {
            RestartOutcome::Started => true,
            RestartOutcome::Refused => false,
        }
    }

    fn name(self) -> &'static str {
        match self {
            RestartOutcome::Started => "started",
            RestartOutcome::Refused => "refused",
        }
    }
}

/// What S's entries after its 7031 say, oldest first.
struct RestartRead {
    /// The first entry that logs how the restart went, and its record id.
    outcome: Option<(RestartOutcome, u64)>,
    /// The record id of the first entry that logs S's disable.
    disable_record: Option<u64>,
    entries: Vec<system_log::Entry>,
}

impl RestartRead {
    /// Reads every entry for the disable and entries up to the first outcome
    /// for the outcome. An entry that is neither is ignored; an outcome-kind
    /// entry the probe has no reading for fails the probe with its XML.
    fn from(entries: Vec<system_log::Entry>) -> Self {
        let disable_record = entries
            .iter()
            .find(|entry| entry.event_id == START_TYPE_CHANGED_EVENT && entry.has_data(DISABLED_START_TYPE_DATA))
            .map(|entry| entry.record_id);
        let outcome = entries.iter().find_map(|entry| match entry.event_id {
            CORRECTIVE_ACTION_FAILED_EVENT if entry.has_data(ERROR_SERVICE_DISABLED_DATA) => {
                Some((RestartOutcome::Refused, entry.record_id))
            }
            CORRECTIVE_ACTION_FAILED_EVENT => panic!(
                "the SCM logged a failed restart of S that the probe has no reading for: {}",
                entry.xml
            ),
            SERVICE_STATE_EVENT if entry.has_data(RUNNING_STATE_DATA) => {
                Some((RestartOutcome::Started, entry.record_id))
            }
            _ => None,
        });
        RestartRead {
            outcome,
            disable_record,
            entries,
        }
    }

    /// The entries as event id, record id and data, for the report.
    fn dump(&self) -> String {
        self.entries
            .iter()
            .map(|entry| format!("[{} #{}: {:?}]", entry.event_id, entry.record_id, entry.data))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// The record id of the SCM's 7031 for S, once it is logged after record
/// `after_record`: it queued S's restart.
fn queued_record(display_name: &str, after_record: u64) -> Option<u64> {
    system_log::scm_entries_naming(display_name, after_record)
        .iter()
        .find(|entry| entry.event_id == CORRECTIVE_ACTION_EVENT)
        .map(|entry| entry.record_id)
}

/// Where S's disable is written relative to the crash.
#[derive(Clone, Copy)]
enum Variant {
    Queued,
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
    RaceLost { evidence: String },
}

/// Runs the probe until an attempt measures its scenario. Unbounded on purpose:
/// each attempt is independent, and an environment that loses every one is
/// bounded by the nextest terminate-after on these tests.
fn run_probe(variant: Variant) {
    // Once per test: a service left by an attempt's own failed teardown is not an
    // earlier run's.
    assert_no_leftover_probe_services();
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

/// One attempt, on services and events named for it: the SCM log keeps every
/// earlier attempt's and run's entries, which a reused name would read as this
/// one's.
fn restart_probe(variant: Variant, attempt: u32) -> AttemptOutcome {
    let name = variant.name();
    let id = format!(
        "{name}-{:08x}-{attempt:08x}-{:016x}",
        std::process::id(),
        filetime_now()
    );
    let dir = tempfile::tempdir().unwrap();
    let s_log = dir.path().join("s.log");
    // `NamedEvent` appends the process id to the tag, so the tag ends in a separator.
    let s_running = NamedEvent::create(&format!("RestartProbeSRunning-{id}-"));
    let s = ProbeService::create(
        format!("{S_NAME_PREFIX}{id}"),
        format!("Hole probe S [{id}]"),
        vec![
            "--pid-log".into(),
            s_log.as_os_str().to_owned(),
            "--running-event".into(),
            s_running.name().into(),
        ],
        S_RESTART_DELAY,
    );

    s.start();
    s_running.wait();
    let s_pid = s.process_id();

    let log = system_log::Watch::open();
    let before_the_crash = system_log::newest_scm_record();
    if variant.disables_before_the_crash() {
        s.disable();
    }
    scm_probe::terminate_process(s_pid);
    eprintln!("P1 {name}: killed S (process {s_pid}); waiting for the SCM to log that it queued S's restart");
    let mut queued_at = None;
    log.wait_until(|| {
        queued_at = queued_record(&s.display_name, before_the_crash);
        queued_at.is_some()
    });
    let queued_at = queued_at.expect("the wait returns once the 7031 is logged");
    let disable_window = (!variant.disables_before_the_crash()).then(|| s.disable());
    eprintln!("P1 {name}: S disabled; waiting for the SCM to log what became of S's restart");
    let mut logged = None;
    log.wait_until(|| {
        let read = RestartRead::from(system_log::scm_entries_naming(&s.display_name, queued_at));
        let done = read.outcome.is_some();
        logged = Some(read);
        done
    });
    let logged = logged.expect("the wait reads the log at least once");
    let (outcome, outcome_record) = logged.outcome.expect("the wait returns once an outcome is logged");

    // Order matters: see the module doc.
    let s_status = raw_scm::query(&s.name);
    let s_stopped = s_status.dwCurrentState == SERVICE_STOPPED;
    let s_state = raw_scm::state_name(s_status.dwCurrentState.0);
    let s_created = (outcome.restarted() && disable_window.is_some() && !s_stopped).then(|| {
        creation_time_of(
            s_status.dwProcessId,
            &format!("S state {s_state}, process id {}", s_status.dwProcessId),
        )
    });
    let s_pids = left_behind::logged(&s_log);
    let s_read = format!(
        "S read after the SCM logged its restart as {}: state {s_state}, process id {} (0 is none), \
         pid log {s_pids:?}; SCM log entries naming S after its 7031 (#{queued_at}), oldest first: {}",
        outcome.name(),
        s_status.dwProcessId,
        logged.dump()
    );
    eprintln!("P1 {name}: {s_read}");
    match outcome {
        RestartOutcome::Refused => assert!(
            s_stopped && s_pids.len() == 1,
            "P1 {name}: the SCM logged S's restart as refused but S ran: {s_read}"
        ),
        RestartOutcome::Started => left_behind::assert_started(&s_log, 2),
    }
    let restarted = outcome.restarted();
    let timing_line = match disable_window {
        None => String::from("S disabled before the crash, no timing read"),
        Some(window) => match outcome {
            RestartOutcome::Refused => {
                if let Some(disable_record) = logged.disable_record {
                    assert!(
                        disable_record < outcome_record,
                        "P1 {name}: the SCM refused S's restart (#{outcome_record}) before it logged S's disable \
                         (#{disable_record}): {s_read}"
                    );
                }
                format!(
                    "the SCM's restart failed, so the disable landed first; disable written at {}",
                    window.describe_window()
                )
            }
            RestartOutcome::Started => {
                if let Some(disable_record) = logged.disable_record.filter(|record| *record > outcome_record) {
                    return AttemptOutcome::RaceLost {
                        evidence: format!(
                            "the SCM logged S running (#{outcome_record}) before S's disable (#{disable_record}): \
                         the timer fired first; {}; {s_read}",
                            window.describe_window()
                        ),
                    };
                }
                let Some(created) = s_created else {
                    panic!(
                        "P1 {name}: S restarted but could not be placed: {s_read}; {}",
                        window.describe_window()
                    )
                };
                let timing_line = window.describe(created);
                let loss = match window.timing_of(created) {
                    RestartTiming::Before => {
                        Some("S's restart was created before the disable began: the SCM's timer fired first")
                    }
                    RestartTiming::During => Some(
                        "S's restart was created while the disable was being written: which came first is unknowable",
                    ),
                    RestartTiming::After => None,
                };
                if let Some(loss) = loss {
                    return AttemptOutcome::RaceLost {
                        evidence: format!("{loss}; {timing_line}; {s_read}"),
                    };
                }
                timing_line
            }
        },
    };
    eprintln!(
        "P1 {name} RESULT: {timing_line}; S's start type read back afterwards {:?}.",
        s.start_type()
    );
    let verdict = if restarted {
        "FALSIFIED: the disabled service was restarted"
    } else {
        "NOT FALSIFIED: the SCM tried to restart S and failed. The documented basis (ChangeServiceConfig2W Remarks) \
         stands unless a run falsifies it"
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
