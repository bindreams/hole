//! Probes P4 to P7 of the service-retirement design, on the service SID that
//! says which process is the service's:
//!
//! - P4: the SID derived from the service name equals the OS's, and exists for
//!   a name no service has.
//! - P5: a scan over every process finds the service's process by its token,
//!   from an elevated administrator and from LocalSystem, and finds nothing for
//!   a service without the SID type.
//! - P6: `OpenService` on a service marked for deletion, and the scan still
//!   finding its live process.
//! - P7: when a SID type set on a running service reaches a process: at the
//!   service's next start, or only at the next boot.
//!
//! The scan is `test_service --scan-sid` (see its module doc), so the elevated
//! administrator and the LocalSystem run execute the same code.

use std::path::Path;

use hole_bridge::cutover::os::windows::WindowsCutoverOs;
use hole_bridge::cutover::os::CutoverOs;
use hole_bridge::platform::os::registration::run_startup_repairs;
use hole_bridge::platform::os::{SidRepairOutcome, SERVICE_NAME};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_SERVICE_MARKED_FOR_DELETE, HANDLE};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
};
use windows::Win32::System::Threading::{OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE};

use super::named_event::NamedEvent;
use super::sid_formula::{derived_service_sid, os_service_sid};
use super::{scm_probe, ProvisionedService, GLOBAL_NET_STATE, TUN};

fn os() -> WindowsCutoverOs {
    WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    }
}

fn helper() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_test_service"))
}

/// The SID `sc showsid` prints for `name`, the OS's own tool, or its output
/// when it prints no SID line.
fn sc_showsid_of(name: &str) -> String {
    let out = std::process::Command::new("sc.exe")
        .args(["showsid", name])
        .output()
        .expect("run sc.exe showsid");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.lines()
        .find_map(|line| line.trim().strip_prefix("SERVICE SID:"))
        .map(|sid| sid.trim().to_owned())
        .unwrap_or_else(|| text.lines().map(str::trim).collect::<Vec<_>>().join(" | "))
}

/// P4. The deputy's decision is to compute the SID from the name rather than
/// ask the OS, which cannot answer once the service is deleted. The registered
/// name is asserted against the OS's own lookup; the name no service has is
/// printed (the lookup is expected to fail, the derivation is not).
///
/// Lines to read: `P4 ANSWER, registered` and `P4 ANSWER, never registered`.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_probe_computed_service_sid() {
    let _service = ProvisionedService::install(helper());
    let computed = derived_service_sid(SERVICE_NAME);
    let from_os = os_service_sid(SERVICE_NAME);
    let from_sc = sc_showsid_of(SERVICE_NAME);
    eprintln!("P4 ANSWER, registered ({SERVICE_NAME}): derived {computed}; LookupAccountNameW {from_os:?}; sc showsid {from_sc}");
    assert_eq!(
        from_os.expect("the OS resolves a registered service"),
        computed,
        "the derived SID is the OS's"
    );
    assert_eq!(from_sc, computed, "the derived SID is what `sc showsid` prints");

    let unregistered = format!("HoleNeverRegistered{}", std::process::id());
    eprintln!(
        "P4 ANSWER, never registered ({unregistered}): derived {}; LookupAccountNameW {:?}; sc showsid {}",
        derived_service_sid(&unregistered),
        os_service_sid(&unregistered),
        sc_showsid_of(&unregistered)
    );
}

/// What one `--scan-sid` run wrote.
struct Scan {
    report: String,
}

impl Scan {
    fn read(out: &Path) -> Self {
        Scan {
            report: std::fs::read_to_string(out).expect("the scan wrote its report"),
        }
    }

    /// The ids of the processes whose token carried the SID.
    fn matches(&self) -> Vec<u32> {
        self.report
            .lines()
            .find_map(|line| line.strip_prefix("matches: "))
            .unwrap_or_else(|| panic!("the scan reported no matches line:\n{}", self.report))
            .split(',')
            .filter_map(|id| id.trim().parse().ok())
            .collect()
    }

    /// The ids the production scan (`scan_service_processes`) kept as alive.
    fn production_alive(&self) -> Vec<u32> {
        let list = self
            .report
            .lines()
            .find_map(|line| line.strip_prefix("production scan, alive: ["))
            .unwrap_or_else(|| {
                panic!(
                    "the scan reported no production scan line:
{}",
                    self.report
                )
            });
        list.trim_end_matches(']')
            .split(',')
            .filter_map(|id| id.trim().parse().ok())
            .collect()
    }

    fn caller(&self) -> &str {
        self.report
            .lines()
            .find_map(|line| line.strip_prefix("caller: "))
            .unwrap_or("(no caller line)")
    }
}

/// Runs the scan as this test's own user, an elevated administrator.
fn scan_as_administrator(service: &str, dir: &Path) -> Scan {
    let out = dir.join("scan-admin.txt");
    let status = std::process::Command::new(helper())
        .args(["--scan-sid", service])
        .arg(&out)
        .status()
        .expect("run the scanner");
    assert!(status.success(), "the scanner failed: {status}");
    Scan::read(&out)
}

/// Deletes the scheduled task on drop.
struct ScheduledTask(String);

impl Drop for ScheduledTask {
    fn drop(&mut self) {
        let _ = std::process::Command::new("schtasks.exe")
            .args(["/Delete", "/TN", &self.0, "/F"])
            .output();
    }
}

/// Runs the scan as LocalSystem, through a scheduled task that runs once, now.
/// Returns when the scanner signals that it is done, which it does whichever
/// way it ended; a task that never starts the scanner hangs here until the
/// nextest `terminate-after` names the test.
fn scan_as_system(service: &str, dir: &Path, tag: &str) -> Scan {
    use std::os::windows::process::CommandExt;

    let out = dir.join("scan-system.txt");
    let done = NamedEvent::create(&format!("ScanDone{tag}"));
    let task = format!("HoleScanProbe{tag}{}", std::process::id());
    // The command line the task runs, with each path quoted for it.
    let quote = format!("{}\"", '\u{5c}');
    let command = format!(
        "{quote}{}{quote} --scan-sid {service} {quote}{}{quote} {}",
        helper().display(),
        out.display(),
        done.name()
    );
    let created = std::process::Command::new("schtasks.exe")
        .args([
            "/Create", "/TN", &task, "/SC", "ONCE", "/ST", "00:00", "/RU", "SYSTEM", "/RL", "HIGHEST", "/F", "/TR",
        ])
        .raw_arg(format!("\"{command}\""))
        .output()
        .expect("run schtasks /Create");
    assert!(
        created.status.success(),
        "schtasks /Create failed: {}{}",
        String::from_utf8_lossy(&created.stdout),
        String::from_utf8_lossy(&created.stderr)
    );
    let _task = ScheduledTask(task.clone());
    let run = std::process::Command::new("schtasks.exe")
        .args(["/Run", "/TN", &task])
        .output()
        .expect("run schtasks /Run");
    assert!(
        run.status.success(),
        "schtasks /Run failed: {}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    done.wait();
    Scan::read(&out)
}

fn print_scan(scenario: &str, scan: &Scan) {
    eprintln!("P5 {scenario}, run as {}:\n{}", scan.caller(), scan.report);
}

/// The id of the process the SCM names for `HoleBridge` now.
fn service_pid() -> u32 {
    scm_probe::service_process_id()
}

/// `HoleBridge`, opened for `DELETE` and marked. The handle stays open so the
/// deletion stays pending until the caller drops this.
struct DeleteMark {
    _service: windows_service::service::Service,
}

impl DeleteMark {
    fn mark() -> Self {
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).expect("open the SCM");
        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::DELETE)
            .expect("open the service for DELETE");
        service.delete().expect("mark the running service for deletion");
        DeleteMark { _service: service }
    }
}

/// `OpenService(SERVICE_QUERY_STATUS)` on `HoleBridge`, as the SCM answers it:
/// the Win32 code, 0 for success.
fn open_service_code() -> u32 {
    let name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: plain FFI calls; `name` is NUL-terminated and outlives them.
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).expect("open the SCM");
        let code = match OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_QUERY_STATUS) {
            Ok(service) => {
                let _ = CloseServiceHandle(service);
                0
            }
            Err(e) => (e.code().0 as u32) & 0xFFFF,
        };
        let _ = CloseServiceHandle(scm);
        code
    }
}

/// P5 and P6. A RUNNING service with the SID type: the scan run as an elevated
/// administrator must find exactly its process (asserted), and must not find
/// this test's own. The same scan as LocalSystem is printed, not asserted: it
/// is the premise under measurement. Then the service is marked for deletion
/// and the same scan runs again, and `OpenService` on the marked service is
/// printed.
///
/// Lines to read: `P5 RUNNING service, run as <caller>` for each caller (the
/// SYSTEM one answers "readable by LocalSystem"), `P5 SYSTEM VERDICT`, and
/// `P6 ANSWER`.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_probe_scan_by_service_sid() {
    let _service = ProvisionedService::install(helper());
    CutoverOs::start_service_wait_running(&mut os()).expect("bring the service up");
    let pid = service_pid();
    let dir = tempfile::tempdir().unwrap();

    let admin = scan_as_administrator(SERVICE_NAME, dir.path());
    print_scan("RUNNING service", &admin);
    assert!(
        admin.matches().contains(&pid),
        "the elevated administrator's scan did not find the service's process {pid}: {:?}",
        admin.matches()
    );
    assert!(
        !admin.matches().contains(&std::process::id()),
        "the scan took this test's own process for the service's"
    );
    assert!(
        admin.production_alive().contains(&pid),
        "the production scan did not find the service's process {pid}: {:?}",
        admin.production_alive()
    );

    let system = scan_as_system(SERVICE_NAME, dir.path(), "Running");
    print_scan("RUNNING service", &system);
    eprintln!(
        "P5 SYSTEM VERDICT: the LocalSystem scan {} the service's process {pid} (it found {:?}).",
        if system.matches().contains(&pid) {
            "FOUND"
        } else {
            "DID NOT FIND"
        },
        system.matches()
    );

    let mark = DeleteMark::mark();
    let open_code = open_service_code();
    eprintln!(
        "P6 ANSWER: OpenService on the marked service -> win32 code {open_code} (ERROR_SERVICE_MARKED_FOR_DELETE is {}).",
        ERROR_SERVICE_MARKED_FOR_DELETE.0
    );
    let marked_admin = scan_as_administrator(SERVICE_NAME, dir.path());
    print_scan("marked service, process alive", &marked_admin);
    assert!(
        marked_admin.matches().contains(&pid),
        "the scan did not find the live process {pid} of a service marked for deletion: {:?}",
        marked_admin.matches()
    );
    let marked_system = scan_as_system(SERVICE_NAME, dir.path(), "Marked");
    print_scan("marked service, process alive", &marked_system);
    eprintln!(
        "P6 SYSTEM VERDICT: the LocalSystem scan {} the marked service's live process {pid}.",
        if marked_system.matches().contains(&pid) {
            "FOUND"
        } else {
            "DID NOT FIND"
        }
    );

    // The marked service goes once its process is gone and no handle is open.
    scm_probe::terminate_process(pid);
    drop(mark);
}

/// P5, the negative half. A service without the SID type has a process whose
/// token lacks the SID, so the scan finds nothing (asserted for the elevated
/// administrator; the LocalSystem run is printed).
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_probe_scan_by_service_sid_finds_nothing_without_the_sid_type() {
    let _service = ProvisionedService::install_without_sid(helper());
    CutoverOs::start_service_wait_running(&mut os()).expect("bring the service up");
    let dir = tempfile::tempdir().unwrap();

    let admin = scan_as_administrator(SERVICE_NAME, dir.path());
    print_scan("RUNNING service without the SID type", &admin);
    assert!(
        admin.matches().is_empty(),
        "the scan found processes for a service without the SID type: {:?}",
        admin.matches()
    );
    let system = scan_as_system(SERVICE_NAME, dir.path(), "NoSid");
    print_scan("RUNNING service without the SID type", &system);
}

/// Waits for process `pid` to exit.
fn wait_for_exit(pid: u32) {
    // SAFETY: plain FFI calls on a handle this function opens and closes.
    unsafe {
        let process: HANDLE = OpenProcess(PROCESS_SYNCHRONIZE, false, pid).expect("open the process to wait on");
        WaitForSingleObject(process, INFINITE);
        let _ = windows::Win32::Foundation::CloseHandle(process);
    }
}

/// P7. `SERVICE_SID_INFO` Remarks say a SID type change "takes effect the next
/// time the system is started"; the design assumes the next start of the
/// service. A service created without the type is started, given the type by
/// the bridge's own startup repair (`run_startup_repairs`), restarted (the
/// service, not the machine), and the restarted process's token is read.
///
/// Lines to read: `P7 RESULT` and `P7 VERDICT`. Nothing about the SID in the
/// restarted process is asserted: whether it appears is the measurement.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_probe_service_sid_type_takes_effect_at_the_next_service_start() {
    let _service = ProvisionedService::install_without_sid(helper());
    let mut os = os();
    CutoverOs::start_service_wait_running(&mut os).expect("bring the service up");
    let first = service_pid();
    let dir = tempfile::tempdir().unwrap();
    let before = scan_as_administrator(SERVICE_NAME, dir.path());
    assert!(
        !before.matches().contains(&first),
        "the process of a service without the SID type carries it"
    );

    let repair = run_startup_repairs().service_sid;
    assert!(
        matches!(repair, Ok(SidRepairOutcome::Applied)),
        "the bridge's startup repair did not apply the SID type: {repair:?}"
    );
    let applied = scan_as_administrator(SERVICE_NAME, dir.path());

    CutoverOs::stop_service_wait_stopped(&mut os).expect("stop the service");
    wait_for_exit(first);
    CutoverOs::start_service_wait_running(&mut os).expect("start the service again");
    let second = service_pid();
    let restarted = scan_as_administrator(SERVICE_NAME, dir.path());
    let carries = restarted.matches().contains(&second);
    eprintln!(
        "P7 RESULT: first process {first}, SID type applied (startup repair -> {repair:?}); the running first process carried the SID after the apply: {}; \
         restarted process {second} (a new process: {}); scan after the restart found {:?}.",
        applied.matches().contains(&first),
        second != first,
        restarted.matches()
    );
    eprintln!(
        "P7 VERDICT: the SID type {} a service restart (no reboot).",
        if carries {
            "TOOK EFFECT AT"
        } else {
            "DID NOT TAKE EFFECT AT"
        }
    );
}
