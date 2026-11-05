//! Probes P2 and P3 of the service-retirement design: what the SCM does for a
//! process that dies without reporting STOPPED, and what a notification armed
//! on a fresh handle reports. Raw SCM calls only (`raw_scm`), so the lines
//! describe the SCM and not the policy built on it.
//!
//! No probe here reads an absence off a timeout. "Reports at once" is a
//! callback that arrives with nothing done to the service. "Waits" is read by
//! arming for every state but the current one, driving a transition, and
//! reading which state the callback reports.

use hole_bridge::cutover::os::windows::WindowsCutoverOs;
use hole_bridge::cutover::os::CutoverOs;
use hole_bridge::platform::os::SERVICE_NAME;

use super::named_event::NamedEvent;
use super::raw_scm::{self, any_state_but, flag_of_state, state_name, Armed, ANY_STATE, STOPPED};
use super::{scm_probe, start_in_background, ProvisionedService, GLOBAL_NET_STATE, TUN};

fn os() -> WindowsCutoverOs {
    WindowsCutoverOs {
        images: vec![],
        target_version: "test".into(),
    }
}

/// P2. The service process is killed with `TerminateProcess`, so it never
/// reports STOPPED. The SCM must reach STOPPED by itself and a STOPPED arm on a
/// fresh handle must fire; the service has no recovery action, so STOPPED is
/// where it stays. The line to read is `P2 ANSWER`. A hang before it, ended by
/// the nextest `terminate-after`, means the SCM never reported STOPPED.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_probe_scm_reports_stopped_for_a_killed_process() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);
    CutoverOs::start_service_wait_running(&mut os()).expect("bring the service up");

    let pid = scm_probe::service_process_id();
    scm_probe::terminate_process(pid);
    eprintln!("P2: killed process {pid} with TerminateProcess; arming STOPPED on a fresh handle");
    let report = Armed::arm(SERVICE_NAME, STOPPED).wait();
    let after = raw_scm::query(SERVICE_NAME);
    eprintln!(
        "P2 ANSWER: the STOPPED arm fired: {}. QueryServiceStatusEx afterwards: state {}, process id {}, win32 exit code {}.",
        report.describe(),
        state_name(after.dwCurrentState.0),
        after.dwProcessId,
        after.dwWin32ExitCode
    );
    // The mask holds only STOPPED, so this is the arm's documented contract.
    assert_eq!(
        report.triggered, STOPPED.0,
        "the callback names the state it was armed for"
    );
}

/// One state's arm measurements (P3), with the service already in `state`.
///
/// 1. An arm for every state reports `state` at once. Documented
///    (`NotifyServiceStatusChangeW` Remarks); asserted.
/// 2. Another handle's arm, for every state but `state`, is outstanding while
///    a second fresh arm for every state is made: the second reports `state`
///    at once. Asserted for the same reason.
/// 3. The same, after the outstanding handle was closed.
/// 4. An arm for every state but `state` waits: `transition` drives the service
///    out of `state` and the callback must name the state it moved to, never
///    `state`. Asserted: a callback naming `state` would be a report of the
///    excluded state.
///
/// `finish` runs once the callback of 4 is in, for what `transition` started.
fn measure_arms(label: &str, state: u32, transition: impl FnOnce(), finish: impl FnOnce()) {
    let flag = flag_of_state(state);

    let at_once = Armed::arm(SERVICE_NAME, ANY_STATE).wait();
    assert_eq!(
        at_once.triggered, flag.0,
        "{label}: an arm for every state reports the current one at once"
    );

    let outstanding = Armed::arm(SERVICE_NAME, any_state_but(flag));
    let beside_outstanding = Armed::arm(SERVICE_NAME, ANY_STATE).wait();
    assert_eq!(
        beside_outstanding.triggered, flag.0,
        "{label}: a fresh arm reports the current state at once while another handle's arm is outstanding"
    );

    drop(outstanding);
    let after_close = Armed::arm(SERVICE_NAME, ANY_STATE).wait();
    assert_eq!(
        after_close.triggered, flag.0,
        "{label}: a fresh arm reports the current state at once after the outstanding handle was closed"
    );

    let excluding = Armed::arm(SERVICE_NAME, any_state_but(flag));
    transition();
    let moved = excluding.wait();
    finish();
    assert_ne!(
        moved.triggered, flag.0,
        "{label}: an arm that excludes the current state reported it"
    );
    eprintln!(
        "P3 ANSWER, {label}: arm for every state -> {}; beside an outstanding arm on another handle -> {}; after that handle was closed -> {}; arm excluding {} then a transition -> {}.",
        at_once.describe(),
        beside_outstanding.describe(),
        after_close.describe(),
        state_name(state),
        moved.describe()
    );
}

#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_probe_arm_on_a_fresh_handle_excluding_the_current_state_running() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);
    CutoverOs::start_service_wait_running(&mut os()).expect("bring the service up");
    measure_arms(
        "RUNNING",
        4,
        || {
            let stop = scm_probe::Probe::open().stop();
            eprintln!("P3: ControlService(STOP) -> {stop:?}");
        },
        || {},
    );
}

#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_probe_arm_on_a_fresh_handle_excluding_the_current_state_stopped() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let _service = ProvisionedService::install(helper);
    assert_eq!(scm_probe::Probe::open().state(), 1, "a new service is STOPPED");
    let started = std::cell::RefCell::new(None);
    measure_arms(
        "STOPPED",
        1,
        || *started.borrow_mut() = Some(start_in_background()),
        || {
            let starter = started.borrow_mut().take().expect("the transition started the service");
            starter.join().unwrap().expect("the service starts");
        },
    );
}

#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn cutover_global_net_state_probe_arm_on_a_fresh_handle_excluding_the_current_state_start_pending() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_test_service"));
    let parked = NamedEvent::create("ArmProbeParked");
    let release = NamedEvent::create("ArmProbeRelease");
    let _service = ProvisionedService::install_with(
        helper,
        vec![
            "--hold-start".into(),
            release.name().into(),
            "--parked-event".into(),
            parked.name().into(),
        ],
        None,
    );
    let _release_on_drop = release.release_on_drop();
    let starter = start_in_background();
    parked.wait();
    measure_arms("START_PENDING", 2, || release.signal(), || {});
    starter.join().unwrap().expect("the held service starts once released");
}
