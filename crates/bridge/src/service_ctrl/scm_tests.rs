use super::*;

use std::time::Duration;
use windows_service::service::{ServiceControlAccept, ServiceState, ServiceType};

fn status(exit_code: ServiceExitCode, wait_hint: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code,
        checkpoint: 7,
        wait_hint,
        process_id: Some(1234),
    }
}

// Literals from winsvc.h, not the `windows` constants under test.
#[skuld::test]
fn raw_status_carries_every_reported_field() {
    let raw = raw_status(&status(ServiceExitCode::Win32(5), Duration::from_millis(1500))).unwrap();
    assert_eq!(raw.dwServiceType.0, 0x10);
    assert_eq!(raw.dwCurrentState.0, 3);
    assert_eq!(raw.dwControlsAccepted, 0x1 | 0x4);
    assert_eq!(raw.dwWin32ExitCode, 5);
    assert_eq!(raw.dwServiceSpecificExitCode, 0);
    assert_eq!(raw.dwCheckPoint, 7);
    assert_eq!(raw.dwWaitHint, 1500);
}

#[skuld::test]
fn raw_status_reports_every_accepted_control_as_its_winsvc_bit() {
    // SERVICE_ACCEPT_*; the `windows` constants are not used, so a wrong
    // mapping cannot agree with itself.
    let bits = [
        (ServiceControlAccept::STOP, 0x1),
        (ServiceControlAccept::PAUSE_CONTINUE, 0x2),
        (ServiceControlAccept::SHUTDOWN, 0x4),
        (ServiceControlAccept::PARAM_CHANGE, 0x8),
        (ServiceControlAccept::NETBIND_CHANGE, 0x10),
        (ServiceControlAccept::HARDWARE_PROFILE_CHANGE, 0x20),
        (ServiceControlAccept::POWER_EVENT, 0x40),
        (ServiceControlAccept::SESSION_CHANGE, 0x80),
        (ServiceControlAccept::PRESHUTDOWN, 0x100),
        (ServiceControlAccept::TIME_CHANGE, 0x200),
        (ServiceControlAccept::TRIGGER_EVENT, 0x400),
    ];
    for (flag, literal) in bits {
        let mut reported = status(ServiceExitCode::NO_ERROR, Duration::ZERO);
        reported.controls_accepted = flag;
        assert_eq!(raw_status(&reported).unwrap().dwControlsAccepted, literal, "{flag:?}");
    }
    // A flag added to the crate's set must be added above.
    assert_eq!(
        ServiceControlAccept::all().bits(),
        bits.iter().fold(0, |all, (_, literal)| all | literal)
    );
}

#[skuld::test]
fn raw_status_reports_every_service_type_as_its_winsvc_value() {
    // SERVICE_KERNEL_DRIVER .. SERVICE_INTERACTIVE_PROCESS.
    let types = [
        (ServiceType::KERNEL_DRIVER, 0x1),
        (ServiceType::FILE_SYSTEM_DRIVER, 0x2),
        (ServiceType::OWN_PROCESS, 0x10),
        (ServiceType::SHARE_PROCESS, 0x20),
        (ServiceType::USER_OWN_PROCESS, 0x50),
        (ServiceType::USER_SHARE_PROCESS, 0x60),
        (ServiceType::INTERACTIVE_PROCESS, 0x100),
    ];
    for (service_type, literal) in types {
        let mut reported = status(ServiceExitCode::NO_ERROR, Duration::ZERO);
        reported.service_type = service_type;
        assert_eq!(
            raw_status(&reported).unwrap().dwServiceType.0,
            literal,
            "{service_type:?}"
        );
    }
    // A flag added to the crate's set must be added above.
    assert_eq!(
        ServiceType::all().bits(),
        types.iter().fold(0, |all, (_, literal)| all | literal)
    );
}

#[skuld::test]
fn service_specific_exit_code_is_reported_under_error_service_specific_error() {
    let raw = raw_status(&status(ServiceExitCode::ServiceSpecific(42), Duration::ZERO)).unwrap();
    assert_eq!(raw.dwWin32ExitCode, 1066);
    assert_eq!(raw.dwServiceSpecificExitCode, 42);
}

#[skuld::test]
fn a_wait_hint_of_exactly_u32_max_milliseconds_is_reported_unchanged() {
    let longest = Duration::from_millis(u64::from(u32::MAX));
    let raw = raw_status(&status(ServiceExitCode::NO_ERROR, longest)).unwrap();
    assert_eq!(raw.dwWaitHint, 4_294_967_295);
}

#[skuld::test]
fn a_wait_hint_that_overflows_the_wire_field_is_an_error_not_a_panic() {
    let too_long = Duration::from_millis(u64::from(u32::MAX) + 1);
    let err = raw_status(&status(ServiceExitCode::NO_ERROR, too_long)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}

// winsvc.h: SERVICE_STOPPED 1, SERVICE_START_PENDING 2, SERVICE_STOP_PENDING 3,
// SERVICE_RUNNING 4, SERVICE_CONTINUE_PENDING 5, SERVICE_PAUSE_PENDING 6,
// SERVICE_PAUSED 7. Written out per variant so a new `ServiceState` variant
// breaks this match instead of going unpinned.
#[skuld::test]
fn raw_status_reports_every_service_state_as_its_winsvc_constant() {
    let wire = |state: ServiceState| {
        let expected = match state {
            ServiceState::Stopped => 1,
            ServiceState::StartPending => 2,
            ServiceState::StopPending => 3,
            ServiceState::Running => 4,
            ServiceState::ContinuePending => 5,
            ServiceState::PausePending => 6,
            ServiceState::Paused => 7,
        };
        let mut reported = status(ServiceExitCode::NO_ERROR, Duration::ZERO);
        reported.current_state = state;
        (raw_status(&reported).unwrap().dwCurrentState.0, expected)
    };
    for state in [
        ServiceState::Stopped,
        ServiceState::StartPending,
        ServiceState::StopPending,
        ServiceState::Running,
        ServiceState::ContinuePending,
        ServiceState::PausePending,
        ServiceState::Paused,
    ] {
        let (raw, expected) = wire(state);
        assert_eq!(raw, expected, "{state:?}");
    }
}
