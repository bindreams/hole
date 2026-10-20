use windows_service::service::{ServiceAccess, ServiceActionType, ServiceFailureResetPeriod, ServiceStartType};

use super::{no_restart_failure_actions, scm_start_type, session_access, start_type_from};
use crate::cutover::scm_wait::retire::{StartType, StartWrite};

#[skuld::test]
fn the_disabled_restart_restarts_nothing_and_keeps_the_reset_period() {
    let actions = no_restart_failure_actions();
    let list = actions.actions.as_deref().expect("an explicit action list");
    assert!(!list.is_empty(), "an empty list would leave the existing actions alone");
    assert!(list.iter().all(|a| a.action_type == ServiceActionType::None));
    assert!(matches!(
        actions.reset_period,
        ServiceFailureResetPeriod::After(d) if d == std::time::Duration::from_secs(86_400)
    ));
}

#[skuld::test]
fn each_start_type_the_scm_reports_is_one_the_retirement_knows() {
    let table = [
        (ServiceStartType::AutoStart, StartType::Auto),
        (ServiceStartType::OnDemand, StartType::Demand),
        (ServiceStartType::Disabled, StartType::Disabled),
        (ServiceStartType::SystemStart, StartType::Other),
        (ServiceStartType::BootStart, StartType::Other),
    ];
    for (reported, known) in table {
        assert_eq!(start_type_from(reported), known, "{reported:?}");
    }
}

#[skuld::test]
fn each_start_type_the_retirement_writes_is_the_scm_one_it_names() {
    // SERVICE_AUTO_START 2, SERVICE_DEMAND_START 3, SERVICE_DISABLED 4.
    for (written, raw) in [
        (StartWrite::Auto, 2),
        (StartWrite::Demand, 3),
        (StartWrite::Disabled, 4),
    ] {
        assert_eq!(scm_start_type(written).to_raw(), raw, "{written:?}");
    }
}

/// Each call the session makes on its handle, with the right the SCM's
/// documentation names for it. The session opens exactly their union: a missing
/// right is an access-denied the call reports at run time, an extra one is
/// authority nothing uses.
#[skuld::test]
fn the_session_handle_carries_exactly_the_rights_its_calls_need() {
    let needs = [
        ("QueryServiceStatusEx", ServiceAccess::QUERY_STATUS),
        ("QueryServiceConfig", ServiceAccess::QUERY_CONFIG),
        ("ChangeServiceConfigW", ServiceAccess::CHANGE_CONFIG),
        (
            "ChangeServiceConfig2W, any failure actions",
            ServiceAccess::CHANGE_CONFIG,
        ),
        // "If the service controller handles the SC_ACTION_RESTART action,
        // hService must have the SERVICE_START access right."
        ("ChangeServiceConfig2W, a restart action", ServiceAccess::START),
        ("ControlService, stop", ServiceAccess::STOP),
        ("DeleteService", ServiceAccess::DELETE),
    ];
    let union = needs
        .iter()
        .fold(ServiceAccess::empty(), |all, (_, right)| all | *right);
    let opened = session_access();
    for (call, right) in needs {
        assert!(opened.contains(right), "{call} needs {right:?}; opened {opened:?}");
    }
    assert_eq!(opened, union);
}
