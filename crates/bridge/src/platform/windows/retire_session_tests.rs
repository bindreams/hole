use windows_service::service::{ServiceActionType, ServiceFailureResetPeriod, ServiceStartType};

use super::{no_restart_failure_actions, scm_start_type, start_type_from};
use crate::cutover::scm_wait::retire::StartWrite;
use crate::service_start::StartType;

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
