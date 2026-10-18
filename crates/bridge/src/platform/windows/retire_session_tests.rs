use windows_service::service::{ServiceActionType, ServiceFailureResetPeriod};

use super::no_restart_failure_actions;

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
