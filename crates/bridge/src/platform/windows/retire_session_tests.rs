use super::*;

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
fn every_state_the_bridge_can_be_in_is_an_observation() {
    assert_eq!(
        observed_from_service_state(ServiceState::Running),
        Some(Observed::Running)
    );
    assert_eq!(
        observed_from_service_state(ServiceState::Stopped),
        Some(Observed::Stopped)
    );
    assert_eq!(
        observed_from_service_state(ServiceState::StartPending),
        Some(Observed::StartPending)
    );
    assert_eq!(
        observed_from_service_state(ServiceState::StopPending),
        Some(Observed::StopPending)
    );
}

#[skuld::test]
fn the_pause_states_are_not_an_observation() {
    for state in [
        ServiceState::ContinuePending,
        ServiceState::PausePending,
        ServiceState::Paused,
    ] {
        assert_eq!(observed_from_service_state(state), None);
    }
}
