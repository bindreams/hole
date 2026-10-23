use windows_service::service::{ServiceActionType, ServiceFailureResetPeriod, ServiceStartType};

use super::{no_restart_failure_actions, scm_start_type, start_type_from, RetireSession};
use crate::platform::os::StartTypeLock;
use crate::service_scm::retire::{Opening, StartWrite};
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

/// An entry the SCM no longer has still has processes to wait out, and an
/// install that registered and started the service meanwhile would hand that
/// wait a live service: the survivors hold the lock until they are dropped.
#[skuld::test]
fn the_survivors_of_an_absent_entry_hold_the_start_type_lock() {
    let lock = StartTypeLock::scratch("retire-absent");
    let Ok(Opening::Absent(survivors)) =
        RetireSession::open_named(&lock, "HoleBridgeNoSuchServiceForTests", || panic!("nothing holds it"))
    else {
        panic!("a service no one registered has no entry");
    };
    assert!(lock.is_held_for_another_thread(), "the survivors wait holds it");
    drop(survivors);
    assert!(!lock.is_held_for_another_thread(), "released with the survivors");
}

#[skuld::test]
fn opening_a_retirement_waits_for_the_start_type_lock() {
    let lock = StartTypeLock::scratch("retire-open");
    let opened = lock.while_another_waits(|on_busy| RetireSession::open_noting(&lock, on_busy).is_ok());
    assert!(opened);
    assert!(!lock.is_held_for_another_thread(), "released with the session");
}
