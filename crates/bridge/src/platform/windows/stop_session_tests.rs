use windows_service::service::ServiceAccess;

use super::stop_access;

/// The calls the session makes on its handle, each with the right the SCM's
/// documentation names for it. The session opens exactly their union: a
/// missing right is an access-denied reported at run time, an extra one is
/// authority nothing uses.
#[skuld::test]
fn the_stop_handle_carries_exactly_the_rights_its_calls_need() {
    let needs = [
        ("QueryServiceStatusEx", ServiceAccess::QUERY_STATUS),
        ("ControlService, stop", ServiceAccess::STOP),
    ];
    let union = needs
        .iter()
        .fold(ServiceAccess::empty(), |all, (_, right)| all | *right);
    let opened = stop_access();
    for (call, right) in needs {
        assert!(opened.contains(right), "{call} needs {right:?}; opened {opened:?}");
    }
    assert_eq!(opened, union);
}
