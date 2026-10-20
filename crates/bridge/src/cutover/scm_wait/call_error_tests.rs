use super::*;

#[skuld::test]
fn an_hresult_from_win32_yields_its_win32_code() {
    // HRESULT_FROM_WIN32 sets the severity bit and facility 7 (0x8007); the
    // codes are winerror.h's 1060, 1061, 1062 and 1072.
    assert_eq!(win32_code_of_hresult(0x8007_0424_u32 as i32), 1060);
    assert_eq!(win32_code_of_hresult(0x8007_0425_u32 as i32), 1061);
    assert_eq!(win32_code_of_hresult(0x8007_0426_u32 as i32), 1062);
    assert_eq!(win32_code_of_hresult(0x8007_0430_u32 as i32), 1072);
}

#[skuld::test]
fn an_hresult_outside_the_win32_facility_is_kept_whole() {
    // E_FAIL.
    assert_eq!(win32_code_of_hresult(0x8000_4005_u32 as i32), 0x8000_4005);
}

#[skuld::test]
fn a_failure_reads_with_the_call_name_and_the_code() {
    let message = ScmCallError {
        call: ScmCall::NotifyServiceStatusChange,
        code: 1072,
    }
    .to_string();
    assert!(message.starts_with("NotifyServiceStatusChange failed: "), "{message}");
    assert!(message.contains("1072"), "{message}");
}

#[skuld::test]
fn a_failure_survives_the_io_error_it_travels_in() {
    let error = ScmCallError {
        call: ScmCall::OpenService,
        code: 1060,
    }
    .into_io();
    let inner = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ScmCallError>())
        .expect("the typed failure is the io::Error's source");
    assert_eq!((inner.call, inner.code), (ScmCall::OpenService, 1060));
}

#[skuld::test]
fn each_call_has_its_win32_name() {
    let table = [
        (ScmCall::OpenScManager, "OpenSCManager"),
        (ScmCall::OpenService, "OpenService"),
        (ScmCall::NotifyServiceStatusChange, "NotifyServiceStatusChange"),
        (ScmCall::ControlService, "ControlService"),
        (ScmCall::StartService, "StartService"),
        (ScmCall::ChangeServiceConfig2, "ChangeServiceConfig2"),
        (ScmCall::QueryServiceConfig2, "QueryServiceConfig2"),
        (ScmCall::DeleteService, "DeleteService"),
        (ScmCall::QueryServiceStatusEx, "QueryServiceStatusEx"),
        (ScmCall::OpenProcess, "OpenProcess"),
        (ScmCall::OpenProcessToken, "OpenProcessToken"),
        (ScmCall::GetTokenInformation, "GetTokenInformation"),
        (ScmCall::LookupAccountName, "LookupAccountName"),
        (ScmCall::WaitForSingleObject, "WaitForSingleObject"),
        (ScmCall::CreateService, "CreateService"),
        (ScmCall::StartServiceCtrlDispatcher, "StartServiceCtrlDispatcher"),
    ];
    for (call, name) in table {
        assert_eq!(call.name(), name);
    }
}

#[skuld::test]
fn the_absent_service_codes_are_does_not_exist_and_marked_for_delete() {
    assert!(is_absent_service_code(1060));
    assert!(is_absent_service_code(1072));
    // Access denied, and the two control answers.
    for code in [5, 1061, 1062] {
        assert!(!is_absent_service_code(code), "{code}");
    }
}

#[skuld::test]
fn an_io_error_is_an_absent_service_in_either_shape() {
    assert!(io_error_is_absent_service(&io::Error::from_raw_os_error(1060)));
    assert!(io_error_is_absent_service(
        &ScmCallError {
            call: ScmCall::OpenService,
            code: 1072
        }
        .into_io()
    ));
    assert!(!io_error_is_absent_service(&io::Error::from_raw_os_error(5)));
    assert!(!io_error_is_absent_service(&io::Error::other("1060")));
}

#[skuld::test]
fn each_gone_code_names_its_own_kind() {
    assert_eq!(ServiceGone::of_code(1060), Some(ServiceGone::DoesNotExist));
    assert_eq!(ServiceGone::of_code(1072), Some(ServiceGone::MarkedForDeletion));
    // Access denied, the two control answers, and a service-disabled start.
    for code in [0, 5, 1061, 1062, 1058] {
        assert_eq!(ServiceGone::of_code(code), None, "{code}");
    }
}

#[skuld::test]
fn only_a_service_marked_for_deletion_still_answers_through_an_open_handle() {
    assert!(ServiceGone::MarkedForDeletion.answers_through_an_open_handle());
    assert!(!ServiceGone::DoesNotExist.answers_through_an_open_handle());
}

#[skuld::test]
fn a_gone_service_keeps_its_kind_in_every_shape_the_error_travels_in() {
    let bare = |code| io::Error::from_raw_os_error(code);
    let typed = |call, code| ScmCallError { call, code }.into_io();
    let winapi = |call: ScmCall, code| call.failed_with(&io::Error::from_raw_os_error(code));
    assert_eq!(service_gone(&bare(1060)), Some(ServiceGone::DoesNotExist));
    assert_eq!(service_gone(&bare(1072)), Some(ServiceGone::MarkedForDeletion));
    assert_eq!(
        service_gone(&typed(ScmCall::OpenService, 1060)),
        Some(ServiceGone::DoesNotExist)
    );
    assert_eq!(
        service_gone(&typed(ScmCall::NotifyServiceStatusChange, 1072)),
        Some(ServiceGone::MarkedForDeletion)
    );
    assert_eq!(
        service_gone(&winapi(ScmCall::ChangeServiceConfig2, 1072)),
        Some(ServiceGone::MarkedForDeletion)
    );
    assert_eq!(
        service_gone(&winapi(ScmCall::OpenService, 1060)),
        Some(ServiceGone::DoesNotExist)
    );
}

#[skuld::test]
fn a_failure_that_is_not_a_gone_service_has_no_kind() {
    assert_eq!(service_gone(&io::Error::from_raw_os_error(5)), None);
    assert_eq!(service_gone(&io::Error::other("1060")), None);
    assert_eq!(service_gone(&io::Error::other("marked for deletion")), None);
    assert_eq!(
        service_gone(
            &ScmCallError {
                call: ScmCall::ControlService,
                code: 1062
            }
            .into_io()
        ),
        None
    );
}

/// The old and the new classification agree until the old one is deleted.
#[skuld::test]
fn the_gone_kinds_are_exactly_the_absent_service_codes() {
    for code in 0..=2000_u32 {
        assert_eq!(
            ServiceGone::of_code(code).is_some(),
            is_absent_service_code(code),
            "{code}"
        );
    }
}

/// `windows_service::Error::Winapi` displays as "IO error in winapi call" and
/// keeps the OS error only as its source, so a call that returns one reaches a
/// log with neither its name nor its code unless it is re-typed here.
#[skuld::test]
fn a_winapi_failure_reads_with_its_call_and_its_code() {
    // 5: access denied. 1072: marked for delete. 1722: the RPC server is unavailable.
    for (call, name, code) in [
        (ScmCall::ChangeServiceConfig2, "ChangeServiceConfig2", 5),
        (ScmCall::DeleteService, "DeleteService", 1072),
        (ScmCall::QueryServiceStatusEx, "QueryServiceStatusEx", 1722),
        (ScmCall::OpenService, "OpenService", 5),
        (ScmCall::OpenScManager, "OpenSCManager", 5),
    ] {
        let error = call.failed_with(&io::Error::from_raw_os_error(code));
        let message = error.to_string();
        assert!(message.starts_with(&format!("{name} failed")), "{message}");
        assert!(message.contains(&code.to_string()), "{message}");
        let typed = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<ScmCallError>())
            .expect("the failure is typed");
        assert_eq!((typed.call, typed.code), (call, code as u32));
    }
}

#[skuld::test]
fn a_winapi_failure_still_says_the_service_is_gone_when_its_code_does() {
    assert!(io_error_is_absent_service(
        &ScmCall::OpenService.failed_with(&io::Error::from_raw_os_error(1060))
    ));
    assert!(io_error_is_absent_service(
        &ScmCall::QueryServiceStatusEx.failed_with(&io::Error::from_raw_os_error(1072))
    ));
    assert!(!io_error_is_absent_service(
        &ScmCall::DeleteService.failed_with(&io::Error::from_raw_os_error(5))
    ));
}

#[skuld::test]
fn a_failure_without_a_win32_code_still_names_its_call() {
    let message = ScmCall::DeleteService
        .failed_with(&io::Error::other("no code"))
        .to_string();
    assert!(message.contains("DeleteService"), "{message}");
    assert!(message.contains("no code"), "{message}");
}

/// Written from the calls themselves: opening a process, and opening and
/// reading its token to prove whose it is, are the two reads of the process
/// itself. Resolving the service's SID reads no process.
#[skuld::test]
fn only_opening_and_identifying_the_process_is_opening_the_service_process() {
    let others = [
        ScmCall::OpenScManager,
        ScmCall::OpenService,
        ScmCall::NotifyServiceStatusChange,
        ScmCall::ControlService,
        ScmCall::StartService,
        ScmCall::ChangeServiceConfig2,
        ScmCall::QueryServiceConfig2,
        ScmCall::DeleteService,
        ScmCall::QueryServiceStatusEx,
        ScmCall::WaitForSingleObject,
        ScmCall::CreateService,
        ScmCall::StartServiceCtrlDispatcher,
        ScmCall::LookupAccountName,
    ];
    assert!(ScmCall::OpenProcess.is_opening_the_service_process());
    assert!(ScmCall::OpenProcessToken.is_opening_the_service_process());
    assert!(ScmCall::GetTokenInformation.is_opening_the_service_process());
    for call in others {
        assert!(!call.is_opening_the_service_process(), "{call:?}");
    }
}

#[skuld::test]
fn a_refused_process_open_is_told_from_any_other_failure_by_its_type() {
    let refused = ScmCallError {
        call: ScmCall::OpenProcess,
        code: 5,
    }
    .into_io();
    assert!(io_error_is_a_refused_process_open(&refused));
    let other = ScmCallError {
        call: ScmCall::ControlService,
        code: 5,
    }
    .into_io();
    assert!(!io_error_is_a_refused_process_open(&other));
    assert!(!io_error_is_a_refused_process_open(&io::Error::other(
        "OpenProcess failed"
    )));
    assert!(!io_error_is_a_refused_process_open(&io::Error::from_raw_os_error(5)));
}
