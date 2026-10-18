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
fn a_control_answer_that_is_a_race_is_not_a_failure() {
    // 1062: stopped between the observation and the control. 1061: no longer
    // in a state that takes a Stop.
    assert_eq!(classify_control_stop(1062), Ok(()));
    assert_eq!(classify_control_stop(1061), Ok(()));
}

#[skuld::test]
fn every_other_control_answer_is_a_failure_naming_the_call_and_the_code() {
    // 1053: the service did not respond to the start or control request in
    // time. 1052: the requested control is not valid for this service. 5:
    // access denied.
    for code in [1053, 1052, 5] {
        assert_eq!(
            classify_control_stop(code),
            Err(ScmCallError {
                call: ScmCall::ControlService,
                code
            })
        );
    }
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
