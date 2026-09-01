use super::*;

#[skuld::test]
fn guid_conversion_round_trips() {
    let g = spec::Guid(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    let win = GUID::from_u128(g.0);
    assert_eq!(win.to_u128(), g.0);
}

/// `engage` must surface a failed engine open as a typed error, never a
/// silent `Ok` — an `Ok` here would mean the confinement engaged nothing
/// while `start_inner` believes DNS is confined. Drives `engage_outcome`
/// directly with a simulated failure so the property holds regardless of
/// this process's real privilege.
#[skuld::test]
fn engage_returns_a_typed_error_when_the_engine_cannot_be_opened() {
    let simulated_open_failure = Err(classify(Stage::EngineOpen, 5));
    let result = engage_outcome(simulated_open_failure, |_engine| {
        panic!("run_transaction must not run when the engine failed to open")
    });
    match result {
        Err(DnsConfineError::EngineOpen(_)) => {}
        Err(e) => panic!("a failed engine open must surface as EngineOpen, got {e:?}"),
        Ok(_) => panic!("a failed engine open must surface as a typed Err, got Ok"),
    }
}

/// Same guarantee as above, for the other gating stage: a transaction
/// failure (`AddFilter`/`Commit`) must also surface as a typed error, never
/// a silent `Ok`.
#[skuld::test]
fn engage_returns_a_typed_error_when_the_transaction_fails() {
    let result = engage_outcome(Ok(HANDLE::default()), |_engine| Err(classify(Stage::AddFilter, 5)));
    match result {
        Err(DnsConfineError::AddFilter(_)) => {}
        Err(e) => panic!("a failed transaction must surface as AddFilter, got {e:?}"),
        Ok(_) => panic!("a failed transaction must surface as a typed Err, got Ok"),
    }
}

#[skuld::test]
fn filter_failures_classify_as_add_filter() {
    match classify(Stage::AddFilter, 5) {
        DnsConfineError::AddFilter(_) => {}
        other => panic!("Stage::AddFilter must classify as AddFilter, got {other:?}"),
    }
    match classify(Stage::Commit, 5) {
        DnsConfineError::AddFilter(_) => {}
        other => panic!("Stage::Commit must classify as AddFilter, got {other:?}"),
    }
    match classify(Stage::EngineOpen, 5) {
        DnsConfineError::EngineOpen(_) => {}
        other => panic!("Stage::EngineOpen must classify as EngineOpen, got {other:?}"),
    }
}
