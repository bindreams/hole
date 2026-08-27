use std::net::{IpAddr, Ipv4Addr};

use super::*;

#[skuld::test]
fn guid_conversion_round_trips() {
    let g = spec::Guid(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
    let win = GUID::from_u128(g.0);
    assert_eq!(win.to_u128(), g.0);
}

/// The one FFI path in this module that is reachable on an unelevated
/// workstation. Measured empirically on this box: `FwpmEngineOpen0` for a
/// *dynamic* session succeeds without elevation, but the first mutating
/// call — `FwpmProviderAdd0`/`FwpmFilterAdd0` inside the transaction —
/// fails with "Access is denied" (os error 5), which `classify` maps to
/// `DnsConfineError::AddFilter`. `engage` must surface that as a typed
/// error either way — never a panic, and never a silent `Ok` that would
/// mean the confinement engaged nothing while `start_inner` believes DNS
/// is confined. A box where even the engine open itself is blocked would
/// legitimately report `EngineOpen` instead, so both variants are accepted
/// here — what this test pins is "always a typed Err, never Ok, never a
/// panic," not which specific stage fails on which machine.
#[skuld::test]
fn engage_without_elevation_returns_a_typed_error() {
    let server_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let result = engage(0, server_ip, &[]);
    match result {
        Err(DnsConfineError::EngineOpen(_)) | Err(DnsConfineError::AddFilter(_)) => {}
        Ok(_) => panic!("engage() succeeded without elevation — this box is unexpectedly elevated"),
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
