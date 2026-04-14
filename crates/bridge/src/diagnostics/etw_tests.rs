//! Unit tests for the pure `dispatch` seam. ETW-free by design: tests
//! construct `ParsedFields` directly and assert against `Emission`
//! enum variants, so no live ETW session or fake `EventRecord` is
//! required.

use super::*;

// Use a zeroed GUID as a throwaway — dispatch ignores the provider
// value in v1 (severity rules key on event_id). Having a concrete
// value in tests keeps signatures honest.
fn any_guid() -> GUID {
    GUID::from_u128(0)
}

const BRIDGE_PID: u32 = 12345;
const OTHER_PID: u32 = 99999;

// PID filter ==========================================================================================================

#[skuld::test]
fn dispatch_ignores_non_bridge_pid() {
    let got = dispatch(
        any_guid(),
        tcpip_events::CONNECT_COMPLETED,
        OTHER_PID,
        BRIDGE_PID,
        &ParsedFields::default(),
    );
    assert!(got.is_none(), "non-bridge pid must be dropped, got {got:?}");
}

#[skuld::test]
fn dispatch_emits_for_matching_pid() {
    let got = dispatch(
        any_guid(),
        tcpip_events::CONNECT_COMPLETED,
        BRIDGE_PID,
        BRIDGE_PID,
        &ParsedFields::default(),
    );
    assert!(matches!(got, Some(Emission::Info { .. })), "expected Info, got {got:?}");
}

// Severity routing ====================================================================================================

#[skuld::test]
fn dispatch_tcp_connect_completed_is_info() {
    let got = dispatch(
        any_guid(),
        tcpip_events::CONNECT_COMPLETED,
        BRIDGE_PID,
        BRIDGE_PID,
        &ParsedFields::default(),
    );
    assert!(matches!(got, Some(Emission::Info { .. })), "got {got:?}");
}

#[skuld::test]
fn dispatch_tcp_connect_request_timeout_is_warn() {
    let got = dispatch(
        any_guid(),
        tcpip_events::CONNECT_REQUEST_TIMEOUT,
        BRIDGE_PID,
        BRIDGE_PID,
        &ParsedFields::default(),
    );
    assert!(matches!(got, Some(Emission::Warn { .. })), "got {got:?}");
}

#[skuld::test]
fn dispatch_tcp_retransmit_timeout_is_warn() {
    let got = dispatch(
        any_guid(),
        tcpip_events::RETRANSMIT_TIMEOUT,
        BRIDGE_PID,
        BRIDGE_PID,
        &ParsedFields::default(),
    );
    assert!(matches!(got, Some(Emission::Warn { .. })), "got {got:?}");
}

#[skuld::test]
fn dispatch_tcp_abort_issued_is_warn() {
    let got = dispatch(
        any_guid(),
        tcpip_events::ABORT_ISSUED,
        BRIDGE_PID,
        BRIDGE_PID,
        &ParsedFields::default(),
    );
    assert!(matches!(got, Some(Emission::Warn { .. })), "got {got:?}");
}

// Retransmit threshold boundary =======================================================================================

#[skuld::test]
fn dispatch_retransmit_count_lt_threshold_is_info() {
    let fields = ParsedFields {
        rexmit_count: Some(RETRANSMIT_WARN_THRESHOLD - 1),
        ..Default::default()
    };
    let got = dispatch(
        any_guid(),
        tcpip_events::SEND_RETRANSMIT_ROUND,
        BRIDGE_PID,
        BRIDGE_PID,
        &fields,
    );
    assert!(
        matches!(got, Some(Emission::Info { .. })),
        "count {} should be info, got {got:?}",
        RETRANSMIT_WARN_THRESHOLD - 1
    );
}

#[skuld::test]
fn dispatch_retransmit_count_at_threshold_is_warn() {
    let fields = ParsedFields {
        rexmit_count: Some(RETRANSMIT_WARN_THRESHOLD),
        ..Default::default()
    };
    let got = dispatch(
        any_guid(),
        tcpip_events::SEND_RETRANSMIT_ROUND,
        BRIDGE_PID,
        BRIDGE_PID,
        &fields,
    );
    assert!(
        matches!(got, Some(Emission::Warn { .. })),
        "count {} should be warn, got {got:?}",
        RETRANSMIT_WARN_THRESHOLD
    );
}

#[skuld::test]
fn dispatch_retransmit_count_gt_threshold_is_warn() {
    let fields = ParsedFields {
        rexmit_count: Some(RETRANSMIT_WARN_THRESHOLD + 10),
        ..Default::default()
    };
    let got = dispatch(
        any_guid(),
        tcpip_events::TCB_CONNECT_REQUESTED,
        BRIDGE_PID,
        BRIDGE_PID,
        &fields,
    );
    assert!(matches!(got, Some(Emission::Warn { .. })), "got {got:?}");
}

// Unknown events ======================================================================================================

#[skuld::test]
fn dispatch_unknown_event_id_returns_unknown() {
    let got = dispatch(
        any_guid(),
        /*event_id=*/ 65500, // deliberately outside the known-IDs block
        BRIDGE_PID,
        BRIDGE_PID,
        &ParsedFields::default(),
    );
    assert_eq!(got, Some(Emission::Unknown));
}
