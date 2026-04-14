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

// parse_socket_address ================================================================================================

#[skuld::test]
fn parse_socket_address_ipv4_loopback_port_8080() {
    // SOCKADDR_IN: family(2 LE) + port(2 BE) + addr(4 BE) + padding.
    // family=AF_INET=2, port=8080 (0x1F90), addr=127.0.0.1
    let bytes = [
        0x02, 0x00, // family = 2 (little-endian)
        0x1F, 0x90, // port = 8080 (big-endian)
        127, 0, 0, 1, // addr = 127.0.0.1
        0, 0, 0, 0, 0, 0, 0, 0, // sin_zero padding
    ];
    let got = parse_socket_address(&bytes);
    assert_eq!(got, Some((IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 8080)));
}

#[skuld::test]
fn parse_socket_address_ipv4_arbitrary_port() {
    let bytes = [
        0x02, 0x00, // AF_INET
        0xC0, 0x00, // port = 49152 (0xC000)
        10, 20, 30, 40, // addr = 10.20.30.40
        0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let got = parse_socket_address(&bytes);
    assert_eq!(got, Some((IpAddr::V4(std::net::Ipv4Addr::new(10, 20, 30, 40)), 49152)));
}

#[skuld::test]
fn parse_socket_address_ipv6_loopback() {
    // SOCKADDR_IN6: family(2 LE) + port(2 BE) + flowinfo(4) + addr(16) + scope_id(4)
    let mut bytes = vec![
        0x17, 0x00, // family = 23 (AF_INET6)
        0x00, 0x50, // port = 80
        0, 0, 0, 0, // flowinfo
    ];
    // addr = ::1 (all zeros except last byte = 1)
    bytes.extend_from_slice(&[0u8; 15]);
    bytes.push(1);
    bytes.extend_from_slice(&[0, 0, 0, 0]); // scope_id

    let got = parse_socket_address(&bytes);
    let expected_addr = std::net::Ipv6Addr::LOCALHOST;
    assert_eq!(got, Some((IpAddr::V6(expected_addr), 80)));
}

#[skuld::test]
fn parse_socket_address_too_short_returns_none() {
    assert_eq!(parse_socket_address(&[]), None);
    assert_eq!(parse_socket_address(&[0x02, 0x00, 0x00]), None); // 3 bytes, <4 header
    assert_eq!(
        parse_socket_address(&[0x02, 0x00, 0x00, 0x50, 127, 0]), // AF_INET but only 6 bytes
        None
    );
    assert_eq!(
        parse_socket_address(&[0x17, 0x00, 0x00, 0x50, 0, 0, 0, 0]), // AF_INET6 but only 8 bytes
        None
    );
}

#[skuld::test]
fn parse_socket_address_unknown_family_returns_none() {
    // family = 17 (AF_NETBIOS) — not one we handle
    let bytes = [0x11, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(parse_socket_address(&bytes), None);
}
