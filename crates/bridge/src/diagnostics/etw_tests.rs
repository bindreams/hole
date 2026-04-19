//! Unit tests for the pure `dispatch` seam. ETW-free by design: tests
//! construct `ParsedFields` directly and assert against `Emission`
//! enum variants, so no live ETW session or fake `EventRecord` is
//! required.

use super::*;
use dump::dump;

// Zeroed GUID — matches no subscribed provider, used where the test is
// about PID filtering or severity rules and not provider-scoped filters.
fn any_guid() -> GUID {
    GUID::from_u128(0)
}

/// TCPIP provider GUID, used by tests that check the
/// [`HIGH_VOLUME_TCPIP_EVENTS`] drop list (which only fires for TCPIP).
fn tcpip_guid() -> GUID {
    GUID::from(TCPIP_PROVIDER)
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

// High-volume TCPIP drop list =========================================================================================

#[skuld::test]
fn dispatch_drops_high_volume_tcpip_events() {
    // Every entry in the drop list must produce None when the provider is TCPIP.
    for &id in HIGH_VOLUME_TCPIP_EVENTS {
        let got = dispatch(tcpip_guid(), id, BRIDGE_PID, BRIDGE_PID, &ParsedFields::default());
        assert!(
            got.is_none(),
            "event_id={id} is in HIGH_VOLUME_TCPIP_EVENTS; expected None from TCPIP, got {got:?}"
        );
    }
}

#[skuld::test]
fn dispatch_keeps_high_volume_event_ids_on_non_tcpip_providers() {
    // Event IDs collide across providers; a high-volume TCPIP event ID
    // from AFD or WFP must not be dropped.
    for &id in HIGH_VOLUME_TCPIP_EVENTS {
        let got = dispatch(any_guid(), id, BRIDGE_PID, BRIDGE_PID, &ParsedFields::default());
        assert_eq!(
            got,
            Some(Emission::Unknown),
            "event_id={id} from non-TCPIP provider should fall through to Unknown, got {got:?}"
        );
    }
}

#[skuld::test]
fn dispatch_syn_send_event_is_info_not_dropped() {
    // Event 1004 (TcpTcbSynSend) was previously filtered out by the
    // `ut:SendPath` kernel-keyword mask. The mask has been removed;
    // dispatch must produce an info emission for it.
    let got = dispatch(
        tcpip_guid(),
        tcpip_events::TCB_SYN_SEND,
        BRIDGE_PID,
        BRIDGE_PID,
        &ParsedFields::default(),
    );
    assert!(
        matches!(got, Some(Emission::Info { .. })),
        "event 1004 must be Info, got {got:?}"
    );
}

#[skuld::test]
fn dispatch_connect_restricted_send_event_is_info() {
    let got = dispatch(
        tcpip_guid(),
        tcpip_events::CONNECT_RESTRICTED_SEND,
        BRIDGE_PID,
        BRIDGE_PID,
        &ParsedFields::default(),
    );
    assert!(
        matches!(got, Some(Emission::Info { .. })),
        "event 1031 must be Info, got {got:?}"
    );
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
    assert_eq!(
        got,
        Some(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 8080))
    );
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
    assert_eq!(
        got,
        Some(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(10, 20, 30, 40)),
            49152
        ))
    );
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
    assert_eq!(got, Some(SocketAddr::new(IpAddr::V6(expected_addr), 80)));
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

// ParsedFields shape ==================================================================================================

#[skuld::test]
fn parsed_fields_default_has_no_endpoints() {
    let pf = ParsedFields::default();
    assert!(pf.local.is_none());
    assert!(pf.remote.is_none());
    assert!(pf.status.is_none());
    assert!(pf.rexmit_count.is_none());
    assert!(pf.tcb.is_none());
}

#[skuld::test]
fn parsed_fields_populated_with_socketaddr() {
    let pf = ParsedFields {
        local: Some("192.168.1.5:54321".parse().unwrap()),
        remote: Some("8.8.8.8:443".parse().unwrap()),
        status: Some(0),
        rexmit_count: Some(2),
        tcb: Some(0xDEAD_BEEF),
    };
    assert_eq!(pf.local.unwrap().port(), 54321);
    assert_eq!(pf.remote.unwrap().ip().to_string(), "8.8.8.8");
}

// Provider name decoding ==============================================================================================

#[skuld::test]
fn provider_name_known_tcpip_returns_microsoft_name() {
    assert_eq!(provider_name(GUID::from(TCPIP_PROVIDER)), "Microsoft-Windows-TCPIP");
}

#[skuld::test]
fn provider_name_known_wfp_returns_microsoft_name() {
    assert_eq!(provider_name(GUID::from(WFP_PROVIDER)), "Microsoft-Windows-WFP");
}

#[skuld::test]
fn provider_name_known_afd_returns_microsoft_name() {
    assert_eq!(provider_name(GUID::from(AFD_PROVIDER)), "Microsoft-Windows-Winsock-AFD");
}

// EventView dump rendering ============================================================================================

#[skuld::test]
fn event_view_dump_uses_kebab_case_keys_and_yaml_primitives() {
    let view = EventView {
        event_id: 1002,
        opcode: 16,
        provider: "Microsoft-Windows-TCPIP",
        tcb: Some(0x1234_ABCD),
        local: Some("192.168.1.5:54321".parse().unwrap()),
        remote: Some("8.8.8.8:443".parse().unwrap()),
        status: Some(0),
        rexmit_count: None,
    };
    let yaml = format!("{}", dump!(&view));
    assert_eq!(
        yaml,
        "\
event-id: 1002
opcode: 16
provider: Microsoft-Windows-TCPIP
tcb: 305441741
local: 192.168.1.5:54321
remote: 8.8.8.8:443
status: 0
rexmit-count: ~"
    );
}

#[skuld::test]
fn event_view_dump_renders_all_none_endpoints_as_tilde() {
    let view = EventView {
        event_id: 1004,
        opcode: 1,
        provider: "Microsoft-Windows-TCPIP",
        tcb: Some(42),
        local: None,
        remote: None,
        status: None,
        rexmit_count: None,
    };
    let yaml = format!("{}", dump!(&view));
    assert!(yaml.contains("local: ~"), "expected `local: ~`, got:\n{yaml}");
    assert!(yaml.contains("remote: ~"), "expected `remote: ~`, got:\n{yaml}");
    assert!(yaml.contains("status: ~"), "expected `status: ~`, got:\n{yaml}");
    assert!(yaml.contains("tcb: 42"), "expected `tcb: 42`, got:\n{yaml}");
}

#[skuld::test]
fn event_view_dump_renders_socketaddr_inline_not_nested() {
    let view = EventView {
        event_id: 1033,
        opcode: 16,
        provider: "Microsoft-Windows-TCPIP",
        tcb: None,
        local: Some("[::1]:443".parse().unwrap()),
        remote: None,
        status: None,
        rexmit_count: None,
    };
    let yaml = format!("{}", dump!(&view));
    // Bracket form is the standard IPv6 `SocketAddr::Display` output;
    // the leading `[` triggers YAML quoting per `dump::format::needs_quoting`.
    assert!(
        yaml.contains("local: \"[::1]:443\""),
        "expected quoted IPv6 socket addr, got:\n{yaml}"
    );
}

#[skuld::test]
fn provider_name_unknown_returns_guid_string() {
    // An unknown GUID must still carry diagnostic value — we fall back to
    // the raw GUID rendering so logs don't lose the provider identity when
    // the table ages out of date.
    let unknown = GUID::from_u128(0xDEAD_BEEF_CAFE_F00D_1234_5678_9ABC_DEF0);
    let got = provider_name(unknown);
    assert!(
        got.contains("DEAD") || got.contains("dead"),
        "expected unknown GUID to be rendered, got {got:?}"
    );
    assert_ne!(got, "unknown", "must preserve GUID, not return literal \"unknown\"");
}
