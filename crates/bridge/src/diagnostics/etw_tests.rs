//! Unit tests for the pure `dispatch` seam. ETW-free by design: tests
//! construct `ParsedFields` directly and assert against `Emission`
//! enum variants, so no live ETW session or fake `EventRecord` is
//! required.

use super::*;
use dump::dump;

// Zeroed GUID — matches no subscribed provider. Useful only for
// "non-TCPIP" tests since the dispatch provider gate (#393) routes
// anything not-TCPIP to `Emission::Unknown` regardless of event-id.
fn any_guid() -> GUID {
    GUID::from_u128(0)
}

/// TCPIP provider GUID, used by tests that exercise TCPIP-specific
/// severity routing (which is the only path that distinguishes
/// event-ids — see [`dispatch`]).
fn tcpip_guid() -> GUID {
    GUID::from(TCPIP_PROVIDER)
}

/// Winsock-AFD provider GUID. Used by tests that verify AFD events
/// with TCPIP-colliding IDs (1002, 1004, …) are not misclassified as
/// TCPIP per the provider gate added in bindreams/hole#393.
fn afd_guid() -> GUID {
    GUID::from(AFD_PROVIDER)
}

/// Microsoft-Windows-WFP provider GUID. Symmetric with `afd_guid()`
/// for WFP coverage.
fn wfp_guid() -> GUID {
    GUID::from(WFP_PROVIDER)
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
        tcpip_guid(),
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
        tcpip_guid(),
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
        tcpip_guid(),
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
        tcpip_guid(),
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
        tcpip_guid(),
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
        tcpip_guid(),
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
        tcpip_guid(),
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
        tcpip_guid(),
        tcpip_events::TCB_CONNECT_REQUESTED,
        BRIDGE_PID,
        BRIDGE_PID,
        &fields,
    );
    assert!(matches!(got, Some(Emission::Warn { .. })), "got {got:?}");
}

// Unknown events ======================================================================================================

#[skuld::test]
fn dispatch_unknown_event_id_from_tcpip_returns_unknown() {
    // TCPIP event with an ID outside the rich-handler table falls through
    // the match arm to Emission::Unknown.
    let got = dispatch(
        tcpip_guid(),
        /*event_id=*/ 65500, // deliberately outside the known-IDs block
        BRIDGE_PID,
        BRIDGE_PID,
        &ParsedFields::default(),
    );
    assert_eq!(got, Some(Emission::Unknown));
}

// Provider gate (bindreams/hole#393) ==================================================================================

#[skuld::test]
fn dispatch_afd_with_tcpip_colliding_id_returns_unknown() {
    // AFD event-id 1004 is TCB_SYN_SEND under TCPIP. Without the
    // provider gate, AFD would emit at INFO under "tcp event". With the
    // gate, AFD short-circuits to DEBUG-level Unknown.
    let got = dispatch(
        afd_guid(),
        tcpip_events::TCB_SYN_SEND,
        BRIDGE_PID,
        BRIDGE_PID,
        &ParsedFields::default(),
    );
    assert_eq!(got, Some(Emission::Unknown));
}

#[skuld::test]
fn dispatch_wfp_with_tcpip_colliding_id_returns_unknown() {
    // Symmetric coverage for WFP: a WFP event sharing a TCPIP event-id
    // must not be misclassified as TCPIP TCB_CONNECT_REQUESTED.
    let got = dispatch(
        wfp_guid(),
        tcpip_events::TCB_CONNECT_REQUESTED,
        BRIDGE_PID,
        BRIDGE_PID,
        &ParsedFields::default(),
    );
    assert_eq!(got, Some(Emission::Unknown));
}

#[skuld::test]
fn dispatch_unknown_provider_returns_unknown() {
    // Zero GUID is not subscribed; same short-circuit as AFD/WFP.
    let got = dispatch(
        any_guid(),
        tcpip_events::CONNECT_COMPLETED,
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
fn dispatch_non_tcpip_provider_with_high_volume_id_short_circuits_to_unknown() {
    // Event IDs collide across providers, but the provider gate
    // short-circuits AFD/WFP to Unknown BEFORE the drop list is
    // consulted. Either way the user-visible effect is the same: no
    // INFO spam from non-TCPIP background traffic.
    for &id in HIGH_VOLUME_TCPIP_EVENTS {
        let got = dispatch(afd_guid(), id, BRIDGE_PID, BRIDGE_PID, &ParsedFields::default());
        assert_eq!(
            got,
            Some(Emission::Unknown),
            "AFD event_id={id} should short-circuit to Unknown, got {got:?}"
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

// event_name ==========================================================================================================

/// A handful of `(constant, symbol)` pairs cross-checked directly against
/// `Microsoft-Windows-TCPIP.xml`'s `<event value=... symbol=...>` elements
/// (fetched from
/// <https://raw.githubusercontent.com/repnz/etw-providers-docs/master/Manifests-Win10-18990/Microsoft-Windows-TCPIP.xml>
/// during review) rather than copied from [`TCPIP_EVENT_NAMES`] itself —
/// this is a genuine spot check, not a restatement of the production
/// table, so a transcription error shared by both would still be caught.
/// Full ID-space coverage (every ID `dispatch` classifies has a name, and
/// vice versa) comes from the two drift-guard tests below, which read
/// [`TCPIP_EVENT_NAMES`] directly rather than duplicating it.
const TCPIP_EVENT_NAME_SPOT_CHECK: &[(u16, &str)] = &[
    (tcpip_events::TCB_CONNECT_REQUESTED, "TcpRequestConnect"),
    (tcpip_events::CONNECT_COMPLETED, "TcpConnectTcbComplete"),
    (tcpip_events::RETRANSMIT_TIMEOUT, "TcpDisconnectTcbRtoTimeout"),
];

#[skuld::test]
fn event_name_maps_manifest_verified_tcpip_event_ids() {
    for &(id, symbol) in TCPIP_EVENT_NAME_SPOT_CHECK {
        assert_eq!(
            event_name(tcpip_guid(), id),
            Some(symbol),
            "event_id={id} expected name {symbol:?}"
        );
    }
}

#[skuld::test]
fn event_name_unknown_tcpip_id_is_none() {
    assert_eq!(event_name(tcpip_guid(), 65500), None);
}

#[skuld::test]
fn event_name_non_tcpip_provider_is_none_even_for_colliding_id() {
    // AFD event-id 1004 collides with TCPIP TCB_SYN_SEND; event_name must
    // gate on provider the same way dispatch's provider gate does.
    assert_eq!(event_name(afd_guid(), tcpip_events::TCB_SYN_SEND), None);
}

#[skuld::test]
fn event_name_table_entries_are_all_dispatch_classified() {
    // Every ID TCPIP_EVENT_NAMES claims to name must actually be something
    // dispatch classifies (Info/Warn), not silently fall through to
    // Unknown — a stale table entry for an ID dispatch no longer
    // recognizes would pass event_name's own lookup but be pointless in
    // the emitted log. Reads the production table directly (not a test
    // fixture copy of it) — this test's job is checking table-vs-dispatch
    // agreement, not table-vs-manifest correctness (that's the spot check
    // above).
    for &(id, _) in TCPIP_EVENT_NAMES {
        let got = dispatch(tcpip_guid(), id, BRIDGE_PID, BRIDGE_PID, &ParsedFields::default());
        assert!(
            !matches!(got, None | Some(Emission::Unknown)),
            "event_id={id} is in TCPIP_EVENT_NAMES but dispatch does not classify it: {got:?}"
        );
    }
}

#[skuld::test]
fn every_dispatch_classified_tcpip_id_has_a_name() {
    // The real drift guard: enumerates the ID space independently of
    // TCPIP_EVENT_NAMES (NOT derived from it), so a future event added only
    // to dispatch's match — and never mirrored into the name table — fails
    // this test instead of silently degrading to `name: ~` in bridge.log.
    for id in 0u16..=u16::MAX {
        let got = dispatch(tcpip_guid(), id, BRIDGE_PID, BRIDGE_PID, &ParsedFields::default());
        if !matches!(got, None | Some(Emission::Unknown)) {
            assert!(
                event_name(tcpip_guid(), id).is_some(),
                "dispatch classifies TCPIP event_id={id} as {got:?} but event_name has no entry for it"
            );
        }
    }
}

// should_escalate =====================================================================================================

#[skuld::test]
fn should_escalate_true_on_first_nonzero_events_lost() {
    let mut last = LastSeenLoss::default();
    assert!(should_escalate(&mut last, 1, 0, 0));
    assert_eq!(last.events_lost, 1);
}

#[skuld::test]
fn should_escalate_false_on_unchanged_events_lost() {
    let mut last = LastSeenLoss::default();
    assert!(should_escalate(&mut last, 1, 0, 0));
    assert!(
        !should_escalate(&mut last, 1, 0, 0),
        "an unchanged cumulative count must not re-escalate"
    );
}

#[skuld::test]
fn should_escalate_true_again_on_further_increase_in_events_lost() {
    let mut last = LastSeenLoss::default();
    assert!(should_escalate(&mut last, 1, 0, 0));
    assert!(should_escalate(&mut last, 3, 0, 0));
    assert_eq!(last.events_lost, 3);
}

#[skuld::test]
fn should_escalate_true_on_first_nonzero_log_buffers_lost() {
    let mut last = LastSeenLoss::default();
    assert!(should_escalate(&mut last, 0, 7, 0));
    assert_eq!(last.log_buffers_lost, 7);
}

#[skuld::test]
fn should_escalate_false_on_unchanged_log_buffers_lost() {
    let mut last = LastSeenLoss::default();
    assert!(should_escalate(&mut last, 0, 7, 0));
    assert!(
        !should_escalate(&mut last, 0, 7, 0),
        "log_buffers_lost gets the same delta treatment as events_lost — no re-escalation on an unchanged reading"
    );
}

#[skuld::test]
fn should_escalate_true_on_first_nonzero_real_time_buffers_lost() {
    let mut last = LastSeenLoss::default();
    assert!(should_escalate(&mut last, 0, 0, 5));
    assert_eq!(last.real_time_buffers_lost, 5);
}

#[skuld::test]
fn should_escalate_false_on_unchanged_real_time_buffers_lost() {
    let mut last = LastSeenLoss::default();
    assert!(should_escalate(&mut last, 0, 0, 5));
    assert!(
        !should_escalate(&mut last, 0, 0, 5),
        "real_time_buffers_lost gets the same delta treatment as events_lost — no re-escalation on an unchanged reading"
    );
}

#[skuld::test]
fn should_escalate_true_on_wraparound_decrease() {
    // A u32 counter wrapping past u32::MAX reads back as a SMALLER value
    // than the last-seen high-water mark. `>` would silently treat this as
    // "no increase"; `!=` (what should_escalate actually uses) still
    // registers it as a change worth escalating.
    let mut last = LastSeenLoss {
        events_lost: 100,
        log_buffers_lost: 0,
        real_time_buffers_lost: 0,
    };
    assert!(should_escalate(&mut last, 5, 0, 0));
    assert_eq!(last.events_lost, 5);
}

// run_periodic_stats_inner ============================================================================================

#[skuld::test]
fn periodic_stats_thread_exits_promptly_on_sender_drop_not_after_the_interval() {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        run_periodic_stats_inner(
            "nonexistent-session-for-timing-test".into(),
            std::time::Duration::from_secs(3600),
            rx,
            |_tick_count| {},
        );
    });
    // Wakes the blocked recv_timeout via Disconnected immediately -- if it
    // instead waited out the 3600s interval, this test would hang, caught
    // by the shell-level timeout on the test invocation, not by a timeout
    // wrapped around the join itself.
    drop(tx);
    handle.join().expect("periodic stats thread panicked");
}

#[skuld::test]
fn periodic_tick_throttles_repeated_query_failures_to_info() {
    use crate::test_support::log_capture::VecWriter;
    use garter::tracing_test::set_default_in_current_thread;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let writer = VecWriter::new();
    // INFO, not DEBUG: matches the bridge's default file-sink level, so
    // this test proves the throttled repeat actually reaches bridge.log —
    // a DEBUG filter would pass even if the repeat were still logged at
    // debug! (the bug this test exists to catch).
    let subscriber = tracing_subscriber::registry().with(
        fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
    );
    let _guard = set_default_in_current_thread(subscriber);

    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let (tick_tx, tick_rx) = std::sync::mpsc::channel::<u32>();
    // `set_default_in_current_thread` installs a thread-local dispatcher, so
    // the spawned thread below (where run_periodic_stats_inner actually
    // logs) needs it propagated explicitly -- a fresh std::thread does not
    // inherit the spawning thread's tracing default.
    let dispatch = tracing::dispatcher::get_default(tracing::Dispatch::clone);
    let handle = std::thread::spawn(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            run_periodic_stats_inner(
                "hole-etw-nonexistent-session-for-tick-test".into(),
                std::time::Duration::from_millis(5),
                stop_rx,
                move |n| {
                    let _ = tick_tx.send(n);
                },
            );
        });
    });

    // Block on real tick completions -- a genuine rendezvous on a channel
    // the production loop itself writes into, not a sleep-then-check. Tick
    // 1 is the immediate baseline tick run_periodic_stats_inner performs
    // before its first recv_timeout wait; tick 2 is the first one driven by
    // the real 5ms interval.
    assert_eq!(tick_rx.recv().expect("first tick"), 1);
    assert_eq!(tick_rx.recv().expect("second tick"), 2);

    drop(stop_tx);
    handle.join().expect("periodic stats thread panicked");

    let output = writer.snapshot_string();
    assert_eq!(
        output.matches("etw: ControlTraceW(QUERY) failed").count(),
        1,
        "only the FIRST failed query should warn; got:\n{output}"
    );
    assert!(
        output.contains("etw: ControlTraceW(QUERY) still failing"),
        "the second failure should throttle to info (not silently to debug, which the bridge's \
         default file-sink level would discard); got:\n{output}"
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
        name: Some("TcpRequestConnect"),
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
name: TcpRequestConnect
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
        name: Some("TcpTcbSynSend"),
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
        name: Some("TcpConnectTcbComplete"),
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
