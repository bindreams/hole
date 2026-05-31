use super::sitrep::*;

#[skuld::test]
fn hello_round_trips() {
    let line = r#"{"event":"hello","protocol":"sitrep-1.0.0"}"#;
    let ev = parse_event(line).expect("valid").expect("an event");
    assert!(matches!(ev, SitrepEvent::Hello { .. }));
    if let SitrepEvent::Hello { protocol } = ev {
        assert_eq!(protocol, "sitrep-1.0.0");
    }
}

#[skuld::test]
fn ready_round_trips_with_transports() {
    let line = r#"{"event":"ready","listen":"127.0.0.1:52344","transports":["tcp","udp"]}"#;
    let ev = parse_event(line).expect("valid").expect("an event");
    match ev {
        SitrepEvent::Ready { listen, transports } => {
            assert_eq!(listen, "127.0.0.1:52344".parse().unwrap());
            assert_eq!(transports, Transports::TCP | Transports::UDP);
        }
        other => panic!("expected Ready, got {other:?}"),
    }
}

#[skuld::test]
fn bind_conflict_round_trips() {
    let line = r#"{"event":"bind_conflict","errno":48,"addr":"127.0.0.1:1984"}"#;
    let ev = parse_event(line).expect("valid").expect("an event");
    match ev {
        SitrepEvent::BindConflict { errno, addr } => {
            assert_eq!(errno, 48);
            assert_eq!(addr, "127.0.0.1:1984".parse().unwrap());
        }
        other => panic!("expected BindConflict, got {other:?}"),
    }
}

#[skuld::test]
fn fatal_round_trips() {
    let line = r#"{"event":"fatal","detail":"config invalid"}"#;
    let ev = parse_event(line).expect("valid").expect("an event");
    assert!(matches!(ev, SitrepEvent::Fatal { .. }));
}

#[skuld::test]
fn non_json_line_is_log_passthrough() {
    // A non-JSON line is not an error and not an event — it's a log line.
    assert_eq!(parse_event("plain log text").unwrap(), None);
}

#[skuld::test]
fn unknown_event_is_ignored_not_error() {
    // Forward-compat: an unknown `event` parses to None (ignored), not Err.
    let line = r#"{"event":"some_future_event","x":1}"#;
    assert_eq!(parse_event(line).unwrap(), None);
}

#[skuld::test]
fn json_without_event_key_is_log_passthrough() {
    // A JSON object that isn't a sitrep envelope (no `event`) is a log line.
    assert_eq!(parse_event(r#"{"level":"info","msg":"hi"}"#).unwrap(), None);
}

#[skuld::test]
fn is_hello_handshake_detects_sitrep_prefix() {
    assert!(is_hello_handshake(r#"{"event":"hello","protocol":"sitrep-1.0.0"}"#));
    assert!(!is_hello_handshake("plain log"));
    assert!(!is_hello_handshake(r#"{"event":"ready","listen":"127.0.0.1:1"}"#));
}

#[skuld::test]
fn major_version_gate_accepts_same_major() {
    assert_eq!(protocol_support("sitrep-1.0.0"), ProtocolSupport::Supported);
    assert_eq!(protocol_support("sitrep-1.9.3"), ProtocolSupport::Supported);
}

#[skuld::test]
fn major_version_gate_falls_back_on_unknown_major() {
    assert_eq!(protocol_support("sitrep-2.0.0"), ProtocolSupport::FallBackToTier2);
}

#[skuld::test]
fn malformed_protocol_falls_back() {
    assert_eq!(protocol_support("garbage"), ProtocolSupport::FallBackToTier2);
    assert_eq!(protocol_support("sitrep-notsemver"), ProtocolSupport::FallBackToTier2);
}

#[skuld::test]
fn empty_transports_deserializes_to_empty_set() {
    let line = r#"{"event":"ready","listen":"127.0.0.1:1","transports":[]}"#;
    let ev = parse_event(line).expect("valid").expect("an event");
    match ev {
        SitrepEvent::Ready { transports, .. } => assert!(transports.is_empty()),
        other => panic!("expected Ready, got {other:?}"),
    }
}

#[skuld::test]
fn ready_serializes_to_canonical_wire_form() {
    let ev = SitrepEvent::Ready {
        listen: "127.0.0.1:1984".parse().unwrap(),
        transports: Transports::TCP,
    };
    assert_eq!(
        serde_json::to_string(&ev).unwrap(),
        r#"{"event":"ready","listen":"127.0.0.1:1984","transports":["tcp"]}"#
    );
}

#[skuld::test]
fn ready_serializes_tcp_before_udp() {
    // Pin transport ordering in the serialized array (TCP first, then UDP).
    let ev = SitrepEvent::Ready {
        listen: "127.0.0.1:1984".parse().unwrap(),
        transports: Transports::TCP | Transports::UDP,
    };
    assert_eq!(
        serde_json::to_string(&ev).unwrap(),
        r#"{"event":"ready","listen":"127.0.0.1:1984","transports":["tcp","udp"]}"#
    );
}

#[skuld::test]
fn hello_serializes_to_canonical_wire_form() {
    let ev = SitrepEvent::Hello {
        protocol: SITREP_PROTOCOL.to_string(),
    };
    assert_eq!(
        serde_json::to_string(&ev).unwrap(),
        r#"{"event":"hello","protocol":"sitrep-1.0.0"}"#
    );
}

#[skuld::test]
fn bind_conflict_serializes_to_canonical_wire_form() {
    let ev = SitrepEvent::BindConflict {
        errno: 48,
        addr: "127.0.0.1:1984".parse().unwrap(),
    };
    assert_eq!(
        serde_json::to_string(&ev).unwrap(),
        r#"{"event":"bind_conflict","errno":48,"addr":"127.0.0.1:1984"}"#
    );
}

#[skuld::test]
fn fatal_omits_errno_key_when_none() {
    // skip_serializing_if = Option::is_none → no "errno" key on the wire.
    let ev = SitrepEvent::Fatal {
        detail: "config invalid".to_string(),
        errno: None,
    };
    assert_eq!(
        serde_json::to_string(&ev).unwrap(),
        r#"{"event":"fatal","detail":"config invalid"}"#
    );
}

#[skuld::test]
fn fatal_includes_errno_key_when_some() {
    let ev = SitrepEvent::Fatal {
        detail: "boom".to_string(),
        errno: Some(13),
    };
    assert_eq!(
        serde_json::to_string(&ev).unwrap(),
        r#"{"event":"fatal","detail":"boom","errno":13}"#
    );
}
