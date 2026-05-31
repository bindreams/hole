use std::net::SocketAddr;

use garter::{ChainReady, SitrepEvent, StartError, Transports};

use crate::sitrep_out::{chain_result_to_event, GALOSHES_TRANSPORTS};

fn addr() -> SocketAddr {
    "127.0.0.1:1080".parse().unwrap()
}

#[skuld::test]
fn galoshes_transports_is_tcp_and_udp() {
    // The load-bearing constant: galoshes advertises BOTH transports
    // (its YAMUX capability), regardless of the inner v2ray TCP-only hop.
    assert_eq!(GALOSHES_TRANSPORTS, Transports::TCP | Transports::UDP);
}

#[skuld::test]
fn ready_overrides_tcp_only_chain_to_tcp_udp() {
    // Pins the override: inner chain reports TCP-only, but the Ready event must
    // advertise TCP|UDP (galoshes carries UDP over YAMUX). See GALOSHES_TRANSPORTS.
    let chain_ready = ChainReady {
        listen: addr(),
        transports: Transports::TCP,
    };
    let ev = chain_result_to_event(Ok(chain_ready));
    assert_eq!(
        ev,
        SitrepEvent::Ready {
            listen: addr(),
            transports: Transports::TCP | Transports::UDP,
        }
    );
}

#[skuld::test]
fn ready_forwards_listen_address() {
    // The listen address is forwarded verbatim (the real outer bind addr).
    let listen: SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let ev = chain_result_to_event(Ok(ChainReady {
        listen,
        transports: Transports::TCP,
    }));
    match ev {
        SitrepEvent::Ready { listen: l, .. } => assert_eq!(l, listen),
        other => panic!("expected Ready, got {other:?}"),
    }
}

#[skuld::test]
fn ready_override_holds_even_if_chain_already_reports_udp() {
    // Defensive: even if the inner chain somehow reported TCP|UDP already,
    // the forwarded value is the galoshes constant (TCP|UDP), unchanged.
    let ev = chain_result_to_event(Ok(ChainReady {
        listen: addr(),
        transports: Transports::TCP | Transports::UDP,
    }));
    assert_eq!(
        ev,
        SitrepEvent::Ready {
            listen: addr(),
            transports: Transports::TCP | Transports::UDP,
        }
    );
}

#[skuld::test]
fn bind_conflict_maps_through() {
    let ev = chain_result_to_event(Err(StartError::BindConflict {
        errno: 10048,
        addr: addr(),
    }));
    assert_eq!(
        ev,
        SitrepEvent::BindConflict {
            errno: 10048,
            addr: addr(),
        }
    );
}

#[skuld::test]
fn fatal_maps_through_with_errno() {
    let ev = chain_result_to_event(Err(StartError::Fatal {
        detail: "upstream dial failed".into(),
        errno: Some(111),
    }));
    assert_eq!(
        ev,
        SitrepEvent::Fatal {
            detail: "upstream dial failed".into(),
            errno: Some(111),
        }
    );
}

#[skuld::test]
fn fatal_maps_through_without_errno() {
    let ev = chain_result_to_event(Err(StartError::Fatal {
        detail: "config error".into(),
        errno: None,
    }));
    assert_eq!(
        ev,
        SitrepEvent::Fatal {
            detail: "config error".into(),
            errno: None,
        }
    );
}
