use std::net::SocketAddr;

use garter::{ChainReady, SitrepEvent, StartError, Transports};

use crate::sitrep_out::{chain_result_to_event, recover_exit_detail, GALOSHES_TRANSPORTS};

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

#[skuld::test]
fn exited_before_ready_maps_to_fatal_with_generic_detail() {
    // See `chain_result_to_event`'s doc comment for why.
    let ev = chain_result_to_event(Err(StartError::ExitedBeforeReady));
    assert_eq!(
        ev,
        SitrepEvent::Fatal {
            detail: garter::EXITED_BEFORE_READY_DETAIL.into(),
            errno: None,
        }
    );
}

#[skuld::test]
fn recover_exit_detail_surfaces_the_chains_specific_error() {
    let joined: Result<garter::Result<()>, tokio::task::JoinError> = Ok(Err(garter::Error::Chain(
        "tap[ex-ray]: alloc inner port: address in use".into(),
    )));
    assert_eq!(
        recover_exit_detail(&joined),
        "tap[ex-ray]: alloc inner port: address in use"
    );
}

#[skuld::test]
fn recover_exit_detail_falls_back_on_a_clean_exit() {
    // `run()` returning `Ok(())` here means shutdown raced the readiness
    // report, not a real failure — nothing more specific to recover.
    let joined: Result<garter::Result<()>, tokio::task::JoinError> = Ok(Ok(()));
    assert_eq!(recover_exit_detail(&joined), garter::EXITED_BEFORE_READY_DETAIL);
}

#[skuld::test]
async fn recover_exit_detail_falls_back_when_the_task_panicked() {
    let handle = tokio::spawn(async { panic!("boom") });
    let joined = handle.await;
    assert!(joined.is_err(), "expected a real JoinError from the panicked task");
    assert_eq!(recover_exit_detail(&joined), garter::EXITED_BEFORE_READY_DETAIL);
}
