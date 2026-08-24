use std::cell::Cell;
use std::sync::Arc;

use smoltcp::iface::SocketHandle;
use tokio::sync::Semaphore;

use super::*;

fn pending() -> Handshake {
    Handshake::Pending {
        handle: SocketHandle::default(),
        port: 80,
        src: "10.0.0.5:40000".parse().unwrap(),
        dst: "93.184.216.34:80".parse().unwrap(),
    }
}

fn stale() -> Handshake {
    Handshake::Stale {
        handle: SocketHandle::default(),
        port: 80,
    }
}

#[skuld::test]
fn a_stale_handshake_is_discarded() {
    assert_eq!(decide_admission(&stale(), || Some(())), Admission::Discard);
}

#[skuld::test]
fn a_stale_handshake_does_not_consume_a_permit() {
    let acquired = Cell::new(false);
    decide_admission(&stale(), || {
        acquired.set(true);
        Some(())
    });
    assert!(!acquired.get());
}

#[skuld::test]
fn a_pending_handshake_with_a_permit_is_admitted() {
    assert_eq!(decide_admission(&pending(), || Some(())), Admission::Admit(()));
}

#[skuld::test]
fn a_pending_handshake_without_a_permit_is_refused() {
    assert_eq!(decide_admission(&pending(), || None::<()>), Admission::Refuse);
}

#[skuld::test]
fn a_pending_handshake_acquires_exactly_once() {
    let calls = Cell::new(0u32);
    decide_admission(&pending(), || {
        calls.set(calls.get() + 1);
        Some(())
    });
    assert_eq!(calls.get(), 1);
}

#[skuld::test]
fn an_exhausted_semaphore_refuses() {
    let semaphore = Arc::new(Semaphore::new(1));
    let _held = Arc::clone(&semaphore).try_acquire_owned().unwrap();

    let verdict = decide_admission(&pending(), || Arc::clone(&semaphore).try_acquire_owned().ok());

    assert!(matches!(verdict, Admission::Refuse));
    assert_eq!(semaphore.available_permits(), 0);
}
