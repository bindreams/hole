// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per the hole workspace clippy.toml's "Bridge cancellation contract"
// sanctioned-test-file exception.
#![allow(clippy::disallowed_methods)]

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::port::{os_probe_with, pick_with};
use crate::tap_tests::{addr, err, scripted};

#[skuld::test]
async fn the_inner_port_pick_never_returns_a_taken_port() {
    tokio::time::pause();
    // Every taken port collides repeatedly, past any fixed attempt count.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut script: Vec<_> = (0..9).map(|i| Ok(addr(if i % 2 == 0 { 5000 } else { 6000 }))).collect();
    script.push(Ok(addr(5001)));
    let picked = pick_with(
        "p",
        addr(5000).ip(),
        &[5000, 6000],
        scripted(script, &calls),
        &CancellationToken::new(),
    )
    .await
    .unwrap();

    assert_eq!(picked, Some(addr(5001)));
    assert_eq!(calls.load(Ordering::SeqCst), 10);
}

#[skuld::test]
async fn the_inner_port_pick_retries_a_bind_race_without_a_cap() {
    tokio::time::pause();
    let kinds = [io::ErrorKind::AddrInUse, io::ErrorKind::PermissionDenied];
    let calls = Arc::new(AtomicUsize::new(0));
    let mut script: Vec<_> = (0..60).map(|i| err(kinds[i % 2])).collect();
    script.push(Ok(addr(5001)));
    let picked = pick_with(
        "p",
        addr(5000).ip(),
        &[5000],
        scripted(script, &calls),
        &CancellationToken::new(),
    )
    .await
    .unwrap();

    assert_eq!(picked, Some(addr(5001)));
    assert_eq!(calls.load(Ordering::SeqCst), 61);
}

#[skuld::test]
async fn the_inner_port_pick_retries_addr_not_available() {
    // A Windows excluded-port-range refusal, like `util::retry::is_bind_race`.
    tokio::time::pause();
    let calls = Arc::new(AtomicUsize::new(0));
    let script = vec![err(io::ErrorKind::AddrNotAvailable), Ok(addr(5001))];
    let picked = pick_with(
        "p",
        addr(5000).ip(),
        &[5000],
        scripted(script, &calls),
        &CancellationToken::new(),
    )
    .await
    .unwrap();

    assert_eq!(picked, Some(addr(5001)));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[skuld::test]
async fn the_inner_port_pick_returns_any_other_error_at_once() {
    tokio::time::pause();
    let calls = Arc::new(AtomicUsize::new(0));
    let script = vec![err(io::ErrorKind::AddrInUse), err(io::ErrorKind::Other)];
    let e = pick_with(
        "p",
        addr(5000).ip(),
        &[5000],
        scripted(script, &calls),
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();

    assert_eq!(e.kind(), io::ErrorKind::Other);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[skuld::test]
async fn the_inner_port_pick_paces_its_retries() {
    tokio::time::pause();
    // The backoff starts at 5ms and is capped at 50ms: 60 retries take well over 2s
    // of virtual time, where a loop that never waits takes none.
    let calls = Arc::new(AtomicUsize::new(0));
    let mut script: Vec<_> = (0..60).map(|_| err(io::ErrorKind::AddrInUse)).collect();
    script.push(Ok(addr(5001)));
    let started = tokio::time::Instant::now();
    pick_with(
        "p",
        addr(5000).ip(),
        &[5000],
        scripted(script, &calls),
        &CancellationToken::new(),
    )
    .await
    .unwrap();

    assert!(started.elapsed() > Duration::from_secs(2), "{:?}", started.elapsed());
}

#[skuld::test]
async fn shutdown_ends_the_inner_port_pick() {
    tokio::time::pause();
    let shutdown = CancellationToken::new();
    let calls = AtomicUsize::new(0);
    // Races forever; the third attempt also fires shutdown.
    let probe = || {
        if calls.fetch_add(1, Ordering::SeqCst) == 2 {
            shutdown.cancel();
        }
        err(io::ErrorKind::AddrInUse)
    };
    let picked = pick_with("p", addr(5000).ip(), &[5000], probe, &shutdown)
        .await
        .unwrap();

    assert_eq!(picked, None);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

/// A port another process takes between the probe's drop and its rebind fails the rebind, so the pick starts over
/// instead of handing out a port someone else holds.
///
/// Serialized: the holder binds the probed port right after the probe drops it, and a concurrent test probing the same
/// ephemeral port in that window could take it first.
#[skuld::test(serial)]
async fn a_port_taken_between_the_probe_and_the_rebind_is_picked_again() {
    let ip = addr(0).ip();
    let mut holder: Option<std::net::TcpListener> = None;
    let mut stolen = None;
    let probe = || {
        os_probe_with(ip, &mut |probed| {
            if holder.is_none() {
                holder = Some(std::net::TcpListener::bind(probed).expect("take the probed port"));
                stolen = Some(probed);
            }
        })
    };

    let picked = pick_with("p", ip, &[], probe, &CancellationToken::new())
        .await
        .unwrap()
        .expect("no shutdown fired");

    let stolen = stolen.expect("the first probe ran its between step");
    assert_ne!(picked.port(), stolen.port(), "the held port must not be handed out");
    drop(holder);
}

/// A transient `WSAEACCES` at the rebind step is absorbed like `WSAEADDRINUSE`: the pick starts over and returns `Ok`.
/// The test forces it with the asymmetric Winsock rule: a wildcard `SO_EXCLUSIVEADDRUSE` holder makes a later
/// specific-address bind fail with `WSAEACCES`. Serialized for the reason of the test above.
#[cfg(windows)]
#[skuld::test(serial)]
async fn a_transient_wsaeacces_at_the_rebind_is_picked_again() {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{setsockopt, SOCKET, SOL_SOCKET, SO_EXCLUSIVEADDRUSE};

    fn hold_wildcard_exclusive(port: u16) -> Socket {
        let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("create socket");
        let raw = SOCKET(s.as_raw_socket() as usize);
        let enable = 1i32.to_ne_bytes();
        // Safety: the FFI call: `raw` is a valid SOCKET owned by `s`, and `&enable` is a live `[u8; 4]`.
        let rc = unsafe { setsockopt(raw, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, Some(&enable)) };
        assert_eq!(rc, 0, "setsockopt SO_EXCLUSIVEADDRUSE failed");
        let wildcard: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
        s.bind(&wildcard.into())
            .expect("bind 0.0.0.0:port with SO_EXCLUSIVEADDRUSE");
        s
    }

    let ip = addr(0).ip();
    let mut holder: Option<Socket> = None;
    let mut attempts = 0;
    let probe = || {
        attempts += 1;
        os_probe_with(ip, &mut |probed| {
            if holder.is_none() {
                holder = Some(hold_wildcard_exclusive(probed.port()));
            }
        })
    };

    let picked = pick_with("p", ip, &[], probe, &CancellationToken::new()).await.unwrap();

    assert!(picked.is_some(), "no shutdown fired");
    assert!(
        attempts >= 2,
        "expected a second pick after the injected WSAEACCES, got {attempts} attempt(s)"
    );
    drop(holder);
}
