// `free_port` is the unit under test in this module; the clippy
// disallowed_methods lint applies to higher-level callers but tests
// must exercise the primitive directly. See workspace `clippy.toml` and
// bindreams/hole#285.
#![allow(clippy::disallowed_methods)]

use super::{bind_with_retry, ensure_port_free, free_port, Protocols, BIND_RETRY_ATTEMPTS};
use std::cell::Cell;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU32;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// Protocols ===========================================================================================================

#[skuld::test]
fn protocols_display_single() {
    assert_eq!(format!("{}", Protocols::TCP), "TCP");
    assert_eq!(format!("{}", Protocols::UDP), "UDP");
}

#[skuld::test]
fn protocols_display_combined() {
    assert_eq!(format!("{}", Protocols::TCP | Protocols::UDP), "TCP | UDP");
}

#[skuld::test]
fn protocols_display_empty() {
    assert_eq!(format!("{}", Protocols::empty()), "-");
}

// free_port ===========================================================================================================

#[skuld::test]
async fn free_port_rejects_empty_protocols() {
    let err = free_port(LOCALHOST, Protocols::empty())
        .await
        .expect_err("empty Protocols should be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[skuld::test]
async fn free_port_tcp_only_returns_bindable_port() {
    let port = free_port(LOCALHOST, Protocols::TCP).await.expect("allocate TCP port");
    // The port was free a moment ago; binding TCP on it now should
    // succeed (modulo TOCTOU from concurrent tests, which PORT_ALLOC
    // serialization handles in the broader bridge suite).
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST, port))
        .await
        .expect("TCP rebind on returned port");
    drop(listener);
}

#[skuld::test]
async fn free_port_udp_only_returns_bindable_port() {
    let port = free_port(LOCALHOST, Protocols::UDP).await.expect("allocate UDP port");
    let sock = tokio::net::UdpSocket::bind(SocketAddr::new(LOCALHOST, port))
        .await
        .expect("UDP rebind on returned port");
    drop(sock);
}

#[skuld::test]
async fn free_port_tcp_and_udp_returns_port_bindable_on_both() {
    let port = free_port(LOCALHOST, Protocols::TCP | Protocols::UDP)
        .await
        .expect("allocate TCP+UDP port");
    let tcp = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST, port))
        .await
        .expect("TCP rebind");
    let udp = tokio::net::UdpSocket::bind(SocketAddr::new(LOCALHOST, port))
        .await
        .expect("UDP rebind on same port");
    drop(tcp);
    drop(udp);
}

// ensure_port_free ====================================================================================================

#[skuld::test]
async fn ensure_port_free_vacuous_empty_protocols() {
    // `ensure_port_free(addr, empty)` is Ok by definition — verifies
    // nothing, so cannot fail. Use port 1 (privileged on Unix) to prove
    // no bind is attempted.
    ensure_port_free(SocketAddr::new(LOCALHOST, 1), Protocols::empty())
        .await
        .expect("vacuous empty protocols should succeed");
}

#[skuld::test]
async fn ensure_port_free_ok_on_free_port() {
    // Pick a fresh port, drop immediately, probe it.
    let port = free_port(LOCALHOST, Protocols::TCP | Protocols::UDP)
        .await
        .expect("allocate port");
    ensure_port_free(SocketAddr::new(LOCALHOST, port), Protocols::TCP | Protocols::UDP)
        .await
        .expect("freshly-allocated port should still be free");
}

#[skuld::test]
async fn ensure_port_free_errors_on_busy_tcp_port() {
    let hostage = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST, 0))
        .await
        .expect("bind hostage TCP");
    let busy = hostage.local_addr().expect("local_addr");
    let err = ensure_port_free(busy, Protocols::TCP)
        .await
        .expect_err("TCP probe on held port must fail");
    // `AddrInUse` is the canonical surfacing; `PermissionDenied` /
    // `AddrNotAvailable` are also acceptable on some Windows configs.
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrNotAvailable,
        ),
        "unexpected error kind: {:?} ({err})",
        err.kind()
    );
    drop(hostage);
}

#[skuld::test]
async fn ensure_port_free_errors_on_busy_udp_port() {
    let hostage = tokio::net::UdpSocket::bind(SocketAddr::new(LOCALHOST, 0))
        .await
        .expect("bind hostage UDP");
    let busy = hostage.local_addr().expect("local_addr");
    let err = ensure_port_free(busy, Protocols::UDP)
        .await
        .expect_err("UDP probe on held port must fail");
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrNotAvailable,
        ),
        "unexpected error kind: {:?} ({err})",
        err.kind()
    );
    drop(hostage);
}

// bind_with_retry =====================================================================================================

const FIVE: NonZeroU32 = NonZeroU32::new(5).expect("literal");

#[skuld::test]
fn bind_retry_attempts_default_is_five() {
    // Pin the public default — callers depend on it.
    assert_eq!(BIND_RETRY_ATTEMPTS.get(), 5);
}

#[skuld::test]
async fn bind_with_retry_returns_ok_on_first_attempt() {
    let calls = Cell::new(0u32);
    let result = bind_with_retry(LOCALHOST, Protocols::TCP, FIVE, |port| {
        calls.set(calls.get() + 1);
        async move { Ok::<_, io::Error>(port) }
    })
    .await
    .expect("bind_with_retry happy path");
    let (port, value) = result;
    assert_eq!(port, value, "returned port and op result must match");
    assert_eq!(calls.get(), 1, "Ok-on-first should not retry");
}

#[skuld::test]
async fn bind_with_retry_propagates_non_bind_race_immediately() {
    let calls = Cell::new(0u32);
    let result: io::Result<(u16, ())> = bind_with_retry(LOCALHOST, Protocols::TCP, FIVE, |_port| {
        calls.set(calls.get() + 1);
        async move { Err(io::Error::from(io::ErrorKind::NotFound)) }
    })
    .await;
    let err = result.expect_err("non-bind-race must propagate");
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    assert_eq!(calls.get(), 1, "non-bind-race must not retry");
}

#[skuld::test]
async fn bind_with_retry_retries_on_bind_race_until_success() {
    let calls = Cell::new(0u32);
    let result = bind_with_retry(LOCALHOST, Protocols::TCP, FIVE, |port| {
        let n = calls.get() + 1;
        calls.set(n);
        async move {
            if n < 3 {
                Err(io::Error::from(io::ErrorKind::AddrInUse))
            } else {
                Ok::<_, io::Error>(port)
            }
        }
    })
    .await
    .expect("bind_with_retry should retry through bind race");
    let (port, value) = result;
    assert_eq!(port, value);
    assert_eq!(calls.get(), 3);
}

#[skuld::test]
async fn bind_with_retry_exhausts_and_returns_last_bind_race_error() {
    let calls = Cell::new(0u32);
    let result: io::Result<(u16, ())> = bind_with_retry(LOCALHOST, Protocols::TCP, FIVE, |_port| {
        calls.set(calls.get() + 1);
        async move { Err(io::Error::from(io::ErrorKind::AddrInUse)) }
    })
    .await;
    let err = result.expect_err("exhaustion must propagate the last error");
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    assert_eq!(calls.get(), 5, "must invoke exactly attempts times on terminal failure");
}

#[skuld::test]
async fn bind_with_retry_propagates_non_bind_race_after_prior_bind_race() {
    // Interleave: AddrInUse twice (retried), then NotFound (immediate
    // propagation). The non-bind-race wins; the prior `last_err` is
    // discarded; total invocations = 3.
    let calls = Cell::new(0u32);
    let result: io::Result<(u16, ())> = bind_with_retry(LOCALHOST, Protocols::TCP, FIVE, |_port| {
        let n = calls.get() + 1;
        calls.set(n);
        async move {
            if n < 3 {
                Err(io::Error::from(io::ErrorKind::AddrInUse))
            } else {
                Err(io::Error::from(io::ErrorKind::NotFound))
            }
        }
    })
    .await;
    let err = result.expect_err("non-bind-race wins over prior bind-races");
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
    assert_eq!(calls.get(), 3);
}

#[skuld::test]
async fn bind_with_retry_invokes_closure_exactly_n_times_on_failure() {
    // Distinct from the exhaustion test: this proves that retries don't
    // silently skip the closure or invoke it more than once per attempt.
    // Future readers auditing per-attempt cost (e.g. plugin subprocess
    // spawns) rely on this invariant.
    let attempts = NonZeroU32::new(4).expect("literal");
    let calls = Cell::new(0u32);
    let result: io::Result<(u16, ())> = bind_with_retry(LOCALHOST, Protocols::TCP, attempts, |_port| {
        calls.set(calls.get() + 1);
        async move { Err(io::Error::from(io::ErrorKind::AddrInUse)) }
    })
    .await;
    assert!(result.is_err());
    assert_eq!(calls.get(), 4);
}

#[skuld::test]
async fn bind_with_retry_returned_port_is_actually_bindable() {
    // Integration: with a closure that successfully binds the port, the
    // (port, T) tuple's port is the same one the closure saw.
    let result = bind_with_retry(LOCALHOST, Protocols::TCP | Protocols::UDP, FIVE, |port| async move {
        let tcp = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST, port)).await?;
        let udp = tokio::net::UdpSocket::bind(SocketAddr::new(LOCALHOST, port)).await?;
        Ok::<_, io::Error>((tcp.local_addr()?.port(), udp.local_addr()?.port()))
    })
    .await
    .expect("real TCP+UDP bind on bind_with_retry'd port");
    let (alloc_port, (tcp_port, udp_port)) = result;
    assert_eq!(alloc_port, tcp_port);
    assert_eq!(alloc_port, udp_port);
}

#[skuld::test]
async fn bind_with_retry_rejects_empty_protocols() {
    // Inherits free_port's empty-protocols rejection at the first attempt;
    // closure must not be invoked.
    let calls = Cell::new(0u32);
    let result: io::Result<(u16, ())> = bind_with_retry(LOCALHOST, Protocols::empty(), FIVE, |_port| {
        calls.set(calls.get() + 1);
        async move { Ok(()) }
    })
    .await;
    let err = result.expect_err("empty Protocols must be rejected by free_port");
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(calls.get(), 0, "closure must not run when free_port rejects");
}
