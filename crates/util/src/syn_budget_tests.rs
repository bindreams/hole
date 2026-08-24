use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use super::{ProbeOutcome, SynBudget};

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// connect =============================================================================================================

#[skuld::test]
async fn connect_reaches_a_live_listener_under_each_budget() {
    for budget in [SynBudget::HostDefault, SynBudget::NoRetransmit] {
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST, 0))
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("local_addr");

        let accept = tokio::spawn(async move { listener.accept().await });
        super::connect(addr, budget)
            .await
            .unwrap_or_else(|e| panic!("connect under {budget:?} to a live listener should succeed: {e}"));
        accept
            .await
            .expect("accept task")
            .expect("accept should observe the connection");
    }
}

// probe ===============================================================================================================

/// `cap` for tests that must let a refusal complete: the platform refusal
/// cost plus a wide margin, so no test here is decided by a timer.
const GENEROUS_CAP: Duration = super::REFUSAL_COST.saturating_add(Duration::from_secs(3));

#[skuld::test]
async fn probe_reports_listening_under_each_budget() {
    for budget in [SynBudget::HostDefault, SynBudget::NoRetransmit] {
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST, 0))
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("local_addr");
        let accept = tokio::spawn(async move { listener.accept().await });

        match super::probe(addr, GENEROUS_CAP, budget).await {
            ProbeOutcome::Listening(_) => {}
            other => panic!("probe under {budget:?} of a live listener should be Listening, got {other:?}"),
        }
        accept
            .await
            .expect("accept task")
            .expect("accept should observe the connection");
    }
}

#[skuld::test]
async fn probe_reports_refused_for_a_closed_port_under_each_budget() {
    for budget in [SynBudget::HostDefault, SynBudget::NoRetransmit] {
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(LOCALHOST, 0))
            .await
            .expect("bind loopback listener");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);

        match super::probe(addr, GENEROUS_CAP, budget).await {
            ProbeOutcome::Refused(_) => {}
            other => panic!("probe under {budget:?} of a closed port should be Refused, got {other:?}"),
        }
    }
}

// classify ============================================================================================================

#[skuld::test]
async fn classify_reads_a_refusal_from_the_error() {
    for kind in [ErrorKind::ConnectionRefused, ErrorKind::ConnectionReset] {
        match super::classify(Err(io::Error::from(kind))) {
            ProbeOutcome::Refused(e) => assert_eq!(e.kind(), kind),
            other => panic!("{kind:?} is a refusal, got {other:?}"),
        }
    }
}

/// The verdict must come from the error, never from which timer fired: an
/// OS give-up (`TimedOut`) says nothing about whether the port is open, and
/// a pre-connect ioctl failure (`PermissionDenied` here) means no SYN was
/// ever sent. Both must stay distinguishable from a refusal, and must carry
/// the error out so the caller can log it.
#[skuld::test]
async fn classify_keeps_a_non_refusal_error_out_of_the_refused_verdict() {
    for kind in [
        ErrorKind::TimedOut,
        ErrorKind::PermissionDenied,
        ErrorKind::AddrNotAvailable,
    ] {
        match super::classify(Err(io::Error::from(kind))) {
            ProbeOutcome::NoVerdict(Some(e)) => assert_eq!(e.kind(), kind),
            other => panic!("{kind:?} is not a refusal and must carry its error, got {other:?}"),
        }
    }
}
