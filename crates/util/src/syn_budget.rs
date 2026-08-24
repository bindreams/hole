//! Windows SYN-retransmission budget for a TCP connect.
//!
//! On Windows, a connect to a closed port is refused at the TCP layer in
//! ~3 ms, but the connecting socket ignores that RST and only reports
//! `ECONNREFUSED` once its own SYN-retransmission budget is spent — by
//! default `MaxSynRetransmissions` (stock 4) × ~514 ms, ≈2.05 s. POSIX
//! sockets surface the RST immediately; there is nothing to pin there.
//!
//! [`SynBudget::NoRetransmit`] uses `SIO_TCP_INITIAL_RTO` to disable SYN
//! retransmissions on Windows, so a refusal is reported in ~0.1 ms while a
//! genuine black hole still yields no verdict. It is **only** correct where
//! that missing verdict is not taken as an answer — see the enum doc.
//!
//! [`probe`] is the entry point for a connect used as a port probe: it owns
//! the cap and returns a [`ProbeOutcome`] read from the error, so no caller
//! decides refused-vs-timeout by which timer fired. [`REFUSAL_COST`] is what
//! any such timeout must clear.
//!
//! Measured on a Windows 11 box, connecting to a closed loopback port,
//! sweeping `MaxSynRetransmissions`:
//!
//! | value | outcome | elapsed | meaning |
//! | --- | --- | --- | --- |
//! | unset | `WSAECONNREFUSED` | 2070 ms | host default |
//! | 0 | `WSAECONNREFUSED` | 2029 ms | **default sentinel** |
//! | 1 / 2 / 4 / 8 | `WSAECONNREFUSED` | 513 / 1015 / 2046 / 4114 ms | literal counts (4 = Windows stock) |
//! | 250 / 253 | *(no return in 40 s)* | >40 s | literal counts |
//! | **254** | **`WSAECONNREFUSED`** | **0.1 ms** | **`NO_SYN_RETRANSMISSIONS`** |
//! | 255 | `WSAECONNREFUSED` | 2041 ms | **default sentinel** |
//!
//! `0` and `255` are both documented "use the host default" sentinels in
//! `mstcpip.h`, not a floor — sampling only those two values is what
//! produced an earlier, false belief that 514 ms was a hard floor. `254`
//! (`TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS`) is the only value that
//! actually suppresses retransmission. `Rtt` was swept at 10, 50, 100, 200,
//! 300, and 1000 ms and moved nothing — the interval is fixed at ~514 ms —
//! so this module always passes `TCP_INITIAL_RTO_UNSPECIFIED_RTT` (0xFFFF).

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

/// How long a connect left at [`SynBudget::HostDefault`] may run before a
/// refusal becomes observable. A caller whose own timeout is below this
/// reports a refused peer as a timeout — the verdict is then decided by
/// which timer fired rather than by what the peer said.
///
/// Windows: `MaxSynRetransmissions` (stock 4) × ~514 ms, measured at
/// 2001–2070 ms across runs; 2100 ms is that with the spread folded in.
/// POSIX surfaces the first RST, so there is nothing to wait for.
#[cfg(windows)]
pub const REFUSAL_COST: Duration = Duration::from_millis(2100);
#[cfg(not(windows))]
pub const REFUSAL_COST: Duration = Duration::ZERO;

/// How many SYN retransmissions a connect may spend before reporting a
/// verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynBudget {
    /// Leave the socket alone.
    HostDefault,
    /// `TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS` — one SYN, then the OS's
    /// verdict. Windows-only; a no-op elsewhere, where the first RST is
    /// already surfaced.
    ///
    /// ONLY where a [`ProbeOutcome::NoVerdict`] is not taken as an answer:
    /// one SYN dropped by a full accept backlog yields no verdict rather
    /// than a retried one. Either re-issue the probe in a loop, or settle
    /// it by an authoritative check that does not involve a SYN (binding
    /// the port). A connect that carries data must not use this.
    NoRetransmit,
}

/// What one [`probe`] learned about `addr`.
#[derive(Debug)]
pub enum ProbeOutcome {
    /// Something accepted the connection.
    Listening(TcpStream),
    /// The peer refused or reset. Authoritative: nothing is listening.
    Refused(io::Error),
    /// No answer, so nothing authoritative about `addr`: either `cap`
    /// elapsed (`None`), or the connect failed for a reason that is not a
    /// refusal (`Some`) — the OS's own give-up, an unreachable network, or
    /// a pre-connect ioctl failure, which means no SYN was ever sent.
    NoVerdict(Option<io::Error>),
}

/// Connect to `addr` under the given [`SynBudget`]. Private: [`probe`] is
/// the way in, so no caller can pin [`SynBudget::NoRetransmit`] without the
/// classified outcome that makes it safe.
async fn connect(addr: SocketAddr, budget: SynBudget) -> io::Result<TcpStream> {
    match budget {
        SynBudget::HostDefault => TcpStream::connect(addr).await,
        SynBudget::NoRetransmit => connect_no_retransmit(addr).await,
    }
}

/// One connect attempt against `addr` under `budget`, classified into a
/// [`ProbeOutcome`]. The single entry point for a connect used as a port
/// probe: the outcome is read from the error, never from which timer fired.
///
/// `cap` is a failure bound on an external event — the OS's connect state
/// machine, which under [`SynBudget::HostDefault`] can run for tens of
/// seconds against a black hole. It is a backstop, not a classifier: every
/// verdict below is decided before it, and reaching it is itself the
/// `NoVerdict(None)` answer. Give it room above [`REFUSAL_COST`] whenever a
/// refusal must be typed as one.
pub async fn probe(addr: SocketAddr, cap: Duration, budget: SynBudget) -> ProbeOutcome {
    match tokio::time::timeout(cap, connect(addr, budget)).await {
        Ok(result) => classify(result),
        Err(_) => ProbeOutcome::NoVerdict(None),
    }
}

fn classify(result: io::Result<TcpStream>) -> ProbeOutcome {
    match result {
        Ok(stream) => ProbeOutcome::Listening(stream),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
            ) =>
        {
            ProbeOutcome::Refused(e)
        }
        Err(e) => ProbeOutcome::NoVerdict(Some(e)),
    }
}

#[cfg(windows)]
async fn connect_no_retransmit(addr: SocketAddr) -> io::Result<TcpStream> {
    use tokio::net::TcpSocket;

    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    set_no_syn_retransmissions(&socket)?;
    socket.connect(addr).await
}

#[cfg(not(windows))]
async fn connect_no_retransmit(addr: SocketAddr) -> io::Result<TcpStream> {
    // POSIX already surfaces the first RST as an immediate refusal, so
    // there is no retransmission budget here to pin.
    TcpStream::connect(addr).await
}

/// Apply `TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS` to a not-yet-connected
/// socket. Extracted so its failure path is directly testable.
///
/// An ioctl failure is returned, never swallowed — a silent fallback to
/// the host default would resurrect the ~2 s cost this module exists to
/// remove without any signal that it happened.
#[cfg(windows)]
fn set_no_syn_retransmissions(socket: &tokio::net::TcpSocket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket as _;

    use windows::Win32::Networking::WinSock::{WSAIoctl, SIO_TCP_INITIAL_RTO, SOCKET, TCP_INITIAL_RTO_PARAMETERS};

    // mstcpip.h: `MaxSynRetransmissions` is `UINT8`; see the module doc for
    // why 254 (not the 0/255 default sentinels) is used, and why Rtt is left
    // TCP_INITIAL_RTO_UNSPECIFIED_RTT.
    const NO_SYN_RETRANSMISSIONS: u8 = 254;
    const UNSPECIFIED_RTT: u16 = 0xFFFF;

    let params = TCP_INITIAL_RTO_PARAMETERS {
        Rtt: UNSPECIFIED_RTT,
        MaxSynRetransmissions: NO_SYN_RETRANSMISSIONS,
    };
    let mut bytes_returned: u32 = 0;
    let rc = unsafe {
        WSAIoctl(
            SOCKET(socket.as_raw_socket() as usize),
            SIO_TCP_INITIAL_RTO,
            Some(std::ptr::addr_of!(params).cast()),
            std::mem::size_of::<TCP_INITIAL_RTO_PARAMETERS>() as u32,
            None,
            0,
            &mut bytes_returned,
            None,
            None,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
#[path = "syn_budget_tests.rs"]
mod syn_budget_tests;

#[cfg(all(test, target_os = "windows"))]
#[path = "syn_budget_windows_tests.rs"]
mod syn_budget_windows_tests;
