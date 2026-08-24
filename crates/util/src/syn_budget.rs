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
//! genuine black hole still times out (bounded by the caller's own
//! `tokio::time::timeout`, not by this module). It is **only** correct for
//! a connect that is a probe inside a retry loop that re-issues on any
//! failure — see the enum doc.
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

use tokio::net::TcpStream;

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
    /// ONLY for a connect that is a probe inside a retry loop that
    /// re-issues on ANY failure. With no retransmissions a SYN dropped by
    /// a full accept backlog becomes an immediate failure rather than a
    /// retried one, so a connect that carries data — or a loop that only
    /// retries one error kind — must not use this.
    NoRetransmit,
}

/// Connect to `addr` under the given [`SynBudget`].
pub async fn connect(addr: SocketAddr, budget: SynBudget) -> io::Result<TcpStream> {
    match budget {
        SynBudget::HostDefault => TcpStream::connect(addr).await,
        SynBudget::NoRetransmit => connect_no_retransmit(addr).await,
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

    // mstcpip.h: `MaxSynRetransmissions` is `UINT8`. `0` and `0xFF` (255)
    // both mean "use the host default"; `0xFE` (254) is the documented
    // `TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS` sentinel — see the module
    // doc's sweep. `Rtt` is left `TCP_INITIAL_RTO_UNSPECIFIED_RTT`
    // (0xFFFF): swept at 10/50/100/200/300/1000 ms and confirmed inert.
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
