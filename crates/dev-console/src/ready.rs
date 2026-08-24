//! Readiness rendezvous.
//!
//! Bridge: FIRST-PARTY, so a real rendezvous exists — we pre-bind a
//! localhost TCP listener (no bind race: we bind before the bridge starts),
//! pass `--ready-notify ADDR/TOKEN`, and the bridge echoes the token only
//! after `IpcServer::bind` + `apply_socket_permissions` (closes the DACL
//! race dev.py's socket-file poll had; spec Delta 5).
//!
//! Vite: third-party — the only options are probing or output-scraping, and
//! the output format is unstable. Connect-probe every address `localhost`
//! resolves to (the hosts-file v4/v6 trap, dev.py §5.5).

use std::net::IpAddr;
use std::time::Duration;

use tokio::io::AsyncBufReadExt as _;
use tokio::net::TcpListener;

pub struct ReadyListener {
    listener: TcpListener,
    token: String,
}

impl ReadyListener {
    pub async fn bind() -> std::io::Result<Self> {
        // bind_ephemeral retries allocate+bind as a unit on bind races
        // (workspace invariant: never raw free_port).
        let (_port, listener) = util::port_alloc::bind_ephemeral(
            IpAddr::from([127, 0, 0, 1]),
            util::port_alloc::Protocols::TCP,
            |port| async move { TcpListener::bind(("127.0.0.1", port)).await },
        )
        .await?;
        let token = format!("{:016x}{:016x}", rand::random::<u64>(), rand::random::<u64>());
        Ok(Self { listener, token })
    }

    /// The `--ready-notify` flag value.
    pub fn notify_arg(&self) -> String {
        format!("{}/{}", self.listener.local_addr().expect("bound"), self.token)
    }

    /// Resolve when a connection presents the token. Wrong/garbled/SILENT
    /// connections must not wedge the wait (an open-but-mute local conn
    /// would otherwise block a serial read while the real bridge's token
    /// sits in the backlog): each accepted conn is read in its own task, the
    /// first token match wins. The TIMEOUT lives in the caller's select! —
    /// this future is pure event.
    pub async fn wait(self) -> std::io::Result<()> {
        let token = std::sync::Arc::new(self.token);
        let (hit_tx, mut hit_rx) = tokio::sync::mpsc::channel::<()>(1);
        let mut readers = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (conn, _) = accepted?;
                    let token = std::sync::Arc::clone(&token);
                    let hit_tx = hit_tx.clone();
                    readers.spawn(async move {
                        let mut lines = tokio::io::BufReader::new(conn).lines();
                        if let Ok(Some(line)) = lines.next_line().await {
                            if line == *token {
                                let _ = hit_tx.send(()).await;
                            }
                        }
                    });
                }
                _ = hit_rx.recv() => return Ok(()),
            }
        }
        // readers (and any mute conns) are dropped/aborted with the JoinSet.
    }
}

/// The result of one connect attempt in [`probe_once`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    /// Something accepted the connection.
    Listening,
    /// The peer refused — authoritative: nothing is listening (yet).
    Refused,
    /// No answer, so nothing authoritative about the port: the cap elapsed
    /// (a real class-2 remote endpoint — see the `hosts`-file note below —
    /// that may never answer), or the connect failed without refusing.
    NoVerdict,
}

/// One connect attempt against `addr`, capped at `cap`.
///
/// Pins [`util::syn_budget::SynBudget::NoRetransmit`], which requires that a
/// `NoVerdict` never be taken as an answer. [`wait_for_port`] re-issues; the
/// single-round [`port_in_use`] settles it by binding the address instead.
/// On Windows a refused loopback port is then reported in ~0.1 ms instead of
/// paying the ~2.05 s stock SYN-retransmission budget. The cap still
/// matters: it bounds a `hosts` file mapping `localhost` off-box to a
/// class-2 remote endpoint that may never answer, which `NoRetransmit` does
/// not affect.
async fn probe_once(addr: std::net::SocketAddr, cap: Duration) -> ProbeOutcome {
    match util::syn_budget::probe(addr, cap, util::syn_budget::SynBudget::NoRetransmit).await {
        util::syn_budget::ProbeOutcome::Listening(_conn) => ProbeOutcome::Listening,
        util::syn_budget::ProbeOutcome::Refused(_) => ProbeOutcome::Refused,
        util::syn_budget::ProbeOutcome::NoVerdict(None) => ProbeOutcome::NoVerdict,
        util::syn_budget::ProbeOutcome::NoVerdict(Some(e)) => {
            // Not a port verdict but a real signal — an unreachable network,
            // or the `SIO_TCP_INITIAL_RTO` ioctl failing before any SYN was
            // sent. Silence here is what would turn that into a bogus "Vite
            // never came up" after the whole budget.
            enote!(
                "[ready] probe of {addr} failed without a verdict: kind={:?} {e}",
                e.kind()
            );
            ProbeOutcome::NoVerdict
        }
    }
}

/// Can anyone else still bind `addr`? A bind involves no SYN, so this
/// answers where a probe could not. Any bind error counts as held: an
/// exclusive owner refuses with `WSAEACCES` rather than `EADDRINUSE`.
pub(crate) async fn is_port_held(addr: std::net::SocketAddr) -> bool {
    TcpListener::bind(addr).await.is_err()
}

/// One probe round (NOT a wait): is something already listening on `port`?
/// Used by the Delta-7 leaked-vite preflight — a clean startup must not pay
/// a polling budget for a port that is supposed to be free.
///
/// A `NoVerdict` is settled by binding the same address: a bind needs no
/// SYN, so a leaked Vite whose SYN was dropped still shows up as a bind
/// failure rather than as a silent "port free". Only the refused path — the
/// common one, and instant on every platform — costs nothing.
pub async fn port_in_use(port: u16) -> bool {
    let addrs: Vec<std::net::SocketAddr> = match tokio::net::lookup_host(("localhost", port)).await {
        Ok(a) => a.collect(),
        Err(_) => vec![
            (std::net::Ipv4Addr::LOCALHOST, port).into(),
            (std::net::Ipv6Addr::LOCALHOST, port).into(),
        ],
    };
    for addr in &addrs {
        // Same per-attempt cap as wait_for_port (see its comment).
        match probe_once(*addr, Duration::from_millis(500)).await {
            ProbeOutcome::Listening => return true,
            ProbeOutcome::Refused => {}
            ProbeOutcome::NoVerdict if is_port_held(*addr).await => return true,
            ProbeOutcome::NoVerdict => {}
        }
    }
    false
}

/// Probe until something accepts on `port` via ANY address `localhost`
/// resolves to (v4 and/or v6), or `budget` elapses. Class-2 exception
/// (CLAUDE.md §sync invariant): the subprocess is out-of-process, the OS
/// exposes no "process N bound port P" event, so we poll; the budget is the
/// human-surfaced failure bound, and the caller's select! on child-exit
/// short-circuits a dead Vite.
pub async fn wait_for_port(port: u16, budget: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    let addrs: Vec<std::net::SocketAddr> = match tokio::net::lookup_host(("localhost", port)).await {
        Ok(a) => a.collect(),
        // Name-resolution failure: fall back to both loopbacks (dev.py:236-242).
        Err(_) => vec![
            (std::net::Ipv4Addr::LOCALHOST, port).into(),
            (std::net::Ipv6Addr::LOCALHOST, port).into(),
        ],
    };
    while tokio::time::Instant::now() < deadline {
        for addr in &addrs {
            // 500ms per-attempt cap — dev.py:251 parity (sock.settimeout(0.5)).
            if probe_once(*addr, Duration::from_millis(500)).await == ProbeOutcome::Listening {
                return true;
            }
        }
        // 200ms between rounds (class-2; dev.py:260 parity).
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

#[cfg(test)]
#[path = "ready_tests.rs"]
mod ready_tests;
