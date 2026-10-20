//! Free-port picking for the tap and the chain: probe a port the OS hands out, never one the caller knows is taken,
//! and pick again on a bind race, uncapped and paced by a backoff.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::backoff::Backoff;

/// One attempt to find a free port: the address a probe bound, or its error.
pub(crate) type Probe = Box<dyn FnMut() -> io::Result<SocketAddr> + Send>;

/// Probes a free TCP port on `(ip, 0)`: bind, drop, rebind, drop. A port is handed out only after it survived a round
/// trip, which is what rejects one another socket claimed, or the excluded-port-range tables refuse, in between.
pub(crate) fn os_probe(ip: IpAddr) -> Probe {
    Box::new(move || os_probe_with(ip, &mut |_| {}))
}

/// [`os_probe`]'s attempt, running `between` after the first drop so a test can take the port at that point.
pub(crate) fn os_probe_with(ip: IpAddr, between: &mut dyn FnMut(SocketAddr)) -> io::Result<SocketAddr> {
    let addr = std::net::TcpListener::bind(SocketAddr::new(ip, 0)).and_then(|l| l.local_addr())?;
    between(addr);
    std::net::TcpListener::bind(addr)?;
    Ok(addr)
}

/// Picks a port from `probe` that is not in `taken`.
///
/// Retries a taken port or a bind race ([`is_port_race`]) with no attempt cap,
/// paced by a backoff; any other error is returned. `Ok(None)`: `shutdown`
/// fired first.
///
/// Each swallowed error is logged at debug. A race that fails the same way
/// twice in a row is warned about once, naming `plugin` and `ip`: such a cause
/// is probably not a race (an address the host does not own never binds).
pub(crate) async fn pick_with(
    plugin: &str,
    ip: IpAddr,
    taken: &[u16],
    mut probe: impl FnMut() -> io::Result<SocketAddr>,
    shutdown: &CancellationToken,
) -> io::Result<Option<SocketAddr>> {
    let mut backoff = retry_backoff();
    let mut last_race = None;
    let mut warned = false;
    loop {
        match probe() {
            Ok(addr) if !taken.contains(&addr.port()) => return Ok(Some(addr)),
            Ok(_) => last_race = None,
            Err(e) if is_port_race(&e) => {
                let cause = (e.kind(), e.raw_os_error());
                tracing::debug!(
                    %plugin, %ip, kind = ?cause.0, errno = ?cause.1,
                    "port pick: probe failed, picking again"
                );
                if last_race == Some(cause) && !warned {
                    warned = true;
                    tracing::warn!(
                        %plugin, %ip, kind = ?cause.0, errno = ?cause.1,
                        "port pick: probing {ip} keeps failing the same way; it is retried until shutdown"
                    );
                }
                last_race = Some(cause);
            }
            Err(e) => return Err(e),
        }
        if !backoff.pause(shutdown).await {
            return Ok(None);
        }
    }
}

/// Whether a failed `bind((ip, 0))` is a race that a later pick can win.
///
/// The same classes as `util::retry::is_bind_race`, which garter (published)
/// cannot depend on: on Windows a `bind(:0)` fails with `PermissionDenied` or
/// `AddrNotAvailable` when the excluded-port-range tables disagree about the
/// port it was handed. An address the host does not own fails the same way on
/// every pick, so such a start never readies; `shutdown` ends it.
pub(crate) fn is_port_race(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
    )
}

/// The pause between retries of the tap's and the chain's own loops: 5ms doubling to a 50ms cap.
pub(crate) fn retry_backoff() -> Backoff {
    Backoff::new(Duration::from_millis(5), Duration::from_millis(50))
}

/// A free loopback TCP port, for a test that needs a public port to hand a chain.
#[cfg(test)]
pub(crate) fn free_loopback_port() -> SocketAddr {
    os_probe(std::net::Ipv4Addr::LOCALHOST.into())().expect("the OS has a free loopback port")
}
