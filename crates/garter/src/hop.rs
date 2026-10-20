//! One hop of a chain: it picks its listen port, runs its plugin, and tells the chain how its start went.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::plugin::ChainPlugin;
use crate::port::{self, Probe};
use crate::sitrep::{PluginReady, StartError};

/// How a hop's start ended, as its supervisor reports it to the chain. A supervisor that ends without deciding drops
/// the channel instead.
#[derive(Debug)]
pub(crate) enum Decision {
    /// The plugin is accepting. `given` is the address it was told to listen on, which is what the hop behind it
    /// forwards to; `report.listen` is what it says it bound, and a host must not trust it for that.
    Ready { given: SocketAddr, report: PluginReady },
    /// The plugin reported a start failure.
    Failed(StartError),
    /// The plugin dropped its readiness sender unsent.
    Dropped,
}

/// Where a hop listens.
pub(crate) enum Placement {
    /// An address the caller chose, which the chain neither picks nor changes.
    Public(SocketAddr),
    /// A port the chain picks on `ip` just before the hop starts, from `probe`, skipping `taken`.
    Intermediate { ip: IpAddr, taken: Vec<u16>, probe: Probe },
}

/// Delivers a hop's one [`Decision`], on every path out of [`run_hop`]: a readiness the plugin sent, the sender it
/// dropped, and whatever it sent while it was being dropped. The last matters because the future of a hop that the
/// chain aborts at its drain bound is dropped here, plugin first and then this, and a plugin may send its start
/// failure from its own `Drop`.
struct Relay {
    ready: oneshot::Receiver<Result<PluginReady, StartError>>,
    given: SocketAddr,
    decided: Option<oneshot::Sender<Decision>>,
}

impl Relay {
    /// Reports `outcome`, `None` for a sender dropped unsent, unless a decision was already reported.
    fn settle(&mut self, outcome: Option<Result<PluginReady, StartError>>) {
        let Some(decided) = self.decided.take() else { return };
        let decision = match outcome {
            Some(Ok(report)) => Decision::Ready {
                given: self.given,
                report,
            },
            Some(Err(error)) => Decision::Failed(error),
            None => Decision::Dropped,
        };
        let _ = decided.send(decision);
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        if self.decided.is_none() {
            return;
        }
        match self.ready.try_recv() {
            Ok(outcome) => self.settle(Some(outcome)),
            Err(oneshot::error::TryRecvError::Closed) => self.settle(None),
            // The plugin kept `ready` past its own end: there is nothing to report, and the chain reads the dropped
            // decision channel as that.
            Err(oneshot::error::TryRecvError::Empty) => {}
        }
    }
}

enum First {
    Ready(Result<Result<PluginReady, StartError>, oneshot::error::RecvError>),
    Exited(crate::Result<()>),
}

/// Starts one hop: picks its port (an [`Placement::Intermediate`] one), runs `plugin` to forward to `remote`, and sends
/// `decided` the hop's [`Decision`] once its readiness, or its end, is known. Returns what the plugin returns.
///
/// A pick that ends because `shutdown` fired starts nothing and decides nothing. A pick that fails for a reason that
/// is not a race fails the hop with a [`StartError::Fatal`].
pub(crate) async fn run_hop(
    plugin: Arc<dyn ChainPlugin>,
    placement: Placement,
    remote: SocketAddr,
    shutdown: CancellationToken,
    decided: oneshot::Sender<Decision>,
) -> crate::Result<()> {
    let local = match placement {
        Placement::Public(addr) => addr,
        Placement::Intermediate { ip, taken, mut probe } => {
            match port::pick_with(plugin.name(), ip, &taken, &mut probe, &shutdown).await {
                Ok(Some(addr)) => addr,
                Ok(None) => return Ok(()),
                Err(error) => {
                    let _ = decided.send(Decision::Failed(StartError::Fatal {
                        detail: format!("picking a port for plugin '{}' failed: {error}", plugin.name()),
                        errno: error.raw_os_error(),
                    }));
                    return Err(error.into());
                }
            }
        }
    };

    let (ready_tx, ready_rx) = oneshot::channel();
    let mut relay = Relay {
        ready: ready_rx,
        given: local,
        decided: Some(decided),
    };
    let run = plugin.run(local, remote, shutdown, ready_tx);
    tokio::pin!(run);

    // Either arm may win: what the plugin left in `ready` when it returned is read by the relay's drop.
    let first = tokio::select! {
        read = &mut relay.ready => First::Ready(read),
        result = &mut run => First::Exited(result),
    };
    match first {
        First::Ready(read) => {
            relay.settle(read.ok());
            run.await
        }
        First::Exited(result) => result,
    }
}
