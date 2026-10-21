//! One hop of a chain: port pick, run, restart on a lost intermediate port.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::plugin::ChainPlugin;
use crate::port::{self, retry_backoff, Probe};
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

impl Decision {
    /// The start failure this decision carries; it stands whoever cancelled the chain afterwards.
    pub(crate) fn failure(&self) -> Option<&StartError> {
        match self {
            Decision::Ready { .. } => None,
            Decision::Dropped => None,
            Decision::Failed(error) => Some(error),
        }
    }

    /// The conflict that makes the hop run again instead of being reported, if this decision is one.
    ///
    /// Only an intermediate hop's bind conflict qualifies: its port was the chain's pick, so a fresh pick can win,
    /// while the public port is the caller's and a fatal failure is final.
    fn restart_cause(&self, intermediate: bool) -> Option<&StartError> {
        match self {
            Decision::Ready { .. } => None,
            Decision::Dropped => None,
            Decision::Failed(error) => match error {
                StartError::BindConflict { .. } if intermediate => Some(error),
                StartError::BindConflict { .. } => None,
                StartError::Fatal { .. } => None,
            },
        }
    }
}

/// Where a hop listens.
pub(crate) enum Placement {
    /// An address the caller chose, which the chain neither picks nor changes.
    Public(SocketAddr),
    /// A port the chain picks on `ip` just before the hop starts, from `probe`, skipping `taken`.
    Intermediate { ip: IpAddr, taken: Vec<u16>, probe: Probe },
}

/// Where a hop's decision goes, across all of its attempts.
struct Outlet {
    decided: Option<oneshot::Sender<Decision>>,
    intermediate: bool,
    /// The conflict that ended the last attempt in a restart.
    restart: Option<StartError>,
}

impl Outlet {
    fn report(&mut self, decision: Decision) {
        if let Some(decided) = self.decided.take() {
            let _ = decided.send(decision);
        }
    }
}

/// Reads one attempt's readiness and routes it: to the chain, or to [`Outlet::restart`] when it is a conflict the hop
/// recovers from. It routes on every path out of [`attempt`], including a failure the plugin sends from its own `Drop`
/// when the chain aborts the hop.
struct Relay<'a> {
    ready: oneshot::Receiver<Result<PluginReady, StartError>>,
    given: SocketAddr,
    outlet: &'a mut Outlet,
    settled: bool,
}

impl Relay<'_> {
    /// Routes `outcome`, `None` for a sender dropped unsent, unless this attempt's readiness was already routed.
    fn settle(&mut self, outcome: Option<Result<PluginReady, StartError>>) {
        if std::mem::replace(&mut self.settled, true) {
            return;
        }
        let decision = match outcome {
            Some(Ok(report)) => Decision::Ready {
                given: self.given,
                report,
            },
            Some(Err(error)) => Decision::Failed(error),
            None => Decision::Dropped,
        };
        match decision.restart_cause(self.outlet.intermediate).cloned() {
            Some(cause) => self.outlet.restart = Some(cause),
            None => self.outlet.report(decision),
        }
    }
}

impl Drop for Relay<'_> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        match self.ready.try_recv() {
            Ok(outcome) => self.settle(Some(outcome)),
            Err(oneshot::error::TryRecvError::Closed) => self.settle(None),
            // The plugin kept `ready` past its own end: nothing is decided, and the chain reads the hop ending without
            // a decision as an exit before ready.
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
/// An intermediate hop that reports a bind conflict is stopped, waited for, and run again on a fresh pick, with no
/// attempt cap: only `shutdown` ends it. Any other failure, and a conflict on the public port, is the hop's decision.
///
/// A pick that ends because `shutdown` fired starts nothing and decides nothing. A pick that fails for a reason that
/// is not a race fails the hop with a [`StartError::Fatal`].
pub(crate) async fn run_hop(
    plugin: Arc<dyn ChainPlugin>,
    mut placement: Placement,
    remote: SocketAddr,
    shutdown: CancellationToken,
    decided: oneshot::Sender<Decision>,
) -> crate::Result<()> {
    let mut outlet = Outlet {
        decided: Some(decided),
        intermediate: matches!(placement, Placement::Intermediate { .. }),
        restart: None,
    };
    let mut backoff = retry_backoff();
    loop {
        let local = match &mut placement {
            Placement::Public(addr) => *addr,
            Placement::Intermediate { ip, taken, probe } => {
                match port::pick_with(plugin.name(), *ip, taken, &mut *probe, &shutdown).await {
                    Ok(Some(addr)) => addr,
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        outlet.report(Decision::Failed(StartError::Fatal {
                            detail: format!("picking a port for plugin '{}' failed: {error}", plugin.name()),
                            errno: error.raw_os_error(),
                        }));
                        return Err(error.into());
                    }
                }
            }
        };

        let result = attempt(&plugin, local, remote, &shutdown, &mut outlet).await;
        let Some(cause) = outlet.restart.take() else {
            return result;
        };
        tracing::info!(
            port = local.port(),
            error = %cause,
            "intermediate port lost; restarting the hop on a fresh port"
        );
        tracing::debug!(attempt_result = ?result, "stopped attempt returned");
        if !backoff.pause(&shutdown).await {
            return Ok(());
        }
    }
}

/// One run of `plugin` on `local`. If readiness says to restart, the attempt is stopped and waited for before this
/// returns, so the caller finds [`Outlet::restart`] set and the plugin gone.
async fn attempt(
    plugin: &Arc<dyn ChainPlugin>,
    local: SocketAddr,
    remote: SocketAddr,
    shutdown: &CancellationToken,
    outlet: &mut Outlet,
) -> crate::Result<()> {
    let stop = shutdown.child_token();
    let (ready_tx, ready_rx) = oneshot::channel();
    let mut relay = Relay {
        ready: ready_rx,
        given: local,
        outlet,
        settled: false,
    };
    let run = plugin.run(local, remote, stop.clone(), ready_tx);
    tokio::pin!(run);

    let first = tokio::select! {
        read = &mut relay.ready => First::Ready(read),
        result = &mut run => First::Exited(result),
    };
    match first {
        First::Ready(read) => {
            relay.settle(read.ok());
            if relay.outlet.restart.is_some() {
                stop.cancel();
            }
            run.await
        }
        First::Exited(result) => result,
    }
}
