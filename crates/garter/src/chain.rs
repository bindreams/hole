use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use contracts::debug_requires;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::backoff::Backoff;
use crate::binary::TAKEDOWN_TAIL;
use crate::hop::{run_hop, Decision, Placement};
use crate::plugin::ChainPlugin;
use crate::port::{self, Probe};
use crate::shutdown;
use crate::sitrep::{PluginReady, StartError, Transports};
use crate::tap::INNER_STOP_BOUND;

/// The default [`ChainRunner::drain_timeout`]: longer than the longest take-down a member waits for, a [`TapPlugin`]
/// stopping a `BinaryPlugin` inner ([`INNER_STOP_BOUND`]), so a member that needs all of its own bounds is waited for
/// rather than aborted mid-take-down. The headroom makes that member's own warning come first.
///
/// [`TapPlugin`]: crate::TapPlugin
pub(crate) const DEFAULT_DRAIN_TIMEOUT: Duration =
    Duration::from_secs(INNER_STOP_BOUND.as_secs() + TAKEDOWN_TAIL.as_secs());

/// Whole-chain readiness reported via [`ChainRunner::on_ready`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReady {
    /// The address the data-source-facing plugin is accepting on
    /// (position 0 in Client mode, position N-1 in Server mode).
    pub listen: SocketAddr,
    /// End-to-end transports: the intersection across all hops. A
    /// transport is carried only if every plugin in the chain serves it.
    pub transports: Transports,
}

/// Direction of the SIP003 chain.
///
/// In `Client` mode, the chain forwards data from `SS_LOCAL_*` (the SS
/// client's listener) to `SS_REMOTE_*` (the SS server's public endpoint).
/// Plugin position 0 listens on `SS_LOCAL`, position N-1 forwards to
/// `SS_REMOTE`. This is what the SIP003 spec calls "client mode."
///
/// In `Server` mode, the chain forwards data from `SS_REMOTE_*` (the
/// public-facing endpoint that external clients connect to) to
/// `SS_LOCAL_*` (the local `ssserver` instance). The plugin chain is
/// supplied in the SAME order in both modes (data-source-side first),
/// but garter inverts the address wiring so position 0 forwards to
/// `SS_LOCAL` and position N-1 listens on `SS_REMOTE` (the public
/// endpoint). Accordingly, the chain-level readiness address reported
/// via [`ChainRunner::on_ready`] is the position N-1 plugin's listen
/// address in Server mode (versus position 0 in Client mode). This is
/// what the SIP003 spec calls "server mode" and what
/// `ssserver --plugin <chain-runner>` requires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Client,
    Server,
}

impl Mode {
    /// Derive the SIP003 chain mode from the `SS_PLUGIN_OPTIONS` string.
    /// Returns [`Mode::Server`] if a `server` key is present in the
    /// options (with or without a value), [`Mode::Client`] otherwise. Uses
    /// [`crate::parse_plugin_options`] to decide, so options like
    /// `servername=cdn.example.com` correctly resolve to client mode, and
    /// an escaped spelling like `\server` still resolves to server mode —
    /// matching how ex-ray reads the same string.
    ///
    /// Deliberately does NOT re-validate the `server` key's VALUE against
    /// ex-ray's own `parseBoolOption` grammar (bare/`1` only): this function
    /// is `BinaryPlugin::sip003_env`'s plugin-agnostic chain-direction
    /// detector, reached for every `BinaryPlugin` in a chain, not only
    /// ex-ray-family ones (garter's own README chains `obfs-local`
    /// alongside `v2ray-plugin`) — hard-rejecting a value spelling a
    /// third-party plugin accepts would be a false regression here. Where
    /// it IS ex-ray, `parseBoolOption` is itself fatal on those same
    /// spellings, so a real disagreement already fails loud when ex-ray
    /// starts.
    ///
    /// `Err` on a malformed options string (e.g. a dangling trailing
    /// backslash or an empty key). Neither `Mode::Client` nor `Mode::Server`
    /// would be real parity with ex-ray here, and there is no safe default to
    /// guess, so the failure is surfaced rather than papered over with one.
    ///
    /// Returns `crate::Error` (not the narrower `MalformedOptions`) so every
    /// caller gets the canonical "malformed SS_PLUGIN_OPTIONS: {reason}"
    /// wording through a plain `?`, with nothing to hand-write at the call site.
    pub fn from_plugin_options(opts: Option<&str>) -> crate::Result<Self> {
        let Some(opts) = opts else { return Ok(Mode::Client) };
        Ok(
            if crate::sip003::parse_plugin_options(opts)?
                .iter()
                .any(|(k, _)| k == "server")
            {
                Mode::Server
            } else {
                Mode::Client
            },
        )
    }

    /// The order a chain of `hops` plugins starts in and the two ends it is wired between, for `local` (`SS_LOCAL`) and
    /// `remote` (`SS_REMOTE`). This is the one place the mode decides them.
    ///
    /// Start position `p` forwards to the destination when `p == 0` and to the address the hop at `p - 1` was given
    /// otherwise; the last-started hop listens on the public end, and every other one on a port picked for it.
    pub(crate) fn flow(self, hops: usize, local: SocketAddr, remote: SocketAddr) -> Flow {
        match self {
            Mode::Client => Flow {
                order: (0..hops).rev().collect(),
                public: local,
                destination: remote,
            },
            Mode::Server => Flow {
                order: (0..hops).collect(),
                public: remote,
                destination: local,
            },
        }
    }
}

/// How a [`Mode`] wires a chain.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Flow {
    /// Plugin indexes in the order they start.
    pub(crate) order: Vec<usize>,
    /// What the last-started hop listens on, and what the chain reports.
    pub(crate) public: SocketAddr,
    /// What the first-started hop forwards to.
    pub(crate) destination: SocketAddr,
}

/// Orchestrates a chain of SIP003u plugins.
pub struct ChainRunner {
    plugins: Vec<Arc<dyn ChainPlugin>>,
    drain_timeout: Duration,
    ready_tx: Option<oneshot::Sender<Result<ChainReady, StartError>>>,
    external_cancel: Option<CancellationToken>,
    mode: Mode,
    /// Replaces the OS probe for every intermediate-port pick.
    #[cfg(test)]
    probe: Option<Arc<std::sync::Mutex<crate::port::Probe>>>,
}

impl Default for ChainRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainRunner {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
            ready_tx: None,
            external_cancel: None,
            mode: Mode::default(),
            #[cfg(test)]
            probe: None,
        }
    }

    /// Test seam: every intermediate-port pick asks `probe` instead of the OS.
    #[cfg(test)]
    pub(crate) fn with_probe(mut self, probe: crate::port::Probe) -> Self {
        self.probe = Some(Arc::new(std::sync::Mutex::new(probe)));
        self
    }

    /// Add a plugin to the end of the chain.
    #[debug_requires(self.plugins.len() <= 100, "chain is unreasonably long")]
    pub fn add(mut self, plugin: Box<dyn ChainPlugin>) -> Self {
        self.plugins.push(Arc::from(plugin));
        self
    }

    /// Set the drain timeout for graceful shutdown.
    ///
    /// Bounds the post-shutdown *drain phase* only — the interval between
    /// shutdown being requested (via external cancel, signal, or a plugin
    /// exiting) and force-kill of any plugins that haven't exited yet. It
    /// does NOT bound the chain's full lifetime: a long-running plugin that
    /// has not been asked to stop will run indefinitely regardless of this
    /// value.
    ///
    /// If the drain budget expires while plugins are still running,
    /// [`ChainRunner::run`] calls `JoinSet::abort_all` and returns
    /// `Err(Chain("drain timeout expired"))` — unless a plugin-level error
    /// was already captured, in which case that error takes precedence.
    /// The aborted tasks are joined before the function returns, so a
    /// plugin that reports a start failure from its `Drop` is heard, and a
    /// plugin that ends with an error or panics in the abort window is
    /// recorded like any other exit.
    ///
    /// The default is 12 seconds. It must outlast the longest take-down a
    /// plugin may need after a shutdown: a `BinaryPlugin` gives its child 5
    /// seconds to exit and 5 to close its output, and a `TapPlugin` waits for
    /// that plus a second for its inner, so a plugin that needs all of those
    /// is waited for, not aborted mid-take-down. The default is that wait plus
    /// a second. A smaller value cuts such a plugin off mid-take-down, and its
    /// last output is lost.
    ///
    /// It is also the bound on the wait that precedes the caller's release
    /// (see [`ChainRunner::on_ready`]): a start failure is delivered, or the
    /// `on_ready` channel closed, once the plugins have returned or this budget
    /// has expired.
    pub fn drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// Register a oneshot that fires when the whole chain is ready, or
    /// with the first plugin's start error if any plugin fails to start.
    ///
    /// Fires `Ok(ChainReady)` once EVERY plugin has reported `PluginReady`;
    /// `Err(StartError)` when any plugin reports a start failure or exits
    /// before readying. Each plugin reports its own readiness through the
    /// `ready` channel passed to [`ChainPlugin::run`]; the chain reads them one
    /// at a time as it starts the hops, and folds them into one chain-level outcome.
    ///
    /// A start failure ends the chain: the runner cancels every plugin and
    /// reports the failure only after each one's `run` has returned, so the
    /// output they were still relaying is out before the caller hears of it.
    /// A plugin that ignores the cancel is waited for until `drain_timeout`
    /// expires (see [`ChainRunner::drain_timeout`]); the failure is reported
    /// then, with the warning that bound already logs.
    ///
    /// If shutdown fires before every plugin has readied, the receiver gets the `StartError` the hop that was
    /// starting had delivered by the time every plugin returned, and `RecvError` if it had delivered none. A hop is
    /// started only once the hop it forwards to is ready, so a hop that never readies keeps every later one from
    /// starting. Only `Ok(ChainReady)` is sent at once: every other outcome, `RecvError`
    /// included, reaches the caller after every plugin has returned or `drain_timeout` has expired.
    pub fn on_ready(mut self, tx: oneshot::Sender<Result<ChainReady, StartError>>) -> Self {
        self.ready_tx = Some(tx);
        self
    }

    /// Set an external cancellation token. When cancelled, the runner
    /// gracefully stops all plugins (SIP003u shutdown sequence).
    pub fn cancel_token(mut self, token: CancellationToken) -> Self {
        self.external_cancel = Some(token);
        self
    }

    /// Set the chain direction. See [`Mode`] for semantics.
    ///
    /// Default: [`Mode::Client`].
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Run the full chain. Blocks until all plugins exit or shutdown is requested.
    ///
    /// The hops start one at a time, in the order [`Mode`] gives (the hop that forwards to the destination first), each
    /// only once the hop it forwards to has reported ready. Every hop but the last-started listens on a port the chain
    /// picks for it just before it starts.
    #[debug_requires(!self.plugins.is_empty(), "chain must have at least one plugin")]
    pub async fn run(self, env: crate::sip003::PluginEnv) -> crate::Result<()> {
        let n = self.plugins.len();

        // Resolve remote address
        let remote_addr: SocketAddr = tokio::net::lookup_host(format!("{}:{}", env.remote_host, env.remote_port))
            .await?
            .next()
            .ok_or_else(|| crate::Error::Chain(format!("failed to resolve {}:{}", env.remote_host, env.remote_port)))?;
        let flow = self.mode.flow(n, env.local_addr(), remote_addr);

        // Shared shutdown token. ChainRunner owns its own shutdown scope —
        // the external `cancel_token` builder option is wired into this
        // token below so cancel propagation flows in either direction.
        #[allow(clippy::disallowed_methods)]
        // Garter's chain-shutdown root: distinct from any caller cancel scope. See hole's clippy.toml CancellationToken::new rule.
        let shutdown = CancellationToken::new();
        shutdown::register_signal_handler(shutdown.clone());

        // Wire external cancellation into the shared shutdown token.
        // Selects on both tokens so the forwarder task terminates when
        // either side fires (prevents leaking if the chain ends naturally).
        if let Some(external) = self.external_cancel {
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                tokio::select! {
                    () = external.cancelled() => shutdown.cancel(),
                    () = shutdown.cancelled() => {} // chain ended naturally
                }
            });
        }

        let mut set = tokio::task::JoinSet::new();
        // Polled here, in Phase 1, rather than spawned: the caller's `ready` sender is owned by `gate` alone, so no
        // path releases it before the other plugins have drained.
        let mut gate = ReadyGate::new(self.ready_tx);
        let mut start = StartSequence::new(self.plugins, self.mode, flow);
        #[cfg(test)]
        {
            start.probe = self.probe;
        }
        start.launch(&mut set, &shutdown);

        // Phase 1: run unbounded until either all plugins exit naturally or
        // shutdown is requested. Any plugin exit (clean or error) also fires
        // `shutdown.cancel()` via `record_exit`, so in a multi-plugin chain
        // the first exit drives the whole chain into Phase 2. `drain_timeout`
        // deliberately does NOT bound this phase — a long-running plugin is
        // expected to run until something tells it to stop.
        //
        // The start sequence goes first (`biased`): a hop that exits without
        // readying has decided so by the time `join_next` yields it, and that
        // exit must be read as "exited before ready" before `record_exit`
        // cancels `shutdown` and turns it into a preempted start. It is also
        // what launches the next hop, so an exit of a hop that is already
        // running is seen while a later one is still starting.
        let mut first_error: Option<crate::Error> = None;
        loop {
            tokio::select! {
                biased;
                decision = await_decision(&mut start.pending), if start.pending.is_some() => {
                    start.pending = None;
                    match start.advance(decision, &mut set, &shutdown) {
                        Step::Launched => {}
                        Step::Settled(readiness) => gate.absorb(readiness),
                    }
                }
                () = shutdown.cancelled() => break,
                maybe_result = set.join_next() => {
                    let Some(result) = maybe_result else { break }; // all plugins exited
                    record_exit(result, &mut first_error, &shutdown);
                }
            }
        }
        // A start still waiting for its hop when the loop ended: the hop may yet deliver a failure it had decided,
        // until it returns, and the gate reads it at the release.
        if let Some(unread) = start.pending.take() {
            gate.absorb(Readiness::Preempted { unread: Some(unread) });
        }

        // Phase 2: drain remaining plugins, bounded by `drain_timeout`. An
        // empty `JoinSet` completes the inner `while let` immediately without
        // consuming any of the budget.
        let drain_result = tokio::time::timeout(self.drain_timeout, async {
            while let Some(result) = set.join_next().await {
                record_exit(result, &mut first_error, &shutdown);
            }
        })
        .await;

        let outcome = match drain_result {
            Ok(()) => first_error.map_or(Ok(()), Err),
            Err(_timeout) => {
                tracing::warn!("drain timeout expired, aborting remaining plugins");
                set.abort_all();
                // Aborting drops each plugin's future, and a plugin may deliver a start failure it decided from
                // that drop: wait for the drops, so the gate below finds the failure. A task cancelled by the abort
                // is expected; anything else (an error, a panic) is an exit like any other.
                while let Some(result) = set.join_next().await {
                    if matches!(&result, Err(join_err) if join_err.is_cancelled()) {
                        continue;
                    }
                    record_exit(result, &mut first_error, &shutdown);
                }
                // A plugin-level error (if captured before drain) is more
                // diagnostic than the drain-timeout error, so it takes
                // precedence.
                Err(first_error.unwrap_or_else(|| crate::Error::Chain("drain timeout expired".into())))
            }
        };

        // Every plugin has returned (or been given up on at the drain bound):
        // only now does the caller hear of a start failure, or find the
        // channel closed.
        gate.release();
        outcome
    }
}

// Helpers =============================================================================================================

/// What the chain's start found.
#[derive(Debug)]
pub(crate) enum Readiness {
    /// Every hop reported ready.
    Ready(ChainReady),
    /// A hop failed to start, or exited before it could say so. The chain is no longer viable.
    Failed(StartError),
    /// `shutdown` came first, or a hop ended without deciding, with nothing to report yet. `unread` is the decision
    /// of the hop that was starting, if it had not been read: that hop may still deliver a start failure it had
    /// decided, until it returns.
    Preempted {
        unread: Option<oneshot::Receiver<Decision>>,
    },
}

/// The sole owner of the caller's `ready` sender, and the one place that decides what the caller is told. A ready
/// chain is reported at once; every other end (a start failure, a cancel, a member that kept `ready` until it was
/// stopped) releases the sender only through [`ReadyGate::release`], which [`ChainRunner::run`] calls once every
/// member's `run` has returned or been given up on at `drain_timeout`. A failure a member decided and delivered while
/// it stopped is found by the release, whichever way the chain ended.
pub(crate) struct ReadyGate {
    ready_tx: Option<oneshot::Sender<Result<ChainReady, StartError>>>,
    failure: Option<StartError>,
    /// The decision a preempted start had not read.
    unread: Option<oneshot::Receiver<Decision>>,
}

impl ReadyGate {
    pub(crate) fn new(ready_tx: Option<oneshot::Sender<Result<ChainReady, StartError>>>) -> Self {
        Self {
            ready_tx,
            failure: None,
            unread: None,
        }
    }

    pub(crate) fn absorb(&mut self, readiness: Readiness) {
        match readiness {
            Readiness::Ready(chain) => {
                if let Some(ready_tx) = self.ready_tx.take() {
                    let _ = ready_tx.send(Ok(chain));
                }
            }
            Readiness::Failed(error) => self.failure = Some(error),
            Readiness::Preempted { unread } => self.unread = unread,
        }
    }

    /// Sends the failure to report, if there is one; otherwise drops the sender unsent, which the receiver sees as
    /// `RecvError`. The failure is the one the start found, or else the one a preempted hop has delivered since. A
    /// delivered `Ready` is not rescued: `shutdown` is chain-wide and nothing shows the chain is still viable.
    pub(crate) fn release(self) {
        let Some(ready_tx) = self.ready_tx else { return };
        let delivered_since = || {
            self.unread.and_then(|mut unread| match unread.try_recv() {
                Ok(Decision::Failed(error)) => Some(error),
                Ok(Decision::Ready { .. }) => None,
                Ok(Decision::Dropped) => None,
                Err(_) => None,
            })
        };
        if let Some(error) = self.failure.or_else(delivered_since) {
            let _ = ready_tx.send(Err(error));
        }
    }
}

/// What the chain makes of one hop's [`Decision`].
#[derive(Debug)]
pub(crate) enum Verdict {
    /// The hop is up: start the next one.
    Ready { given: SocketAddr, report: PluginReady },
    /// The start failed, and the chain was cancelled for it.
    Failed(StartError),
    /// The chain was already stopping, or the hop ended without deciding: nothing to report.
    Preempted,
}

/// Judges `decision` against `shutdown`. A start failure the hop delivered stands whoever cancelled the chain, because
/// `BindConflict` is the only retryable class and discarding one turns a collision into a hard failure. A `Ready` or a
/// dropped sender after the cancel is the cancel's doing, so it is preempted rather than reported. A start failure
/// cancels `shutdown`: the other plugins stop cooperatively.
pub(crate) fn judge(decision: Result<Decision, oneshot::error::RecvError>, shutdown: &CancellationToken) -> Verdict {
    match decision {
        Ok(Decision::Failed(error)) => {
            shutdown.cancel();
            Verdict::Failed(error)
        }
        Ok(Decision::Ready { given, report }) => {
            if shutdown.is_cancelled() {
                return Verdict::Preempted;
            }
            Verdict::Ready { given, report }
        }
        Ok(Decision::Dropped) => {
            if shutdown.is_cancelled() {
                return Verdict::Preempted;
            }
            // The hop dropped its sender unsent, so it exited before readying. The same exit is independently observed by
            // the Phase-1 `record_exit`, which sets `first_error` and cancels: that is the lifecycle channel that becomes
            // `run`'s return, and this is the typed cause for `on_ready`. The two are separate observers of one event.
            shutdown.cancel();
            Verdict::Failed(StartError::Fatal {
                detail: "plugin exited before becoming ready".into(),
                errno: None,
            })
        }
        Err(_) => Verdict::Preempted,
    }
}

/// What the start does after a decision.
enum Step {
    /// The hop was ready and the next one is launched.
    Launched,
    /// The start is over, one way or another.
    Settled(Readiness),
}

/// The chain's start: launches the hops one at a time in [`Flow`] order and reads each one's [`Decision`] before the
/// next launch.
struct StartSequence {
    plugins: Vec<Arc<dyn ChainPlugin>>,
    mode: Mode,
    flow: Flow,
    /// Position in `flow.order` of the next hop to launch.
    next: usize,
    /// What the next hop forwards to: the destination, then each hop's `given`.
    forward_to: SocketAddr,
    /// Ports an intermediate pick must not return: the ends of the chain and the ports already given.
    taken: Vec<u16>,
    transports: Transports,
    /// The decision of the hop that was launched last, until it is read.
    pending: Option<oneshot::Receiver<Decision>>,
    #[cfg(test)]
    probe: Option<Arc<std::sync::Mutex<Probe>>>,
}

impl StartSequence {
    fn new(plugins: Vec<Arc<dyn ChainPlugin>>, mode: Mode, flow: Flow) -> Self {
        let taken = [flow.public.port(), flow.destination.port()]
            .into_iter()
            .filter(|&port| port != 0)
            .collect();
        Self {
            plugins,
            mode,
            next: 0,
            forward_to: flow.destination,
            taken,
            // Intersection identity (the full transport set); each hop's reported transports narrow this. `all()`
            // lives on the `bitflags::Flags` trait for this generated type.
            transports: <Transports as bitflags::Flags>::all(),
            pending: None,
            flow,
            #[cfg(test)]
            probe: None,
        }
    }

    /// The probe an intermediate hop picks its port with.
    fn probe(&self) -> Probe {
        #[cfg(test)]
        {
            if let Some(shared) = &self.probe {
                let shared = shared.clone();
                return Box::new(move || {
                    let mut probe = shared.lock().unwrap();
                    probe()
                });
            }
        }
        port::os_probe(Ipv4Addr::LOCALHOST.into())
    }

    /// Launches the hop at `next`; its decision arrives on `pending`.
    fn launch(&mut self, set: &mut tokio::task::JoinSet<(String, crate::Result<()>)>, shutdown: &CancellationToken) {
        debug_assert!(
            self.pending.is_none(),
            "a hop is launched only after the last one decided"
        );
        let position = self.flow.order[self.next];
        let plugin = self.plugins[position].clone();
        let placement = if self.next + 1 == self.flow.order.len() {
            Placement::Public(self.flow.public)
        } else {
            Placement::Intermediate {
                ip: Ipv4Addr::LOCALHOST.into(),
                taken: self.taken.clone(),
                probe: self.probe(),
            }
        };
        let (decided_tx, decided_rx) = oneshot::channel();
        self.pending = Some(decided_rx);

        let name = plugin.name().to_string();
        let span = tracing::info_span!("plugin", name = %name, position, chain_mode = ?self.mode);
        let token = shutdown.child_token();
        let remote = self.forward_to;
        set.spawn(async move {
            let result = run_hop(plugin, placement, remote, token, decided_tx)
                .instrument(span)
                .await;
            (name, result)
        });
    }

    /// Takes one hop's `decision` and launches the next hop if the chain is still starting.
    fn advance(
        &mut self,
        decision: Result<Decision, oneshot::error::RecvError>,
        set: &mut tokio::task::JoinSet<(String, crate::Result<()>)>,
        shutdown: &CancellationToken,
    ) -> Step {
        match judge(decision, shutdown) {
            Verdict::Failed(error) => Step::Settled(Readiness::Failed(error)),
            Verdict::Preempted => Step::Settled(Readiness::Preempted { unread: None }),
            Verdict::Ready { given, report } => {
                self.transports &= report.transports;
                self.next += 1;
                if self.next == self.flow.order.len() {
                    // The public hop is the last one started; its reported address is the chain's.
                    return Step::Settled(Readiness::Ready(ChainReady {
                        listen: report.listen,
                        transports: self.transports,
                    }));
                }
                if given.port() != 0 {
                    self.taken.push(given.port());
                }
                self.forward_to = given;
                self.launch(set, shutdown);
                Step::Launched
            }
        }
    }
}

/// Waits for the decision of the hop that is starting; never ends when there is none.
async fn await_decision(
    pending: &mut Option<oneshot::Receiver<Decision>>,
) -> Result<Decision, oneshot::error::RecvError> {
    match pending {
        Some(decision) => decision.await,
        None => std::future::pending().await,
    }
}

/// Shared handler for a single plugin-task exit result. Updates
/// `first_error` on a first-write-wins basis and fires `shutdown` so the
/// rest of the chain stops. Called from both Phase 1 and Phase 2 of
/// `ChainRunner::run`.
pub(crate) fn record_exit(
    result: Result<(String, crate::Result<()>), tokio::task::JoinError>,
    first_error: &mut Option<crate::Error>,
    shutdown: &CancellationToken,
) {
    match result {
        Ok((name, Ok(()))) => {
            tracing::info!(plugin = %name, "exited cleanly");
            shutdown.cancel();
        }
        Ok((name, Err(e))) => {
            // Surface the process exit code / signal as structured fields so
            // a mid-run plugin death is loud + machine-parseable in bridge.log
            // (bindreams/hole#438 — the "third silent gap": ex-ray vanished
            // with no exit line).
            let exit_code = match &e {
                crate::Error::PluginExit { code, .. } => Some(*code),
                _ => None,
            };
            let killed = matches!(e, crate::Error::PluginKilled { .. });
            tracing::error!(
                plugin = %name,
                exit_code,
                killed,
                error = %e,
                "exited with error"
            );
            if first_error.is_none() {
                *first_error = Some(e);
            }
            shutdown.cancel();
        }
        Err(join_err) => {
            tracing::error!(error = %join_err, "plugin task panicked");
            if first_error.is_none() {
                *first_error = Some(crate::Error::Chain(format!("plugin panicked: {join_err}")));
            }
            shutdown.cancel();
        }
    }
}

/// Poll a TCP address with exponential backoff (10ms doubling to 1s) until it
/// accepts a connection. Returns `None` if shutdown fires before the address is
/// ready.
///
/// Each connect attempt races against the shutdown token so that a
/// cancellation during an OS-level TCP timeout is not delayed.
pub(crate) async fn poll_ready(addr: SocketAddr, shutdown: CancellationToken) -> Option<SocketAddr> {
    let mut backoff = Backoff::new(Duration::from_millis(10), Duration::from_secs(1));

    loop {
        tokio::select! {
            result = tokio::net::TcpStream::connect(addr) => {
                if result.is_ok() {
                    return Some(addr);
                }
            }
            () = shutdown.cancelled() => return None,
        }

        if !backoff.pause(&shutdown).await {
            return None;
        }
    }
}
