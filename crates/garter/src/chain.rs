use std::net::SocketAddr;
use std::time::Duration;

use contracts::debug_requires;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::plugin::ChainPlugin;
use crate::shutdown;
use crate::sitrep::{PluginReady, StartError, Transports};

const MAX_PORT_RETRIES: usize = 3;

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
}

/// Allocate `count` unique ephemeral ports on localhost.
pub fn allocate_ports(count: usize) -> crate::Result<Vec<SocketAddr>> {
    let mut ports = Vec::with_capacity(count);
    let mut seen = std::collections::HashSet::with_capacity(count);
    for _ in 0..count {
        loop {
            let addr = allocate_one_port()?;
            if seen.insert(addr.port()) {
                ports.push(addr);
                break;
            }
            tracing::debug!(port = addr.port(), "duplicate port, retrying");
        }
    }
    Ok(ports)
}

fn allocate_one_port() -> crate::Result<SocketAddr> {
    for attempt in 0..MAX_PORT_RETRIES {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        drop(listener);

        #[cfg(all(test, windows))]
        test_hook::fire(addr.port());

        match std::net::TcpListener::bind(addr) {
            Ok(l) => {
                drop(l);
                return Ok(addr);
            }
            // `AddrInUse` — another socket grabbed the port between drop and rebind.
            // `PermissionDenied` — Windows `WSAEACCES`: typically a shift in the
            // TCP dynamic excluded-port range (Hyper-V / WSL2 / Docker Desktop
            // reservations, visible via `netsh int ipv4 show excludedportrange`),
            // or another socket claiming the port with `SO_EXCLUSIVEADDRUSE` on a
            // wildcard interface.
            // `AddrNotAvailable` — same excluded-port-range class; distinct from
            // `WSAEACCES` only in whether the kernel rejects the bind at the
            // address-reservation layer or the permission layer.
            // All three are transient probe-races; retry on a fresh ephemeral port.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::AddrInUse
                        | std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::AddrNotAvailable
                ) =>
            {
                tracing::debug!(
                    attempt,
                    port = addr.port(),
                    kind = ?e.kind(),
                    "port unavailable, retrying"
                );
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(crate::Error::Chain(
        "failed to allocate a free port after retries".into(),
    ))
}

/// Orchestrates a chain of SIP003u plugins.
pub struct ChainRunner {
    plugins: Vec<Box<dyn ChainPlugin>>,
    drain_timeout: Duration,
    ready_tx: Option<oneshot::Sender<Result<ChainReady, StartError>>>,
    external_cancel: Option<CancellationToken>,
    mode: Mode,
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
            drain_timeout: Duration::from_secs(5),
            ready_tx: None,
            external_cancel: None,
            mode: Mode::default(),
        }
    }

    /// Add a plugin to the end of the chain.
    #[debug_requires(self.plugins.len() <= 100, "chain is unreasonably long")]
    pub fn add(mut self, plugin: Box<dyn ChainPlugin>) -> Self {
        self.plugins.push(plugin);
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
    /// Note that aborted tasks are not joined before the function returns;
    /// their underlying `Drop` impls run as the `JoinSet` is dropped, but
    /// any terminal error produced during the abort window is lost.
    pub fn drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    /// Register a oneshot that fires when the whole chain is ready, or
    /// with the first plugin's start error if any plugin fails to start.
    ///
    /// Fires `Ok(ChainReady)` once EVERY plugin has reported `PluginReady`;
    /// `Err(StartError)` as soon as any plugin reports a start failure or
    /// exits before readying. Each plugin reports its own readiness through
    /// the `ready` channel passed to [`ChainPlugin::run`]; the aggregator
    /// collects the N per-plugin results into one chain-level outcome.
    ///
    /// If shutdown fires before every plugin has readied, `tx` carries
    /// whichever outcome is most specific rather than being unconditionally
    /// dropped: the most specific already-delivered `StartError` if any
    /// plugin had one buffered, else `Err(StartError::ExitedBeforeReady)`
    /// if any plugin's readiness sender had already closed unsent, and
    /// only drops `tx` (leaving the receiver to see `RecvError`) when every
    /// remaining plugin is genuinely still pending. See
    /// [`run_readiness_aggregator`]'s doc comment for why shutdown alone is
    /// never enough to justify dropping `tx` outright.
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
    #[debug_requires(!self.plugins.is_empty(), "chain must have at least one plugin")]
    pub async fn run(self, env: crate::sip003::PluginEnv) -> crate::Result<()> {
        let n = self.plugins.len();

        // Resolve remote address
        let remote_addr: SocketAddr = tokio::net::lookup_host(format!("{}:{}", env.remote_host, env.remote_port))
            .await?
            .next()
            .ok_or_else(|| crate::Error::Chain(format!("failed to resolve {}:{}", env.remote_host, env.remote_port)))?;

        // Build address chain: [local, intermediate..., remote]
        let intermediate = allocate_ports(n.saturating_sub(1))?;
        let mut addrs = Vec::with_capacity(n + 1);
        addrs.push(env.local_addr());
        addrs.extend(intermediate);
        addrs.push(remote_addr);

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

        // Capture `Copy` field before the partial move below.
        let mode = self.mode;

        // Spawn all plugins, each with its own readiness channel. In Client
        // mode, plugin i listens on addrs[i] and forwards to addrs[i+1]. In
        // Server mode, the direction is inverted: plugin i listens on
        // addrs[i+1] and forwards to addrs[i]. See `Mode`. The aggregator
        // below collects the N per-plugin readiness results.
        let mut set = tokio::task::JoinSet::new();
        let mut ready_rxs: Vec<(usize, oneshot::Receiver<Result<PluginReady, StartError>>)> = Vec::with_capacity(n);
        for (i, plugin) in self.plugins.into_iter().enumerate() {
            let (local, remote) = match mode {
                Mode::Client => (addrs[i], addrs[i + 1]),
                Mode::Server => (addrs[i + 1], addrs[i]),
            };
            let token = shutdown.child_token();
            let plugin_name = plugin.name().to_string();
            let (rtx, rrx) = oneshot::channel();
            ready_rxs.push((i, rrx));

            let span = tracing::info_span!(
                "plugin",
                name = %plugin_name,
                position = i,
                chain_mode = ?mode,
            );
            set.spawn(async move {
                let result = plugin.run(local, remote, token, rtx).instrument(span).await;
                (plugin_name, result)
            });
        }

        // Readiness aggregator: await all N plugin results, racing the
        // shared shutdown token so a cancel during startup doesn't hang.
        // The aggregator body lives in a free async fn (not an inline
        // `async move`) because `#[debug_requires]` rewrites `return` in
        // this fn's body into `break 'run`, which is illegal across an
        // async-block boundary; a free fn keeps the rewrite out of it.
        if let Some(ready_tx) = self.ready_tx {
            tokio::spawn(run_readiness_aggregator(ready_rxs, n, mode, shutdown.clone(), ready_tx));
        }

        // Phase 1: run unbounded until either all plugins exit naturally or
        // shutdown is requested. Any plugin exit (clean or error) also fires
        // `shutdown.cancel()` via `record_exit`, so in a multi-plugin chain
        // the first exit drives the whole chain into Phase 2. `drain_timeout`
        // deliberately does NOT bound this phase — a long-running plugin is
        // expected to run until something tells it to stop.
        let mut first_error: Option<crate::Error> = None;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                maybe_result = set.join_next() => {
                    let Some(result) = maybe_result else { break }; // all plugins exited
                    record_exit(result, &mut first_error, &shutdown);
                }
            }
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

        match drain_result {
            Ok(()) => first_error.map_or(Ok(()), Err),
            Err(_timeout) => {
                tracing::warn!("drain timeout expired, aborting remaining plugins");
                set.abort_all();
                // A plugin-level error (if captured before drain) is more
                // diagnostic than the drain-timeout error, so it takes
                // precedence.
                Err(first_error.unwrap_or_else(|| crate::Error::Chain("drain timeout expired".into())))
            }
        }
    }
}

// Helpers =============================================================================================================

/// Scan `rxs` for an already-delivered start-failure signal, preferring a
/// SPECIFIC `Err(StartError)` — anything other than `ExitedBeforeReady`,
/// which is itself a "no reason known" placeholder, not a real diagnosis —
/// over a generic signal (a `Closed` sender, or a *delivered*
/// `ExitedBeforeReady`) regardless of which order they're found in. A
/// generic signal earlier in iteration order must never mask a real
/// `BindConflict`/`Fatal` delivered by a later one, however that later one
/// arrives. Returns `None` only when every scanned receiver is genuinely
/// `Empty` (or holds an `Ok(PluginReady)`, which is not a failure and is
/// ignored here) — the caller then has nothing to recover.
///
/// A point-in-time `try_recv` snapshot — used ONLY where the caller must
/// terminate PROMPTLY even when a remaining receiver is legitimately,
/// indefinitely `Empty` (a plugin still starting up, not yet failed): the
/// shutdown-preempted arm of [`run_readiness_aggregator`] (shutdown does not
/// itself mean any plugin failed) and [`crate::tap::TapPlugin`]'s inner-exit
/// race (the single receiver scanned there is already resolved by the time
/// it's reached, so this is exact, not approximate). See
/// `aggregator_shutdown_with_nothing_to_recover_drops_ready_tx_promptly` in
/// `chain_tests.rs`, which pins the prompt-termination requirement.
///
/// For the OTHER two arms of `run_readiness_aggregator` — `Err(_recv)` and a
/// delivered `ExitedBeforeReady` — a plugin has already DEFINITIVELY failed,
/// so [`drain_for_delivered_error`] is used instead: awaiting there cannot
/// hang, because that same failure fires `shutdown` via `record_exit`,
/// which bounds every other remaining plugin via `ChainRunner::run`'s own
/// `drain_timeout`/`abort_all`.
pub(crate) fn scan_for_delivered_error<'a>(
    rxs: impl Iterator<Item = &'a mut oneshot::Receiver<Result<PluginReady, StartError>>>,
) -> Option<StartError> {
    let mut saw_generic = false;
    for r in rxs {
        match r.try_recv() {
            Ok(Err(StartError::ExitedBeforeReady)) => saw_generic = true,
            Ok(Err(e)) => return Some(e),
            Err(oneshot::error::TryRecvError::Closed) => saw_generic = true,
            Ok(Ok(_)) | Err(oneshot::error::TryRecvError::Empty) => {}
        }
    }
    saw_generic.then_some(StartError::ExitedBeforeReady)
}

/// Await `rxs` — each to ITS OWN resolution — for the same preference
/// [`scan_for_delivered_error`] applies (a SPECIFIC `Err(StartError)` over a
/// generic `Closed`/delivered-`ExitedBeforeReady` signal, regardless of
/// order). Used by [`send_recovered_or_generic`], from the TWO
/// `run_readiness_aggregator` arms where a plugin has already definitively
/// failed — see [`scan_for_delivered_error`]'s doc comment for why awaiting
/// is safe (bounded by `ChainRunner`'s own `drain_timeout`) in exactly those
/// two arms and NOT the shutdown-preempted one. Closes the window
/// `scan_for_delivered_error`'s try_recv snapshot leaves open: a
/// `BindConflict`/`Fatal` delivered a moment AFTER a snapshot would run is
/// still recovered here, not silently downgraded.
///
/// `pub(crate)`: also used by [`crate::tap::TapPlugin`]'s `join` arm, for
/// the identical reason — `BinaryPlugin::run` (the only inner the bridge
/// ever taps) hands its readiness sender to a spawned reader task that is
/// only best-effort-joined (a 100ms grace window) before `run` returns, so
/// `inner_handle` completing does NOT guarantee `inner_ready_rx` has
/// resolved yet. Awaiting here is bounded the same way: the child process
/// has already exited by this point, so its stdout pipe closes and the
/// reader task's own `lines.next_line()` loop terminates on EOF shortly
/// after, dropping the sender if it never sent.
pub(crate) async fn drain_for_delivered_error<'a>(
    rxs: impl Iterator<Item = &'a mut oneshot::Receiver<Result<PluginReady, StartError>>>,
) -> Option<StartError> {
    let mut saw_generic = false;
    for r in rxs {
        match r.await {
            Ok(Err(StartError::ExitedBeforeReady)) => saw_generic = true,
            Ok(Err(e)) => return Some(e),
            Err(_recv) => saw_generic = true,
            Ok(Ok(_)) => {}
        }
    }
    saw_generic.then_some(StartError::ExitedBeforeReady)
}

/// Aggregate the N per-plugin readiness results into a single chain-level
/// outcome on `ready_tx`.
///
/// Awaits each plugin's `ready` receiver in turn, racing the shared
/// `shutdown` token so a cancel during startup doesn't hang. `shutdown` is
/// checked with `biased`, so on any poll where both it and the receiver
/// being awaited are simultaneously ready, `shutdown` wins and the receiver
/// is never polled that round — before returning on shutdown, this fn
/// therefore always falls back to [`scan_for_delivered_error`] to recover
/// whatever the biased check would otherwise have discarded, rather than
/// dropping `ready_tx` unconditionally. The position-0 plugin's reported
/// `listen` is the chain's public address in Client mode; in Server mode it
/// is position N-1. The chain's transports are the intersection across all
/// hops.
pub(crate) async fn run_readiness_aggregator(
    ready_rxs: Vec<(usize, oneshot::Receiver<Result<PluginReady, StartError>>)>,
    n: usize,
    mode: Mode,
    shutdown: CancellationToken,
    ready_tx: oneshot::Sender<Result<ChainReady, StartError>>,
) {
    let mut plugin_listens: Vec<Option<SocketAddr>> = vec![None; n];
    // Intersection identity (the full transport set); each plugin's
    // reported transports narrow this. `all()` lives on the
    // `bitflags::Flags` trait for this generated type.
    let mut transports = <Transports as bitflags::Flags>::all();
    let public_index = match mode {
        Mode::Client => 0,
        Mode::Server => n - 1,
    };
    let mut remaining: std::collections::VecDeque<_> = ready_rxs.into_iter().collect();
    while let Some((i, mut rrx)) = remaining.pop_front() {
        // `biased` checks the shutdown arm first regardless of whether
        // `rrx` ALSO already has a value waiting — a plugin can call
        // `ready.send(...)` and exit (dropping its task, which is what
        // fires `shutdown` via `record_exit`) within the same poll, with
        // no `.await` between the two. Naively discarding on shutdown here
        // would silently downgrade a real `BindConflict`/`Fatal` to a
        // generic `ExitedBeforeReady`, so the shutdown arm yields `None`
        // instead of returning outright, and the scan below checks for an
        // already-delivered value — on ANY not-yet-processed receiver, not
        // just this one, since shutdown can win the bias while an EARLIER
        // poll of a LATER plugin already delivered — before treating this
        // as shutdown preempting a chain that never got to report anything.
        let selected = tokio::select! {
            biased;
            () = shutdown.cancelled() => None,
            r = &mut rrx => Some(r),
        };
        let outcome = match selected {
            Some(r) => r,
            None => {
                // Same preference as the shutdown-arm scan above: see
                // `scan_for_delivered_error`'s doc comment.
                let rest = std::iter::once(&mut rrx).chain(remaining.iter_mut().map(|(_, r)| r));
                match scan_for_delivered_error(rest) {
                    Some(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                    None => return, // nothing to recover anywhere → drop ready_tx; the receiver gets RecvError.
                }
            }
        };
        match outcome {
            Ok(Ok(pr)) => {
                plugin_listens[i] = Some(pr.listen);
                transports &= pr.transports;
            }
            // A delivered `ExitedBeforeReady` is itself a "no reason known"
            // placeholder (see its doc comment) — before forwarding it,
            // check whether a LATER plugin already delivered (or still
            // delivers) something more specific: same preference as
            // `scan_for_delivered_error`'s doc comment.
            Ok(Err(StartError::ExitedBeforeReady)) => {
                let rest = remaining.iter_mut().map(|(_, r)| r);
                send_recovered_or_generic(rest, ready_tx).await;
                return;
            }
            Ok(Err(start_err)) => {
                let _ = ready_tx.send(Err(start_err));
                return;
            }
            Err(_recv) => {
                // Sender dropped unsent → exited before readying; same recovery
                // preference as above (see `scan_for_delivered_error`'s doc
                // comment). This is the START-GATE channel — the SAME exit is
                // independently observed by the Phase-1 record_exit loop as
                // the LIFECYCLE channel that becomes run()'s return. The two
                // are intentionally separate observers of one event; do NOT
                // reconcile them into one value.
                let rest = remaining.iter_mut().map(|(_, r)| r);
                send_recovered_or_generic(rest, ready_tx).await;
                return;
            }
        }
    }
    let listen = plugin_listens[public_index].expect("public plugin must have reported a listen address");
    let _ = ready_tx.send(Ok(ChainReady { listen, transports }));
}

/// Drain `rest` to resolution and send the best recoverable error on
/// `ready_tx` — shared by the `ExitedBeforeReady` and `Err(_recv)` arms
/// above, which reach this in the identical shape: one plugin has already
/// confirmed "I have no reason of my own", so drain every other
/// not-yet-processed receiver for something better, falling back to the
/// generic placeholder rather than dropping `ready_tx` unsent. Unlike the
/// shutdown-preempted arm (which drops `ready_tx` when nothing is
/// recoverable, matching "shutdown before anything ready"), these two arms
/// already KNOW a plugin failed — there is always something to report here,
/// even if it's only "no reason given". Uses [`drain_for_delivered_error`]
/// (await-to-resolution), not [`scan_for_delivered_error`] (point-in-time
/// snapshot) — see the latter's doc comment for why that's safe here and
/// not in the shutdown-preempted arm.
async fn send_recovered_or_generic<'a>(
    rest: impl Iterator<Item = &'a mut oneshot::Receiver<Result<PluginReady, StartError>>>,
    ready_tx: oneshot::Sender<Result<ChainReady, StartError>>,
) {
    let recovered = drain_for_delivered_error(rest)
        .await
        .unwrap_or(StartError::ExitedBeforeReady);
    let _ = ready_tx.send(Err(recovered));
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

/// Poll a TCP address with exponential backoff until it accepts a connection.
/// Returns `None` if shutdown fires before the address is ready.
///
/// Each connect attempt races against the shutdown token so that a
/// cancellation during an OS-level TCP timeout is not delayed.
///
/// `pub(crate)` so the [`crate::tap`] module can reuse the same backoff
/// schedule when waiting for the inner plugin to bind.
pub(crate) async fn poll_ready(addr: SocketAddr, shutdown: CancellationToken) -> Option<SocketAddr> {
    let mut delay = Duration::from_millis(10);
    let max_delay = Duration::from_secs(1);

    loop {
        tokio::select! {
            result = tokio::net::TcpStream::connect(addr) => {
                if result.is_ok() {
                    return Some(addr);
                }
            }
            () = shutdown.cancelled() => return None,
        }

        tokio::select! {
            () = tokio::time::sleep(delay) => {
                delay = (delay * 2).min(max_delay);
            }
            () = shutdown.cancelled() => return None,
        }
    }
}

#[cfg(all(test, windows))]
pub(crate) mod test_hook {
    use std::cell::RefCell;

    type HookFn = Box<dyn FnMut(u16)>;

    thread_local! {
        static HOOK: RefCell<Option<HookFn>> = const { RefCell::new(None) };
    }

    pub(crate) struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            HOOK.with(|h| *h.borrow_mut() = None);
        }
    }

    /// Install a callback that fires between `drop(listener)` and the rebind
    /// inside `allocate_one_port`. Only valid when the caller of
    /// `allocate_ports` runs synchronously on the same thread that called
    /// `set`. Do NOT use this hook with `ChainRunner::run` on a
    /// multi-threaded tokio runtime — `allocate_ports` would then fire on a
    /// worker thread with an empty `HOOK` and the injection is silently
    /// skipped.
    pub(crate) fn set<F: FnMut(u16) + 'static>(f: F) -> Guard {
        HOOK.with(|h| {
            assert!(
                h.borrow().is_none(),
                "test_hook::set called with a hook already installed"
            );
            *h.borrow_mut() = Some(Box::new(f));
        });
        Guard
    }

    pub(crate) fn fire(port: u16) {
        HOOK.with(|h| {
            if let Some(cb) = h.borrow_mut().as_mut() {
                cb(port);
            }
        });
    }
}
