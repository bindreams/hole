use std::net::SocketAddr;
use std::time::Duration;

use contracts::debug_requires;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::plugin::ChainPlugin;
use crate::shutdown;

const MAX_PORT_RETRIES: usize = 3;

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
    ready_tx: Option<oneshot::Sender<SocketAddr>>,
    external_cancel: Option<CancellationToken>,
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

    /// Register a oneshot that fires when the first plugin in the chain is
    /// confirmed listening on its local address.
    ///
    /// Readiness is detected via a TCP connect probe, which means the plugin
    /// will briefly accept and then see a connection reset. The probe has no
    /// overall timeout — callers should apply their own timeout on the receiver.
    ///
    /// If the plugin exits before becoming ready, `tx` is dropped and the
    /// receiver gets `RecvError`.
    pub fn on_ready(mut self, tx: oneshot::Sender<SocketAddr>) -> Self {
        self.ready_tx = Some(tx);
        self
    }

    /// Set an external cancellation token. When cancelled, the runner
    /// gracefully stops all plugins (SIP003u shutdown sequence).
    pub fn cancel_token(mut self, token: CancellationToken) -> Self {
        self.external_cancel = Some(token);
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

        // Shared shutdown token
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

        // Spawn all plugins
        let mut set = tokio::task::JoinSet::new();
        for (i, plugin) in self.plugins.into_iter().enumerate() {
            let local = addrs[i];
            let remote = addrs[i + 1];
            let token = shutdown.child_token();
            let plugin_name = plugin.name().to_string();

            let span = tracing::info_span!("plugin", name = %plugin_name, position = i);
            set.spawn(async move {
                let result = plugin.run(local, remote, token).instrument(span).await;
                (plugin_name, result)
            });
        }

        // Readiness polling: probe the outermost local address until it accepts.
        if let Some(ready_tx) = self.ready_tx {
            let local_addr = addrs[0];
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                if let Some(addr) = poll_ready(local_addr, shutdown).await {
                    let _ = ready_tx.send(addr);
                }
                // If poll_ready returns None (shutdown before ready), ready_tx
                // is dropped and the receiver gets RecvError.
            });
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

/// Shared handler for a single plugin-task exit result. Updates
/// `first_error` on a first-write-wins basis and fires `shutdown` so the
/// rest of the chain stops. Called from both Phase 1 and Phase 2 of
/// `ChainRunner::run`.
fn record_exit(
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
            tracing::error!(plugin = %name, error = %e, "exited with error");
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
async fn poll_ready(addr: SocketAddr, shutdown: CancellationToken) -> Option<SocketAddr> {
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
