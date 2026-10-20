use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cosca::containment::Containment;
use cosca::tokio::Command;
use cosca::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::chain::Mode;
use crate::plugin::ChainPlugin;
use crate::sitrep::{PluginReady, StartError};

/// How a [`BinaryPlugin`] learns it is ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadinessMode {
    /// Parse the child's stdout for a sitrep `hello`/`ready` handshake.
    /// Use for plugins known to speak sitrep (ex-ray, galoshes-embedded).
    ExpectSitrep,
    /// Self-probe `local` with a TCP connect, retried with backoff until it accepts.
    /// The conservative default for arbitrary / legacy plugins.
    #[default]
    Probe,
    /// Infer the strategy from the plugin's own sitrep `hello`, with NO timeout.
    /// Runs the sitrep stdout reader AND an unconditional concurrent self-probe
    /// (like [`ReadinessMode::Probe`]) sharing one send-once sender. A SUPPORTED
    /// `hello` stands the probe down (cancels a `probe_standdown` child token) so
    /// the plugin's richer `ready` (authoritative transports + the `bind_conflict`
    /// retry signal) is the readiness source; a plugin that emits no `hello` (a
    /// non-sitrep plugin, including one that is silent on stdout) is readied by
    /// the probe. `probe_standdown` is a child of `shutdown`, so chain shutdown
    /// also stops the probe.
    ///
    /// Use for harnesses that mix sitrep and non-sitrep plugins (the plugin-e2e
    /// server fixture: ex-ray/galoshes speak sitrep, stock v2ray-plugin does not).
    /// The probe connects to whatever listens on `local`, so on a bind conflict it
    /// wins whenever another process holds the port and the plugin's `hello` has not
    /// yet stood it down: it reports ready for the other process's listener and the
    /// plugin's `BindConflict` is lost. Only when nothing listens on the port can
    /// the probe not win. On success either path may win; both report the same
    /// listen address, so the sitrep-preference (better transports) is best-effort,
    /// not guaranteed. Prefer explicit `ExpectSitrep` when the plugin is known to
    /// speak sitrep AND authoritative transports or a deterministic `BindConflict`
    /// matter (the bridge does).
    ///
    /// The concurrent probe is a TCP connect (as in `Probe`), so it cannot ready
    /// a UDP-only listener; a UDP-only plugin must therefore speak sitrep. All
    /// first-party UDP plugins (ex-ray/galoshes QUIC) do, so this is not a
    /// limitation in practice.
    Auto,
}

/// Resolved SIP003 environment-variable mapping for a `BinaryPlugin`'s
/// child process. The plugin's `(local, remote)` from
/// [`ChainPlugin::run`] is mapped here per the SIP003 spec: in client
/// mode `local → SS_LOCAL_*` and `remote → SS_REMOTE_*`; in server mode
/// the pair is swapped so the binary's own server-mode address swap
/// (v2ray-plugin `parseEnv`, etc.) restores the chain's intended
/// direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sip003Env {
    pub ss_local_host: String,
    pub ss_local_port: u16,
    pub ss_remote_host: String,
    pub ss_remote_port: u16,
}

/// Callback invoked synchronously when a binary plugin process is spawned.
/// Receives the child PID immediately after `Command::spawn()` returns,
/// before any `.await` point. Consumers use this to record PIDs for crash
/// recovery (e.g. persist to a state file).
pub type PidSink = Arc<dyn Fn(u32) + Send + Sync>;

/// Sink for a plugin's raw log lines, mirroring [`PidSink`]. Invoked for EVERY
/// line the child writes to stdout or stderr — including lines the sitrep
/// reader goes on to parse as protocol events — before any interpretation.
/// Lines are unparsed and unclassified, except that any ANSI SGR (color)
/// escape sequences are already stripped (see `ansi::strip_sgr`) — the
/// sink never sees what `sitrep::parse_event` sees, which is the untouched
/// original.
pub type LogSink = Arc<dyn Fn(&str) + Send + Sync>;

/// A plugin backed by an external SIP003u binary.
///
/// In the sitrep readiness modes a start failure the plugin reports, or closing its sitrep stream before `ready`,
/// takes the plugin down and makes [`run`](ChainPlugin::run) return an error however the plugin then ends, even with
/// exit status 0. The failure itself reaches the chain's readiness channel once the plugin's output has been drained.
/// A stdout close that a shutdown's take-down of a live, unready plugin causes is not a start failure; a close the
/// reader saw first, or from a plugin whose root had already exited, stays one even if a shutdown was requested.
pub struct BinaryPlugin {
    path: PathBuf,
    options: Option<String>,
    name: String,
    pid_sink: Option<PidSink>,
    log_sink: Option<LogSink>,
    readiness: ReadinessMode,
    extra_env: Vec<(String, String)>,
}

impl BinaryPlugin {
    pub fn new(path: impl Into<PathBuf>, options: Option<&str>) -> Self {
        let path = path.into();
        let name = extract_name(&path);
        Self {
            path,
            options: options.map(String::from),
            name,
            pid_sink: None,
            log_sink: None,
            readiness: ReadinessMode::default(),
            extra_env: Vec::new(),
        }
    }

    /// Set a callback that fires with the child PID immediately after spawn.
    pub fn pid_sink(mut self, sink: PidSink) -> Self {
        self.pid_sink = Some(sink);
        self
    }

    /// Also deliver every line the child writes to `sink` — see [`LogSink`].
    pub fn log_sink(mut self, sink: LogSink) -> Self {
        self.log_sink = Some(sink);
        self
    }

    /// Inject an additional environment variable into the spawned child
    /// process. Primarily for tests (fault injection); production plugins
    /// are configured via `SS_PLUGIN_OPTIONS`.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_env.push((key.into(), value.into()));
        self
    }

    /// Select how this plugin learns it is ready. Defaults to
    /// [`ReadinessMode::Probe`].
    pub fn readiness(mut self, mode: ReadinessMode) -> Self {
        self.readiness = mode;
        self
    }

    #[cfg(test)]
    pub(crate) fn readiness_mode_for_test(&self) -> ReadinessMode {
        self.readiness
    }

    /// Compute the SIP003 env-var mapping for `(local, remote)`. Public
    /// to `crate` for testability; production callers use [`Self::run`]
    /// which feeds this into `Command::env`. See [`Sip003Env`] for the
    /// client/server semantics.
    pub(crate) fn sip003_env(&self, local: SocketAddr, remote: SocketAddr) -> crate::Result<Sip003Env> {
        // In server mode the binary itself swaps SS_LOCAL/SS_REMOTE
        // semantics (SS_REMOTE = inbound listener, SS_LOCAL = outbound
        // dial). We swap here first so the binary's swap restores the
        // direction we wanted.
        let (ss_local, ss_remote) = match Mode::from_plugin_options(self.options.as_deref())? {
            Mode::Client => (local, remote),
            Mode::Server => (remote, local),
        };
        Ok(Sip003Env {
            ss_local_host: ss_local.ip().to_string(),
            ss_local_port: ss_local.port(),
            ss_remote_host: ss_remote.ip().to_string(),
            ss_remote_port: ss_remote.port(),
        })
    }
}

/// Environment variables always injected into a binary plugin's child
/// process, independent of SIP003 config. `GOTRACEBACK=crash` makes a Go
/// plugin (ex-ray) dump full goroutine state to stderr on a native fault
/// (the bridge relays that stderr through tracing). Harmless to Rust
/// plugins, which ignore it. See bindreams/hole#438. `NO_COLOR=1` /
/// `CLICOLOR=0` strip ANSI a plugin child's logger may write to stderr —
/// `tracing-subscriber` (galoshes) already honors `NO_COLOR`; ex-ray never
/// colors, so both are a no-op there.
pub(crate) fn fixed_plugin_env() -> &'static [(&'static str, &'static str)] {
    &[("GOTRACEBACK", "crash"), ("NO_COLOR", "1"), ("CLICOLOR", "0")]
}

fn extract_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
}

/// The single choke point every stdout/stderr reader in [`BinaryPlugin::run`]
/// and [`spawn_sitrep_stdout_reader`] goes through before a line reaches a
/// [`LogSink`]: strip ANSI SGR escapes once, feed the result to `sink` (if
/// any), and return it so the caller's own tracing macro — level and
/// conditionality differ per reader, so that stays inline at each call site
/// — relays the same ANSI-clean text. A reader that reaches `sink` any other
/// way bypasses this guarantee; there is currently no such path.
fn relay_to_sink<'a>(line: &'a str, sink: &Option<LogSink>) -> Cow<'a, str> {
    let clean = crate::ansi::strip_sgr(line);
    if let Some(sink) = sink {
        sink(&clean);
    }
    clean
}

#[async_trait::async_trait]
impl ChainPlugin for BinaryPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(
        self: Box<Self>,
        local: SocketAddr,
        remote: SocketAddr,
        shutdown: CancellationToken,
        ready: oneshot::Sender<Result<PluginReady, StartError>>,
    ) -> crate::Result<()> {
        let env = self.sip003_env(local, remote)?;
        // A bare name reaches here only if the caller's resolution left one.
        #[allow(clippy::disallowed_methods)]
        let mut cmd = Command::new();
        #[allow(clippy::disallowed_methods)]
        cmd.executable(&self.path);
        // argv[0]: `executable()` only OVERRIDES which file is loaded; the argv is
        // still what names the program, and a command with none is refused.
        #[allow(clippy::disallowed_methods)]
        cmd.arg(&self.path);
        cmd.env("SS_LOCAL_HOST", env.ss_local_host);
        cmd.env("SS_LOCAL_PORT", env.ss_local_port.to_string());
        cmd.env("SS_REMOTE_HOST", env.ss_remote_host);
        cmd.env("SS_REMOTE_PORT", env.ss_remote_port.to_string());
        if let Some(ref opts) = self.options {
            cmd.env("SS_PLUGIN_OPTIONS", opts);
        }
        for (k, v) in fixed_plugin_env() {
            cmd.env(k, v);
        }
        for (k, v) in &self.extra_env {
            cmd.env(k, v);
        }
        cmd.stdout(Stdio::pipe())?;
        cmd.stderr(Stdio::pipe())?;
        cmd.kill_on_drop(true);

        // Spawn as the root of a contained process tree (Windows job object /
        // Linux cgroup / Unix process group), with stdio handle hygiene, so a
        // force-kill reaps the plugin's whole descendant tree and an orphaned
        // grandchild can never hold the host's pipe handles (bindreams/hole#197).
        // Containment is also what gives the child its own console process group
        // on Windows, which is what `terminate`'s CTRL_BREAK addresses.
        // `Nesting::Mark` keeps the root-only group rule: a nested garter (e.g.
        // galoshes inside the bridge's chain) joins this tree instead of creating
        // one Unix pgids could escape from.
        //
        // Only ONE marker name is recognised. The ancestor and the descendant
        // must therefore agree on it, and within hole they always do: galoshes
        // takes garter by path, so a galoshes binary and the garter inside it are
        // always the same commit, and hole's release builds galoshes from its own
        // checkout and resolves plugins to the sidecar beside its executable. The
        // pairing that can skew is a separately-released `garter-bin` driving a
        // separately-released `galoshes` — mixed pre-1.0 binaries, which this
        // project does not support and does not bridge.
        cmd.contain();
        cmd.nesting(cosca::containment::Nesting::Mark);
        let mut child = cmd
            .spawn()
            .map_err(|e| crate::Error::Chain(format!("failed to spawn '{}': {e}", self.path.display())))?;

        if let Some(sink) = &self.pid_sink {
            sink(child.id().pid());
        }

        let stderr = child.stderr().expect("stderr was piped");
        let plugin_name = self.name.clone();
        let log_sink = self.log_sink.clone();
        let stderr_task = tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        let line = relay_to_sink(&line, &log_sink);
                        tracing::warn!(plugin = %plugin_name, "{line}");
                    }
                    Ok(None) => break, // EOF
                    Err(e) => {
                        tracing::debug!(plugin = %plugin_name, "log reader error: {e}");
                        break;
                    }
                }
            }
        });

        // Stdout consumer: in Probe mode it forwards lines to tracing and
        // readiness comes from a separate self-probe task; in ExpectSitrep
        // mode it parses sitrep events and IS the readiness source. Build
        // the right one per `self.readiness`.
        let stdout = child.stdout().expect("stdout was piped");
        let probes = ReadinessProbes::new(&self.name, &shutdown);
        let (stdout_task, failure) = match self.readiness {
            ReadinessMode::Probe => {
                // Tier-2: the stdout reader is a pure log passthrough; a
                // separate self-probe task owns readiness.
                let plugin_name = self.name.clone();
                let log_sink = self.log_sink.clone();
                let log_task = tokio::spawn(async move {
                    let reader = BufReader::new(stdout);
                    let mut lines = reader.lines();
                    loop {
                        match lines.next_line().await {
                            Ok(Some(line)) => {
                                let line = relay_to_sink(&line, &log_sink);
                                tracing::info!(plugin = %plugin_name, "{line}");
                            }
                            Ok(None) => break, // EOF
                            Err(e) => {
                                tracing::debug!(plugin = %plugin_name, "log reader error: {e}");
                                break;
                            }
                        }
                    }
                });

                // Self-probe readiness. On a successful connect, report TCP
                // readiness; once stopped (the chain's shutdown, or the plugin's end), drop
                // `ready` unsent.
                let probe_local = local;
                let probe_stop = probes.token();
                probes.spawn(async move {
                    if let Some(addr) = crate::chain::poll_ready(probe_local, probe_stop).await {
                        let _ = ready.send(Ok(PluginReady {
                            listen: addr,
                            transports: crate::sitrep::Transports::TCP,
                        }));
                    }
                });

                (log_task, None)
            }
            ReadinessMode::ExpectSitrep => {
                let (task, failure) = spawn_sitrep_stdout_reader(
                    stdout,
                    local,
                    shutdown.clone(),
                    ready,
                    false,
                    self.log_sink.clone(),
                    &probes,
                );
                (task, Some(failure))
            }
            ReadinessMode::Auto => {
                let (task, failure) = spawn_sitrep_stdout_reader(
                    stdout,
                    local,
                    shutdown.clone(),
                    ready,
                    true,
                    self.log_sink.clone(),
                    &probes,
                );
                (task, Some(failure))
            }
        };

        // If the child binds but never readies and is then shut down, the readiness sender is dropped
        // unsent and the aggregator synthesizes `Fatal{exited before ready}`.
        let supervised = supervise_plugin(
            &self.name,
            &mut child,
            &shutdown,
            SHUTDOWN_GRACE,
            stdout_task,
            stderr_task,
            failure,
        )
        .await;
        // A probe holds the readiness sender while it polls. It ends here, before `run` returns, so a plugin that
        // exits before ready is seen by the chain as one that dropped its sender.
        probes.end().await;
        supervised?.outcome(&self.name)
    }
}

/// The single readiness sender, shared between the sitrep stdout reader
/// and (only on a [`ProtocolSupport::FallBackToTier2`] handoff) a
/// self-probe task. Wrapping in `Arc<Mutex<Option<..>>>` keeps the
/// "send AT MOST once" invariant while letting either owner make the
/// attempt: whichever runs first `take()`s the sender; the other finds
/// `None` and does nothing.
///
/// [`ProtocolSupport::FallBackToTier2`]: crate::sitrep::ProtocolSupport::FallBackToTier2
type SharedReady = Arc<tokio::sync::Mutex<Option<oneshot::Sender<Result<PluginReady, StartError>>>>>;

/// A plugin's self-probes: the tasks that connect to its `local` until it accepts. A probe holds the plugin's
/// readiness sender while it polls, so the plugin's `run` must [`end`](Self::end) them before it returns: the chain
/// reads a sender that is gone as a plugin that exited before ready.
#[derive(Clone)]
pub(crate) struct ReadinessProbes {
    plugin: Arc<str>,
    /// A child of the chain's shutdown, cancelled by [`end`](Self::end).
    stop: CancellationToken,
    tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl ReadinessProbes {
    pub(crate) fn new(plugin: &str, shutdown: &CancellationToken) -> Self {
        Self {
            plugin: plugin.into(),
            stop: shutdown.child_token(),
            tasks: Arc::default(),
        }
    }

    /// A token that ends one probe: when it is cancelled, when the probes end, or on the chain's shutdown.
    pub(crate) fn token(&self) -> CancellationToken {
        self.stop.child_token()
    }

    /// Starts a probe, unless the probes have ended already.
    pub(crate) fn spawn(&self, probe: impl std::future::Future<Output = ()> + Send + 'static) {
        let mut tasks = self.tasks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.stop.is_cancelled() {
            tasks.push(tokio::spawn(probe));
        }
    }

    /// Stops every probe and waits for them to end. Once it returns no probe holds the readiness sender, and none
    /// starts later.
    pub(crate) async fn end(&self) {
        let tasks = {
            let mut tasks = self.tasks.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            self.stop.cancel();
            std::mem::take(&mut *tasks)
        };
        for probe in tasks {
            if let Err(e) = probe.await {
                tracing::warn!(plugin = %self.plugin, "a readiness probe did not end normally: {e}");
            }
        }
    }
}

/// Spawn a tier-2 self-probe that, on a successful TCP connect to `local`,
/// reports `PluginReady` (TCP-only) through the shared send-once sender.
/// Shared by `ExpectSitrep`'s unknown-major fallback and `Auto`'s concurrent
/// probe. `standdown` ends the probe early (without sending) when cancelled.
fn spawn_shared_probe(local: SocketAddr, standdown: CancellationToken, shared: SharedReady, probes: &ReadinessProbes) {
    probes.spawn(async move {
        if let Some(addr) = crate::chain::poll_ready(local, standdown).await {
            if let Some(tx) = shared.lock().await.take() {
                let _ = tx.send(Ok(PluginReady {
                    listen: addr,
                    transports: crate::sitrep::Transports::TCP,
                }));
            }
        }
    });
}

/// A start failure the sitrep reader has decided on, held until the plugin's output is drained.
struct HeldFailure {
    ready: oneshot::Sender<Result<PluginReady, StartError>>,
    error: StartError,
}

/// The reader's side of a held failure: `ready` moves here, unsent, and `failed` is cancelled so the
/// plugin is taken down. Returns the error back, changing nothing, once readiness is decided (a `ready`, or an
/// earlier failure).
///
/// A hold that is already gone (the supervision ended, or its future was dropped) leaves nobody to
/// deliver the failure later, so it is sent at once: a decided failure is never dropped.
async fn try_hold_failure(
    shared: &SharedReady,
    held: &mut Option<oneshot::Sender<HeldFailure>>,
    failed: &CancellationToken,
    error: StartError,
) -> Result<(), StartError> {
    let Some(ready) = shared.lock().await.take() else {
        return Err(error);
    };
    let failure = HeldFailure { ready, error };
    let undelivered = match held.take() {
        Some(held) => held.send(failure).err(),
        None => Some(failure),
    };
    if let Some(HeldFailure { ready, error }) = undelivered {
        let _ = ready.send(Err(error));
    }
    failed.cancel();
    Ok(())
}

/// [`try_hold_failure`] for a failure the plugin itself reported. One it cannot act on, because readiness was
/// already decided, is logged naming the plugin: at warn when a `ready` decided it, at debug after an earlier failure.
async fn hold_reported_failure(
    plugin: &str,
    shared: &SharedReady,
    held: &mut Option<oneshot::Sender<HeldFailure>>,
    failed: &CancellationToken,
    error: StartError,
) {
    let Err(error) = try_hold_failure(shared, held, failed, error).await else {
        return;
    };
    // `held` is gone once a failure was held; it is still there if a `ready` took the sender.
    match held {
        Some(_) => tracing::warn!(
            plugin = %plugin,
            "the plugin reported a start failure after its readiness was already decided; ignored: {error}"
        ),
        None => tracing::debug!(
            plugin = %plugin,
            "the plugin reported another start failure after its readiness was already decided; ignored: {error}"
        ),
    }
}

/// Where a sitrep reader's start failure waits for the plugin's output. The failure is sent only when the
/// hold ends ([`FailureHold::deliver`], or its drop when the supervision is aborted or unwinds), so a
/// caller that learns of it has already seen everything the plugin wrote before.
pub(crate) struct FailureHold {
    held: oneshot::Receiver<HeldFailure>,
    /// Cancelled once the reader has decided the start failed. A child of the chain's shutdown token.
    failed: CancellationToken,
    /// Set when the supervision takes the plugin down on a chain shutdown, before it sends the plugin anything.
    /// The reader reads it to tell a stdout closed by that take-down from one the plugin closed itself.
    taken_down: Arc<AtomicBool>,
}

impl FailureHold {
    /// Resolves once the reader has decided the start failed.
    pub(crate) async fn failed(&self) {
        self.failed.cancelled().await;
    }

    /// Records that this plugin is being taken down on a shutdown. Call it before anything is sent to the plugin: a
    /// stdout closed after that is the take-down's doing, one closed before it is not.
    fn mark_taken_down(&self) {
        self.taken_down.store(true, Ordering::SeqCst);
    }

    /// The signal [`mark_taken_down`](Self::mark_taken_down) raises, for a test to watch from a fake tree.
    #[cfg(test)]
    pub(crate) fn taken_down_signal(&self) -> Arc<AtomicBool> {
        self.taken_down.clone()
    }

    /// Sends the failure the reader held, if it held one, on the plugin's readiness channel, and
    /// returns whether it did. Call it once the plugin's output readers have finished or been given up
    /// on.
    pub(crate) fn deliver(mut self) -> bool {
        self.finish()
    }

    /// Closes the hold, then sends what reached it first: a reader deciding later finds the hold closed
    /// and sends its own failure (see [`try_hold_failure`]), so every decided failure is sent exactly once.
    pub(crate) fn finish(&mut self) -> bool {
        self.held.close();
        let Ok(HeldFailure { ready, error }) = self.held.try_recv() else {
            return false;
        };
        let _ = ready.send(Err(error));
        true
    }
}

impl Drop for FailureHold {
    /// A supervision that is aborted or unwinds still reports the failure its reader decided.
    fn drop(&mut self) {
        self.finish();
    }
}

/// Spawn the sitrep stdout reader.
///
/// The reader parses `@sitrep` events and decides exactly one readiness result. On an unknown protocol
/// major (`FallBackToTier2`) it hands readiness to a self-probe, sharing the single sender via
/// [`SharedReady`] so at most one send ever happens. When `auto` is true ([`ReadinessMode::Auto`]) a
/// concurrent self-probe is ALSO started up front and stood down on a supported `hello`, so a non-sitrep
/// plugin (including one silent on stdout) is still readied by the probe. Non-event lines pass through
/// to tracing as logs.
///
/// A `ready` is sent at once. A failure (`fatal`, `bind_conflict`, an empty `ready`, or stdout closing
/// where no probe owns readiness: a sitrep plugin's readiness travels on stdout, so it can never become
/// ready) is not: it is held in the returned [`FailureHold`], which [`supervise_plugin`] takes the plugin
/// down for, drains its output, and only then delivers. Once a shutdown starts taking a live plugin down,
/// a stdout close the reader has not yet seen is the take-down's and no failure, whoever closed it: nothing
/// orders the close against the take-down, and the caller asked for the shutdown. A failure the reader
/// decided first, or a plugin whose root had already exited, keeps its failure. Either way the output is
/// relayed. The reader keeps relaying lines until stdout closes. The probes it starts are `probes`, which end with
/// `shutdown` or when the plugin's `run` ends them; the reader logs under their plugin's name.
pub(crate) fn spawn_sitrep_stdout_reader(
    stdout: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    local: SocketAddr,
    shutdown: CancellationToken,
    ready: oneshot::Sender<Result<PluginReady, StartError>>,
    auto: bool,
    log_sink: Option<LogSink>,
    probes: &ReadinessProbes,
) -> (tokio::task::JoinHandle<()>, FailureHold) {
    use crate::sitrep::{ProtocolSupport, SitrepEvent};

    let shared: SharedReady = Arc::new(tokio::sync::Mutex::new(Some(ready)));
    let (held_tx, held_rx) = oneshot::channel();
    let failed = shutdown.child_token();
    let taken_down = Arc::new(AtomicBool::new(false));
    let hold = FailureHold {
        held: held_rx,
        failed: failed.clone(),
        taken_down: taken_down.clone(),
    };
    let probes = probes.clone();
    let plugin_name = probes.plugin.to_string();
    let task = tokio::spawn(async move {
        let mut held = Some(held_tx);
        // Auto: run the self-probe concurrently from the start (mirrors the
        // default `Probe` mode), sharing the send-once sender. A SUPPORTED
        // `hello` cancels `probe_standdown` so the probe defers to sitrep;
        // otherwise the probe readies the plugin (handles a non-sitrep plugin
        // that is silent on stdout — there is no first line to classify on).
        // `probe_standdown` is a child of the probes' token, so the chain's shutdown and the plugin's end stop it.
        let probe_standdown = probes.token();
        if auto {
            spawn_shared_probe(local, probe_standdown.clone(), shared.clone(), &probes);
        }
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut handshake_ok = false;
        // Whether a probe, not this reader, is what readies the plugin.
        let mut probe_owns_readiness = auto;
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    // Sink BEFORE parsing: the arms below consume lines that
                    // would otherwise never reach a consumer — a post-ready
                    // `fatal` finds the readiness one-shot already taken and
                    // falls through with no relay at all. `relay_to_sink`
                    // gives the sink the ANSI-stripped display copy;
                    // `parse_event` below gets the untouched original —
                    // never strip ahead of the parser (see `ansi` module
                    // doc for why).
                    let clean_line = relay_to_sink(&line, &log_sink);
                    match crate::sitrep::parse_event(&line) {
                        Ok(Some(SitrepEvent::Hello { protocol })) => {
                            match crate::sitrep::protocol_support(&protocol) {
                                ProtocolSupport::Supported => {
                                    handshake_ok = true;
                                    probe_owns_readiness = false;
                                    // Auto: a real sitrep plugin — stand the probe
                                    // down so its richer `ready` wins. (No-op when
                                    // !auto: no probe was started with this token.)
                                    probe_standdown.cancel();
                                    tracing::debug!(plugin = %plugin_name, %protocol, "sitrep handshake");
                                }
                                ProtocolSupport::FallBackToTier2 => {
                                    tracing::info!(
                                        plugin = %plugin_name,
                                        %protocol,
                                        "unknown sitrep protocol major; readiness falls back to probe"
                                    );
                                    // Hand readiness to a tier-2 self-probe, sharing
                                    // the single sender. In Auto the probe is already
                                    // running (do NOT cancel its standdown — unknown
                                    // major means the probe drives); in ExpectSitrep
                                    // start it now. The reader continues only as a log
                                    // passthrough (it never sends readiness again).
                                    if !auto {
                                        spawn_shared_probe(local, probes.token(), shared.clone(), &probes);
                                    }
                                    probe_owns_readiness = true;
                                    // Drain the rest of stdout as logs so the
                                    // child's pipe never blocks; the probe task
                                    // owns readiness from here on.
                                    drain_remaining_logs(&mut lines, &plugin_name, &log_sink).await;
                                    break;
                                }
                            }
                        }
                        Ok(Some(SitrepEvent::Ready { listen, transports })) if handshake_ok => {
                            // Empty/all-unknown transports is illegal per
                            // SITREP: a `ready` MUST list >=1 served
                            // transport. Reject as Fatal.
                            if transports.is_empty() {
                                let error = StartError::Fatal {
                                    detail: "sitrep ready reported empty transports (protocol violation)".into(),
                                    errno: None,
                                };
                                hold_reported_failure(&plugin_name, &shared, &mut held, &failed, error).await;
                            } else if let Some(tx) = shared.lock().await.take() {
                                let _ = tx.send(Ok(PluginReady { listen, transports }));
                            }
                        }
                        Ok(Some(SitrepEvent::BindConflict { errno, addr })) if handshake_ok => {
                            hold_reported_failure(
                                &plugin_name,
                                &shared,
                                &mut held,
                                &failed,
                                StartError::BindConflict { errno, addr },
                            )
                            .await;
                        }
                        Ok(Some(SitrepEvent::Fatal { detail, errno })) if handshake_ok => {
                            hold_reported_failure(
                                &plugin_name,
                                &shared,
                                &mut held,
                                &failed,
                                StartError::Fatal { detail, errno },
                            )
                            .await;
                        }
                        // log line / pre-handshake / unknown event → passthrough
                        _ => tracing::info!(plugin = %plugin_name, "{clean_line}"),
                    }
                }
                Ok(None) => break, // EOF
                Err(e) => {
                    tracing::debug!(plugin = %plugin_name, "log reader error: {e}");
                    break;
                }
            }
        }
        // Stdout is closed. Where this reader is the only readiness source, nothing can ready the
        // plugin any more; a probe that owns readiness decides for itself. A stdout that closes because
        // the plugin was taken down is the take-down's doing, not a start failure; one the plugin closed
        // by itself is, whatever the chain's token says by now.
        if !probe_owns_readiness && !taken_down.load(Ordering::SeqCst) {
            let error = StartError::Fatal {
                detail: "plugin closed its sitrep stream before becoming ready".into(),
                errno: None,
            };
            // Readiness already decided: the close is no event the plugin reported, so nothing is logged.
            let _ = try_hold_failure(&shared, &mut held, &failed, error).await;
        }
    });
    (task, hold)
}

/// Forward all remaining stdout lines to tracing as ordinary logs. Used
/// after a `FallBackToTier2` handoff so the child's stdout pipe never
/// blocks while the self-probe owns readiness.
///
/// The loop is unbounded by design and terminates on the **child's** stdout
/// EOF, which `run` waits for (bounded) once the child's tree is killed or the
/// child is dropped (`kill_on_drop`). This reads the child's pipe,
/// not the host's, so it cannot reproduce the #197 runtime-drop hang (that was
/// an orphan holding the *host's* stdio); and because it runs inside a detached
/// `tokio::spawn`, runtime drop aborts it at the await point rather than
/// blocking on it.
async fn drain_remaining_logs(
    lines: &mut tokio::io::Lines<BufReader<impl tokio::io::AsyncRead + Unpin>>,
    plugin_name: &str,
    log_sink: &Option<LogSink>,
) {
    while let Ok(Some(line)) = lines.next_line().await {
        let line = relay_to_sink(&line, log_sink);
        tracing::info!(plugin = %plugin_name, "{line}");
    }
}

// Post-exit reader wait ===============================================================================================

/// Failure bound on the wait for the plugin's output to reach EOF once its tree is gone. Expiry is
/// not taken as proof that the output is complete: it is surfaced as a warning and the readers are
/// aborted.
pub(crate) const READER_EOF_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether the tree's own exit edge proves every member gone. True only where the kernel owns the
/// membership: a live process cannot leave a Windows job object or a cgroup. The macOS fd marker
/// has an edge too, but a live process can close its copy of the marker and stay up. Every other
/// mechanism has no edge. One arm per mechanism; `Containment` is `#[non_exhaustive]`, so a mechanism
/// cosca adds later is unproven until named here.
fn exit_edge_proves_the_tree_gone(containment: Containment) -> bool {
    match containment {
        Containment::CgroupV2 => true,
        Containment::JobObject => true,
        Containment::ProcessGroup => false,
        Containment::Session => false,
        Containment::FdMarker => false,
        Containment::TreeWalk => false,
        Containment::Delegated => false,
        Containment::None => false,
        _ => false,
    }
}

/// Whether `kill_tree` finds the tree through an id the root's reap releases, so that after the
/// reap the OS may have recycled it onto an unrelated process. cosca's `ProcessGroup` and `Session`
/// are `killpg` of the root's pgid, a macOS `FdMarker` fires `killpg` on its pgid, and `TreeWalk`
/// enumerates descendants from the root's pid. A mechanism cosca adds later is assumed to, until
/// named here. A kernel container (`CgroupV2`, `JobObject`) is its own object and outlives the reap.
fn kill_tree_addresses_a_releasable_id(containment: Containment) -> bool {
    match containment {
        Containment::CgroupV2 => false,
        Containment::JobObject => false,
        Containment::ProcessGroup => true,
        Containment::Session => true,
        Containment::FdMarker => true,
        Containment::TreeWalk => true,
        Containment::Delegated => false,
        Containment::None => false,
        _ => true,
    }
}

/// The plugin's process, as the teardown acts on it. `cosca`'s child implements it; a test
/// substitutes a recorder.
pub(crate) trait PluginTree {
    fn containment(&self) -> Containment;
    /// Resolves once the root has exited, without reaping it: until `reap`, its pid (and with it a
    /// process group id) stays ours and cannot be recycled onto an unrelated process.
    async fn wait_root_exit(&self) -> Result<(), cosca::error::Error>;
    /// [`wait_root_exit`](Self::wait_root_exit) for at most `grace`: `Ok(false)` if the root is still running.
    async fn wait_root_exit_within(&self, grace: std::time::Duration) -> Result<bool, cosca::error::Error>;
    /// Asks the root to exit (a cooperative signal). Does not wait.
    fn terminate(&self) -> Result<(), cosca::error::Error>;
    /// Hard-kills the root alone. Does not wait.
    fn kill_root(&mut self) -> Result<(), cosca::error::Error>;
    fn kill_tree(&mut self) -> Result<(), cosca::error::Error>;
    /// Resolves once every member of the tree has exited. Not every containment can say so.
    async fn wait_tree_drained(&self) -> Result<(), cosca::error::Error>;
    /// Collects the root's exit status.
    async fn reap(&mut self) -> Result<std::process::ExitStatus, cosca::error::Error>;
    /// Called once the root is reaped. Dropping the handle must not then signal a process group id
    /// that may now name an unrelated group.
    fn disarm(&mut self);
}

/// The exit watch for a root cosca cannot watch (on Linux, `pidfd_open` is missing before 5.3 or denied by a seccomp
/// profile): `waitid(WNOWAIT)` where that exists, and `pidfd_error` otherwise. Either way the root stays unreaped.
#[cfg(target_os = "linux")]
async fn watch_exit_without_pidfd(pid: u32, pidfd_error: cosca::error::Error) -> Result<(), cosca::error::Error> {
    tracing::debug!("the pidfd exit watch is unavailable ({pidfd_error}); watching the exit with waitid");
    crate::exit_watch::wait_exit_without_reaping(pid)
        .await
        .map_err(cosca::error::Error::Io)
}

#[cfg(not(target_os = "linux"))]
async fn watch_exit_without_pidfd(_pid: u32, pidfd_error: cosca::error::Error) -> Result<(), cosca::error::Error> {
    Err(pidfd_error)
}

/// The exit watch of the root `pid`, given what cosca's own watch answered: that answer, or, where cosca could not
/// watch, the fallback. The `Child` impl calls this, so a kernel without `pidfd_open` can be stood in for by an
/// injected answer.
pub(crate) async fn root_exit_watch(
    pid: u32,
    cosca_watch: Result<(), cosca::error::Error>,
) -> Result<(), cosca::error::Error> {
    match cosca_watch {
        Err(pidfd_error) => watch_exit_without_pidfd(pid, pidfd_error).await,
        watched => watched,
    }
}

/// [`root_exit_watch`] for at most `grace`: `Ok(false)` if the root is still running.
pub(crate) async fn root_exit_watch_within(
    pid: u32,
    grace: std::time::Duration,
    cosca_watch: Result<bool, cosca::error::Error>,
) -> Result<bool, cosca::error::Error> {
    match cosca_watch {
        Err(pidfd_error) => {
            // A zero grace is still a probe: `timeout` polls the watch before its deadline.
            match tokio::time::timeout(grace, watch_exit_without_pidfd(pid, pidfd_error)).await {
                Ok(watched) => watched.map(|()| true),
                Err(_grace_over) => Ok(false),
            }
        }
        watched => watched,
    }
}

impl PluginTree for cosca::tokio::Child {
    fn containment(&self) -> Containment {
        cosca::tokio::Child::containment(self)
    }

    async fn wait_root_exit(&self) -> Result<(), cosca::error::Error> {
        let pidfd_watch = cosca::tokio::Process::from_id(self.id()).wait().await;
        root_exit_watch(self.id().pid(), pidfd_watch).await
    }

    async fn wait_root_exit_within(&self, grace: std::time::Duration) -> Result<bool, cosca::error::Error> {
        let pidfd_watch = cosca::tokio::Process::from_id(self.id()).wait_timeout(grace).await;
        root_exit_watch_within(self.id().pid(), grace, pidfd_watch).await
    }

    fn terminate(&self) -> Result<(), cosca::error::Error> {
        cosca::tokio::Child::terminate(self)
    }

    fn kill_root(&mut self) -> Result<(), cosca::error::Error> {
        cosca::tokio::Child::kill(self)
    }

    fn kill_tree(&mut self) -> Result<(), cosca::error::Error> {
        cosca::tokio::Child::kill_tree(self)
    }

    #[cfg(not(windows))]
    async fn wait_tree_drained(&self) -> Result<(), cosca::error::Error> {
        self.wait_tree().await.map(|_| ())
    }

    // cosca 0.3's job-object `wait_tree` future is `!Send` (it holds a raw `HANDLE` across its await), and
    // `BinaryPlugin::run` must be `Send`. Until cosca's wait is `Send` (bindreams/hole#1124), every take-down on
    // Windows takes the reader-wait fallback of `drain_readers_after_exit`.
    #[cfg(windows)]
    async fn wait_tree_drained(&self) -> Result<(), cosca::error::Error> {
        Err(cosca::error::Error::Unsupported {
            op: "wait_tree".into(),
            platform: "windows",
            detail: "cosca 0.3's job-object wait_tree future is not Send".into(),
        })
    }

    async fn reap(&mut self) -> Result<std::process::ExitStatus, cosca::error::Error> {
        self.wait().await
    }

    /// cosca's `Drop` runs the tree kill before it looks at whether the root was reaped, and for a
    /// pgid mechanism that kill is a `killpg`. `detach` is the only way to skip it; it also clears a
    /// job object's kill-on-close, so it is applied only where the drop's kill would be that `killpg`.
    /// A tree kill that failed before the reap is therefore not retried by the drop.
    fn disarm(&mut self) {
        if kill_tree_addresses_a_releasable_id(self.containment()) {
            self.detach();
        }
    }
}

/// How long a plugin gets to exit on its own after being asked to, before it is killed.
const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// The two waits on external code a [`BinaryPlugin`]'s take-down is made of: its root's [`SHUTDOWN_GRACE`], then its
/// output's [`READER_EOF_BOUND`]. What waits for a plugin to stop by itself must wait at least this long.
pub(crate) const TAKEDOWN_BOUND: std::time::Duration =
    std::time::Duration::from_secs(SHUTDOWN_GRACE.as_secs() + READER_EOF_BOUND.as_secs());

/// Headroom over a [`TAKEDOWN_BOUND`] for the steps between and after its waits, which carry no bound of their own (the
/// kills, the tree's drain, the reap): they are the OS's to finish. Each bound that waits on another takes this on top
/// of the bound it waits on, so the waited-on one expires, and warns, first.
pub(crate) const TAKEDOWN_TAIL: std::time::Duration = std::time::Duration::from_secs(1);

/// How a plugin's root came to its end.
pub(crate) enum PluginEnd {
    /// The root exited, with this status: by itself, or within the grace a take-down gave it.
    Exited(std::process::ExitStatus),
    /// The root was taken down: asked to exit, or killed because it did not.
    ShutDown,
}

/// How [`supervise_plugin`] ended a plugin, and whether its start had failed.
pub(crate) struct Supervised {
    pub(crate) end: PluginEnd,
    /// The sitrep reader decided the start failed. The failure itself reaches the caller through readiness.
    pub(crate) start_failed: bool,
}

impl Supervised {
    /// The result `BinaryPlugin::run` returns, and the only place it is derived. A plugin whose start failed never
    /// ends `Ok`, however it ended: an exit status that is an error keeps naming the error, and anything else is a
    /// [`Chain`](crate::Error::Chain) error saying the start failed. This is what makes a runner that registered no
    /// `on_ready` see the chain fail.
    pub(crate) fn outcome(self, plugin: &str) -> crate::Result<()> {
        let start_failed = self.start_failed;
        let ok_unless_start_failed = |how: &str| match start_failed {
            true => Err(crate::Error::Chain(format!(
                "plugin '{plugin}' failed to start and {how}"
            ))),
            false => Ok(()),
        };
        match self.end {
            PluginEnd::ShutDown => ok_unless_start_failed("was taken down"),
            PluginEnd::Exited(status) if status.success() => ok_unless_start_failed("then exited cleanly"),
            PluginEnd::Exited(status) => match status.code() {
                Some(code) => Err(crate::Error::PluginExit {
                    name: plugin.to_owned(),
                    code,
                }),
                None => Err(crate::Error::PluginKilled {
                    name: plugin.to_owned(),
                }),
            },
        }
    }
}

/// Runs a started plugin to its end: waits for its root to exit, for `shutdown`, or for its sitrep
/// reader to decide the start failed, then ends it so that its tree is killed while the root is still
/// unreaped (see [`end_plugin`]). An exit that has already happened is reported as an exit even when a
/// take-down was requested too; a take-down ends a plugin that is still running (see [`Takedown`]).
///
/// The exit watch is non-reaping ([`root_exit_watch`]), so every take-down of a running root kills its
/// tree before the root is reaped. Only when no watch works is a root reaped first, and its tree killed only
/// where that stays safe (see [`end_reaped_plugin`]); a take-down then has no grace to give and kills the
/// root at once.
///
/// The returned [`Supervised`] says whether the start failed, which makes `run` return an error
/// however the plugin ended (see [`Supervised::outcome`]).
///
/// The readiness sender (start-gate for `on_ready`) and the exit's `Err` (lifecycle error driving
/// teardown) are two intentionally separate observers of one exit; a plugin that emits `fatal` then
/// exits nonzero fires both, and neither must be suppressed. See `run_readiness_aggregator` in
/// chain.rs for the full two-channel rationale. The start failure `failure` holds is delivered last,
/// after the plugin's output has been drained (or given up on at its bound): whoever hears of it has
/// been shown the plugin's last words. If this future is dropped or unwinds first, dropping `failure`
/// delivers it.
///
/// Once the root is reaped the handle is disarmed (see [`PluginTree::disarm`]); on an `Err` it may
/// not be, and dropping the handle then still kills the tree.
pub(crate) async fn supervise_plugin(
    plugin: &str,
    tree: &mut impl PluginTree,
    shutdown: &CancellationToken,
    grace: std::time::Duration,
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
    failure: Option<FailureHold>,
) -> Result<Supervised, cosca::error::Error> {
    let end = supervise(plugin, tree, shutdown, failure.as_ref(), grace, stdout, stderr).await;
    let start_failed = failure.is_some_and(FailureHold::deliver);
    Ok(Supervised {
        end: end?,
        start_failed,
    })
}

/// Why a running plugin must come down, and how. One exhaustive match decides each.
#[derive(Clone, Copy)]
enum Takedown {
    /// The chain is shutting down: ask the plugin to exit, give it its grace, then kill it.
    Shutdown,
    /// The plugin's start failed. It has said so or can no longer say otherwise, so it is not asked
    /// anything: it gets its grace to exit on its own, which is what a plugin that reported a fatal
    /// error does, and keeps its own exit status; then it is killed.
    StartFailed,
}

impl Takedown {
    async fn carry_out(
        self,
        plugin: &str,
        tree: &mut impl PluginTree,
        failure: Option<&FailureHold>,
        grace: std::time::Duration,
        stdout: tokio::task::JoinHandle<()>,
        stderr: tokio::task::JoinHandle<()>,
    ) -> Result<PluginEnd, cosca::error::Error> {
        match self {
            Takedown::Shutdown => {
                // Before anything reaches the plugin, so a stdout it closes in answer is seen as taken down.
                if let Some(failure) = failure {
                    failure.mark_taken_down();
                }
                shut_down_on_request(plugin, tree, grace, stdout, stderr).await
            }
            Takedown::StartFailed => end_failed_start(plugin, tree, grace, stdout, stderr).await,
        }
    }
}

/// Resolves with the first reason the plugin must come down. A chain shutdown outranks a failed
/// start, which is a child of it; never resolves when neither has happened.
async fn takedown_requested(shutdown: &CancellationToken, failure: Option<&FailureHold>) -> Takedown {
    let failed = async {
        match failure {
            Some(failure) => failure.failed().await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        biased;
        () = shutdown.cancelled() => Takedown::Shutdown,
        () = failed => Takedown::StartFailed,
    }
}

async fn supervise(
    plugin: &str,
    tree: &mut impl PluginTree,
    shutdown: &CancellationToken,
    failure: Option<&FailureHold>,
    grace: std::time::Duration,
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
) -> Result<PluginEnd, cosca::error::Error> {
    tokio::select! {
        // An exit seen at the same moment as a take-down request is still an exit.
        biased;
        watched = tree.wait_root_exit() => match watched {
            Ok(()) => end_exited_plugin(plugin, tree, stdout, stderr).await,
            Err(e) => {
                tracing::warn!(
                    plugin = %plugin,
                    "the plugin's exit cannot be watched ({e}); reaping it before killing its tree"
                );
                tokio::select! {
                    biased;
                    reaped = reap_root(tree) => end_after_reap(plugin, tree, stdout, stderr, reaped).await,
                    // Nothing can say the root exited short of reaping it, which would leave the tree to a
                    // recycled process group id: the take-down kills the root and then the tree first.
                    takedown = takedown_requested(shutdown, failure) => {
                        takedown.carry_out(plugin, tree, failure, grace, stdout, stderr).await
                    }
                }
            }
        },
        takedown = takedown_requested(shutdown, failure) => {
            if root_has_exited(plugin, tree).await {
                return end_exited_plugin(plugin, tree, stdout, stderr).await;
            }
            takedown.carry_out(plugin, tree, failure, grace, stdout, stderr).await
        }
    }
}

/// Whether the root has already exited: one non-blocking read of its state (a zero-grace watch), not
/// a wait. `false` when the state cannot be read, so the caller acts as for a running root.
async fn root_has_exited(plugin: &str, tree: &impl PluginTree) -> bool {
    match tree.wait_root_exit_within(std::time::Duration::ZERO).await {
        Ok(exited) => exited,
        Err(e) => {
            tracing::warn!(plugin = %plugin, "could not read whether the plugin's root has exited: {e}");
            false
        }
    }
}

async fn end_exited_plugin(
    plugin: &str,
    tree: &mut impl PluginTree,
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
) -> Result<PluginEnd, cosca::error::Error> {
    Ok(PluginEnd::Exited(end_plugin(plugin, tree, stdout, stderr).await?))
}

/// Collects the root's status and, with the root reaped, disarms its handle. Nothing awaits between
/// the two, so a task aborted from outside never holds a reaped root with an armed handle.
async fn reap_root(tree: &mut impl PluginTree) -> Result<std::process::ExitStatus, cosca::error::Error> {
    let status = tree.reap().await?;
    tree.disarm();
    Ok(status)
}

/// Ends a plugin whose root was reaped before its tree could be killed (see [`end_reaped_plugin`]).
async fn end_after_reap(
    plugin: &str,
    tree: &mut impl PluginTree,
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
    reaped: Result<std::process::ExitStatus, cosca::error::Error>,
) -> Result<PluginEnd, cosca::error::Error> {
    match reaped {
        Ok(status) => {
            end_reaped_plugin(plugin, tree, stdout, stderr).await;
            Ok(PluginEnd::Exited(status))
        }
        // Nothing was killed, so the output may stay open: the bounded wait still
        // keeps a failure reported after this return behind what the plugin wrote.
        Err(e) => {
            wait_for_readers(plugin, stdout, stderr).await;
            Err(e)
        }
    }
}

async fn shut_down_on_request(
    plugin: &str,
    tree: &mut impl PluginTree,
    grace: std::time::Duration,
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
) -> Result<PluginEnd, cosca::error::Error> {
    tracing::info!(plugin = %plugin, "shutting down");
    shut_plugin_down(plugin, tree, grace, stdout, stderr).await?;
    Ok(PluginEnd::ShutDown)
}

/// Ends a plugin whose root has exited or been told to die: kills and drains its tree, waits for its
/// output, and only then collects the root's status. The root stays unreaped until then, so a pgid-based
/// kill cannot hit a recycled process group.
pub(crate) async fn end_plugin(
    plugin: &str,
    tree: &mut impl PluginTree,
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
) -> Result<std::process::ExitStatus, cosca::error::Error> {
    drain_readers_after_exit(plugin, tree, stdout, stderr).await;
    reap_root(tree).await
}

/// Ends a plugin whose root was reaped before its tree could be killed. A kill that signals a process
/// group id is skipped (the id may now name an unrelated group); the tree is killed otherwise. The
/// bounded wait for the output follows either way.
async fn end_reaped_plugin(
    plugin: &str,
    tree: &mut impl PluginTree,
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
) {
    if kill_tree_addresses_a_releasable_id(tree.containment()) {
        tracing::debug!(
            plugin = %plugin,
            "not killing the plugin's process tree: its root is reaped and the process group id the kill names may be recycled"
        );
        wait_for_readers(plugin, stdout, stderr).await;
    } else {
        drain_readers_after_exit(plugin, tree, stdout, stderr).await;
    }
}

/// Ends a plugin whose start failed: gives its root `grace` to exit on its own, then kills it if it has
/// not, and [`finish_plugin`]s it. A root that exited by itself is reported with its own status.
async fn end_failed_start(
    plugin: &str,
    tree: &mut impl PluginTree,
    grace: std::time::Duration,
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
) -> Result<PluginEnd, cosca::error::Error> {
    tracing::info!(plugin = %plugin, "the plugin's start failed; taking it down");
    let exited = watch_root_exit_within(plugin, tree, grace).await;
    let status = finish_plugin(plugin, tree, exited, stdout, stderr).await?;
    Ok(if exited {
        PluginEnd::Exited(status)
    } else {
        PluginEnd::ShutDown
    })
}

/// Whether the root exits within `grace`. `false` when it does not, or when it cannot be watched.
async fn watch_root_exit_within(plugin: &str, tree: &impl PluginTree, grace: std::time::Duration) -> bool {
    match tree.wait_root_exit_within(grace).await {
        Ok(exited) => exited,
        Err(e) => {
            tracing::warn!(plugin = %plugin, "could not watch the plugin exit during shutdown: {e}");
            false
        }
    }
}

/// Shuts a running plugin down: asks the root to exit, gives it `grace`, hard-kills it if it has not
/// exited (or could not be asked or watched: the escalation), then [`end_plugin`]s it.
///
/// A refused root kill (an elevated or setuid wrapper) is logged at once and returned. The tree is
/// still killed and its output drained, but the root is reaped only if a probe then finds it exited:
/// a root that survives the tree kill too cannot be waited for, and the handle is left armed so that
/// dropping it still kills what it can.
pub(crate) async fn shut_plugin_down(
    plugin: &str,
    tree: &mut impl PluginTree,
    grace: std::time::Duration,
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
) -> Result<std::process::ExitStatus, cosca::error::Error> {
    let exited_within_grace = match tree.terminate() {
        Ok(()) => watch_root_exit_within(plugin, tree, grace).await,
        Err(e) => {
            tracing::debug!(plugin = %plugin, "could not ask the plugin to exit: {e}");
            false
        }
    };
    finish_plugin(plugin, tree, exited_within_grace, stdout, stderr).await
}

/// The end of a take-down, once the root has had its grace: kills a root that has not exited, then
/// [`end_plugin`]s it. A refused root kill is handled as [`shut_plugin_down`] documents.
async fn finish_plugin(
    plugin: &str,
    tree: &mut impl PluginTree,
    exited_within_grace: bool,
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
) -> Result<std::process::ExitStatus, cosca::error::Error> {
    // Still running after the grace, or never asked: either way the root must go.
    let refusal = match if exited_within_grace { Ok(()) } else { tree.kill_root() } {
        Ok(()) => return end_plugin(plugin, tree, stdout, stderr).await,
        Err(refusal) => refusal,
    };
    tracing::warn!(plugin = %plugin, "failed to kill the plugin's root: {refusal}");
    drain_readers_after_exit(plugin, tree, stdout, stderr).await;
    if root_has_exited(plugin, tree).await {
        if let Err(e) = reap_root(tree).await {
            tracing::warn!(plugin = %plugin, "failed to reap the plugin's root: {e}");
        }
    }
    Err(refusal)
}

/// After the child has exited (or been shut down): kill its process tree, wait for the tree to
/// drain, then wait for both output readers to reach EOF, so the child's last lines (the typed
/// `BindConflict`/`Fatal` among them) are delivered before `run` returns.
///
/// The kill comes first because a descendant that inherited the pipe holds it open after the child
/// is gone. Where the kernel owns the tree's membership, the tree's exit edge then has no bound: the
/// kernel guarantees the members exit. The reader wait is bounded by [`READER_EOF_BOUND`] on every
/// containment, because a pipe holder outside the tree (a process that left its cgroup, a handle
/// duplicated into a process outside the job) outlives the drain. See `wait_for_readers` for what its
/// expiry does. An edge that cannot be awaited leaves the reader wait alone to order the output: a platform
/// that cannot observe the edge at all is logged at debug, any other failure is a warning.
pub(crate) async fn drain_readers_after_exit(
    plugin: &str,
    tree: &mut impl PluginTree,
    stdout: tokio::task::JoinHandle<()>,
    stderr: tokio::task::JoinHandle<()>,
) {
    let containment = tree.containment();
    match tree.kill_tree() {
        Ok(()) => {
            if exit_edge_proves_the_tree_gone(containment) {
                match tree.wait_tree_drained().await {
                    Ok(()) => {}
                    // A known platform gap (bindreams/hole#1124), so not worth a warning on every take-down.
                    Err(e @ cosca::error::Error::Unsupported { .. }) => tracing::debug!(
                        plugin = %plugin,
                        "the plugin's process tree drain cannot be observed here ({e}); its output is waited for at most {READER_EOF_BOUND:?} instead"
                    ),
                    Err(e) => tracing::warn!(
                        plugin = %plugin,
                        "the plugin's process tree drain cannot be observed ({e}); its output is waited for at most {READER_EOF_BOUND:?} instead"
                    ),
                }
            }
        }
        Err(e) if containment.can_teardown() => {
            tracing::warn!(plugin = %plugin, "failed to kill the plugin's process tree: {e}");
        }
        // A nested or uncontained child has no tree of its own to kill.
        Err(e) => tracing::debug!(plugin = %plugin, "no process tree to kill: {e}"),
    }
    wait_for_readers(plugin, stdout, stderr).await;
}

/// Waits for both output readers to reach EOF, for at most [`READER_EOF_BOUND`]. On expiry it warns
/// that the output after this point was cut and aborts the readers (so their hold on the readiness
/// sender drops), then waits for the aborted readers to end.
async fn wait_for_readers(
    plugin: &str,
    mut stdout: tokio::task::JoinHandle<()>,
    mut stderr: tokio::task::JoinHandle<()>,
) {
    let both = async {
        let _ = tokio::join!(&mut stdout, &mut stderr);
    };
    // A process outside containment may hold the pipe forever; the bound is surfaced as a warning,
    // not taken as proof the output is complete.
    if tokio::time::timeout(READER_EOF_BOUND, both).await.is_err() {
        tracing::warn!(
            plugin = %plugin,
            "the plugin's output pipes were still open {READER_EOF_BOUND:?} after it exited (a process it started holds them); its output after this point was cut"
        );
        // `abort` takes effect at a task's next await, so a reader mid-poll on another thread finishes that
        // poll first, and what it decides in it must be in before the caller reads the failure hold.
        for reader in [&mut stdout, &mut stderr] {
            if !reader.is_finished() {
                reader.abort();
                let _ = reader.await;
            }
        }
    }
}
