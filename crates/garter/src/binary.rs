use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::chain::Mode;
use crate::plugin::ChainPlugin;
use crate::shutdown;
use crate::sitrep::{PluginReady, StartError};

/// How a [`BinaryPlugin`] learns it is ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadinessMode {
    /// Parse the child's stdout for a sitrep `hello`/`ready` handshake.
    /// Use for plugins known to speak sitrep (ex-ray, galoshes-embedded).
    ExpectSitrep,
    /// Self-probe `local` with a TCP connect (via [`crate::chain::poll_ready`]).
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
    /// On a bind conflict the port never binds, so the probe can never win —
    /// `BindConflict` always comes from sitrep (deterministic). On success either
    /// path may win; both report the same listen address, so the sitrep-preference
    /// (better transports) is best-effort, not guaranteed. Prefer explicit
    /// `ExpectSitrep` when the plugin is known to speak sitrep AND authoritative
    /// transports matter (the bridge does).
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

/// Fires a [`tokio::sync::Notify`] when dropped, so a task's completion signal
/// survives the task unwinding or being aborted — not only returning normally.
struct SignalOnDrop(Arc<tokio::sync::Notify>);

impl Drop for SignalOnDrop {
    fn drop(&mut self) {
        self.0.notify_one();
    }
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
        let mut cmd = Command::new(&self.path);
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
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.kill_on_drop(true);

        // Spawn as the root of a process-tree kill-group (Windows job object /
        // Unix process group) with stdio handle hygiene, so a force-kill reaps the
        // plugin's whole descendant tree and an orphaned grandchild can never hold
        // the host's pipe handles (bindreams/hole#197). CREATE_NEW_PROCESS_GROUP
        // (for graceful_stop's CTRL_BREAK) is set inside `GroupedChild::spawn`.
        // Nesting::Mark keeps the root-only group rule: a nested garter (e.g.
        // galoshes inside the bridge's chain) joins this group instead of
        // creating one Unix pgids could escape from.
        let mut gc = kill_group::GroupedChild::spawn(&mut cmd, kill_group::Nesting::Mark)
            .map_err(|e| crate::Error::Chain(format!("failed to spawn '{}': {e}", self.path.display())))?;

        if let (Some(sink), Some(pid)) = (&self.pid_sink, gc.child.id()) {
            sink(pid);
        }

        // Capture stderr FIRST: the sitrep stdout reader's readiness-FAILURE
        // path (child exited before ever readying) joins `stderr_done` before
        // reporting that failure, so a plugin whose crash lands on stderr (the
        // common shape for a Go panic under `GOTRACEBACK=crash`) isn't reported
        // as if it said nothing. `Notify` (not the `JoinHandle` itself) so this
        // task's handle stays free for the unconditional drain below too.
        let stderr = gc.child.stderr.take().expect("stderr was piped");
        let plugin_name = self.name.clone();
        let log_sink = self.log_sink.clone();
        let stderr_done = Arc::new(tokio::sync::Notify::new());
        let stderr_done_signal = SignalOnDrop(Arc::clone(&stderr_done));
        let stderr_task = tokio::spawn(async move {
            // Signalled on unwind and on abort too: the stdout reader waits on
            // this with no bound, and `relay_to_sink` runs a consumer-supplied
            // `LogSink` that garter cannot assume is panic-free.
            let _stderr_done = stderr_done_signal;
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

        // Every task that can still resolve readiness is owned HERE, not by the
        // reader: in `Probe` the sender lives in a self-probe task outright, and
        // in `Auto` / the tier-2 fallback a probe CO-owns it through
        // `SharedReady`. `run` therefore holds their standdown token and their
        // handles, so `reap_and_drain` can end them and wait for them.
        let probe_standdown = shutdown.child_token();
        let (probe_tx, mut probe_rx) = tokio::sync::mpsc::unbounded_channel::<tokio::task::JoinHandle<()>>();

        // Stdout consumer: in Probe mode it forwards lines to tracing and
        // readiness comes from a separate self-probe task; in ExpectSitrep
        // mode it parses sitrep events and IS the readiness source. Build
        // the right one per `self.readiness`.
        let stdout = gc.child.stdout.take().expect("stdout was piped");
        let stdout_task = match self.readiness {
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
                // readiness; on standdown-first, drop `ready` unsent (the
                // receiver gets RecvError: shutdown happened before readiness).
                let probe_local = local;
                let probe_standdown = probe_standdown.clone();
                let _ = probe_tx.send(tokio::spawn(async move {
                    if let Some(addr) = crate::chain::poll_ready(probe_local, probe_standdown).await {
                        let _ = ready.send(Ok(PluginReady {
                            listen: addr,
                            transports: crate::sitrep::Transports::TCP,
                        }));
                    }
                }));

                log_task
            }
            ReadinessMode::ExpectSitrep => spawn_sitrep_stdout_reader(
                stdout,
                self.name.clone(),
                local,
                probe_standdown.clone(),
                ready,
                false,
                self.log_sink.clone(),
                stderr_done,
                probe_tx.clone(),
            ),
            ReadinessMode::Auto => spawn_sitrep_stdout_reader(
                stdout,
                self.name.clone(),
                local,
                probe_standdown.clone(),
                ready,
                true,
                self.log_sink.clone(),
                stderr_done,
                probe_tx.clone(),
            ),
        };

        // Wait for child exit or shutdown signal.
        //
        // The readiness sender (start-gate for `on_ready`) and this
        // `child.wait()` Err return (lifecycle error driving teardown) are two
        // intentionally separate observers of one exit; a plugin that emits
        // `fatal` then exits nonzero fires both, and neither must be suppressed.
        // If the child binds but never readies and is then shut down, the
        // sender is dropped unsent and the aggregator synthesizes `Fatal{exited
        // before ready}`. See `run_readiness_aggregator` in chain.rs for the
        // full two-channel rationale.
        let drain_timeout = std::time::Duration::from_secs(5);
        tokio::select! {
            status = gc.child.wait() => {
                // Drain BEFORE inspecting `status`: readiness must be final on
                // every exit from `run`, including a `wait()` that itself failed.
                reap_and_drain(&mut gc, &probe_standdown, stdout_task, stderr_task, &mut probe_rx).await;
                let status = status?;
                if status.success() {
                    Ok(())
                } else {
                    match status.code() {
                        Some(code) => Err(crate::Error::PluginExit {
                            name: self.name.clone(),
                            code,
                        }),
                        None => Err(crate::Error::PluginKilled {
                            name: self.name.clone(),
                        }),
                    }
                }
            }
            _ = shutdown.cancelled() => {
                tracing::info!(plugin = %self.name, "shutting down");
                // Force path force-kills the direct child; `reap_and_drain` below
                // takes the rest of the tree. Its result is held, not `?`-ed:
                // readiness must be final on every exit from `run`, and
                // `graceful_stop` is fallible (a Windows console-event error, an
                // io error from wait/kill).
                let stopped = shutdown::graceful_stop(&mut gc.child, drain_timeout).await;
                reap_and_drain(&mut gc, &probe_standdown, stdout_task, stderr_task, &mut probe_rx).await;
                stopped
            }
        }
    }
}

/// Reap the plugin's process tree, then wait for every task that can still
/// resolve this plugin's readiness. EVERY exit from `run` ends here — both
/// `select!` arms and both their error paths — so the guarantee (when `run`
/// returns, the readiness outcome is FINAL) depends neither on which arm an
/// already-dead child was handled by (`select!` is unbiased) nor on the arm
/// succeeding.
///
/// **The reap is what makes the wait terminate.** A dead direct child does NOT
/// close its stdout/stderr: any descendant that inherited its stdio holds a
/// duplicate of the write end, so the readers reach EOF only once the whole tree
/// is gone (bindreams/hole#197). `GroupedChild::Drop` reaps that tree either way
/// when `run` returns; this only orders the reap ahead of the drain instead of
/// after it. Standing the probes down is the same argument for the other
/// readiness owner: the child is gone, so no probe can still report a real
/// listener.
///
/// RESIDUAL: the reap covers only processes inside THIS spawn's kill-group. A
/// nested spawn (no group of its own), a Windows job kill-group already logged
/// as degraded, or a descendant that `setsid()`s out of the process group can
/// still hold a write end, and this wait would then block. Closing that needs a
/// "what containment did I actually achieve" answer from the spawn itself, which
/// bindreams/hole#816 tracks.
async fn reap_and_drain(
    gc: &mut kill_group::GroupedChild,
    probe_standdown: &CancellationToken,
    stdout_task: tokio::task::JoinHandle<()>,
    stderr_task: tokio::task::JoinHandle<()>,
    probes: &mut tokio::sync::mpsc::UnboundedReceiver<tokio::task::JoinHandle<()>>,
) {
    gc.kill_tree().await;
    probe_standdown.cancel();
    let _ = tokio::join!(stdout_task, stderr_task);
    // Close rather than rely on every sender having been dropped: the reader (the
    // only task that spawns a probe mid-stream) has ended, so no send can still be
    // coming, and `recv` then drains what is buffered and stops.
    probes.close();
    while let Some(probe) = probes.recv().await {
        let _ = probe.await;
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

/// Spawn a tier-2 self-probe that, on a successful TCP connect to `local`,
/// reports `PluginReady` (TCP-only) through the shared send-once sender.
/// Shared by `ExpectSitrep`'s unknown-major fallback and `Auto`'s concurrent
/// probe. `standdown` ends the probe early (without sending) when cancelled.
///
/// The handle goes to `probes` because this task CO-OWNS the readiness sender:
/// `run` must be able to wait for it, not just for the reader (see
/// [`reap_and_drain`]).
fn spawn_shared_probe(
    local: SocketAddr,
    standdown: CancellationToken,
    shared: SharedReady,
    probes: &tokio::sync::mpsc::UnboundedSender<tokio::task::JoinHandle<()>>,
) {
    let _ = probes.send(tokio::spawn(async move {
        if let Some(addr) = crate::chain::poll_ready(local, standdown).await {
            if let Some(tx) = shared.lock().await.take() {
                let _ = tx.send(Ok(PluginReady {
                    listen: addr,
                    transports: crate::sitrep::Transports::TCP,
                }));
            }
        }
    }));
}

/// Spawn the sitrep stdout reader.
///
/// The reader parses `@sitrep` events and sends exactly one readiness result.
/// On an unknown protocol major (`FallBackToTier2`) it hands readiness to a
/// self-probe, sharing the single sender via [`SharedReady`] so at most one send
/// ever happens. When `auto` is true ([`ReadinessMode::Auto`]) a concurrent
/// self-probe is ALSO started up front and stood down on a supported `hello`, so
/// a non-sitrep plugin (including one silent on stdout) is still readied by the
/// probe. Non-event lines pass through to tracing as logs. On stdout EOF without
/// ever sending, the sender drops unsent → the chain aggregator synthesizes a
/// process-exit failure (the intended backstop) — waiting on `stderr_done` first
/// (unbounded, on the same guarantor as this reader's own EOF: see
/// [`reap_and_drain`]), so a crash whose last words land on stderr is not
/// reported as if the plugin said nothing.
#[allow(clippy::too_many_arguments)] // 9 args — bundling into a struct adds more noise than the warning.
fn spawn_sitrep_stdout_reader(
    stdout: tokio::process::ChildStdout,
    plugin_name: String,
    local: SocketAddr,
    probe_standdown: CancellationToken,
    ready: oneshot::Sender<Result<PluginReady, StartError>>,
    auto: bool,
    log_sink: Option<LogSink>,
    stderr_done: Arc<tokio::sync::Notify>,
    probes: tokio::sync::mpsc::UnboundedSender<tokio::task::JoinHandle<()>>,
) -> tokio::task::JoinHandle<()> {
    use crate::sitrep::{ProtocolSupport, SitrepEvent};

    let shared: SharedReady = Arc::new(tokio::sync::Mutex::new(Some(ready)));
    tokio::spawn(async move {
        // Auto: run the self-probe concurrently from the start (mirrors the
        // default `Probe` mode), sharing the send-once sender. A SUPPORTED
        // `hello` cancels `probe_standdown` so the probe defers to sitrep;
        // otherwise the probe readies the plugin (handles a non-sitrep plugin
        // that is silent on stdout — there is no first line to classify on).
        // `probe_standdown` is a child of the plugin's `shutdown` token and is
        // owned by `run`, so both chain shutdown and child exit stop the probe.
        if auto {
            spawn_shared_probe(local, probe_standdown.clone(), shared.clone(), &probes);
        }
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut handshake_ok = false;
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
                                        spawn_shared_probe(local, probe_standdown.clone(), shared.clone(), &probes);
                                    }
                                    // Drain the rest of stdout as logs so the
                                    // child's pipe never blocks; the probe task
                                    // owns readiness from here on.
                                    drain_remaining_logs(&mut lines, &plugin_name, &log_sink).await;
                                    break;
                                }
                            }
                        }
                        Ok(Some(SitrepEvent::Ready { listen, transports })) if handshake_ok => {
                            if let Some(tx) = shared.lock().await.take() {
                                // Empty/all-unknown transports is illegal per
                                // SITREP: a `ready` MUST list >=1 served
                                // transport. Reject as Fatal.
                                if transports.is_empty() {
                                    let _ = tx.send(Err(StartError::Fatal {
                                        detail: "sitrep ready reported empty transports (protocol violation)".into(),
                                        errno: None,
                                    }));
                                } else {
                                    let _ = tx.send(Ok(PluginReady { listen, transports }));
                                }
                            }
                        }
                        Ok(Some(SitrepEvent::BindConflict { errno, addr })) if handshake_ok => {
                            if let Some(tx) = shared.lock().await.take() {
                                let _ = tx.send(Err(StartError::BindConflict { errno, addr }));
                            }
                        }
                        Ok(Some(SitrepEvent::Fatal { detail, errno })) if handshake_ok => {
                            if let Some(tx) = shared.lock().await.take() {
                                let _ = tx.send(Err(StartError::Fatal { detail, errno }));
                            }
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
        // If the child closed stdout without ever sending readiness, wait for the
        // stderr reader before dropping the shared sender signals process-exit to
        // the aggregator — a crash lands on stderr more often than stdout (e.g. a
        // Go panic under `GOTRACEBACK=crash`), and the two pipes are read by
        // independent tasks with no ordering between them otherwise. Unbounded on
        // the same guarantor as this reader's own EOF (the tree is reaped, so both
        // pipes close), rather than a budget a large panic dump can overrun. A
        // plugin that closes stdout while still ALIVE parks here instead of
        // reporting an exit it has not made.
        stderr_done.notified().await;
    })
}

/// Forward all remaining stdout lines to tracing as ordinary logs. Used
/// after a `FallBackToTier2` handoff so the child's stdout pipe never
/// blocks while the self-probe owns readiness.
///
/// The loop is unbounded by design and terminates on the **child's** stdout
/// EOF — guaranteed when the child (and its tree) is reaped via `GroupedChild`
/// / `kill_on_drop`, which closes the write end. This reads the child's pipe,
/// not the host's, so it cannot reproduce the #197 runtime-drop hang (that was
/// an orphan holding the *host's* stdio); and because it runs inside a detached
/// `tokio::spawn`, runtime drop aborts it at the await point rather than
/// blocking on it.
async fn drain_remaining_logs(
    lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    plugin_name: &str,
    log_sink: &Option<LogSink>,
) {
    while let Ok(Some(line)) = lines.next_line().await {
        let line = relay_to_sink(&line, log_sink);
        tracing::info!(plugin = %plugin_name, "{line}");
    }
}
