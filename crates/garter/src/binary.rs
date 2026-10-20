use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
                // readiness; on shutdown-first, drop `ready` unsent (the
                // receiver gets RecvError: shutdown happened before readiness).
                let probe_local = local;
                let probe_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    if let Some(addr) = crate::chain::poll_ready(probe_local, probe_shutdown).await {
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
                    self.name.clone(),
                    local,
                    shutdown.clone(),
                    ready,
                    false,
                    self.log_sink.clone(),
                );
                (task, Some(failure))
            }
            ReadinessMode::Auto => {
                let (task, failure) = spawn_sitrep_stdout_reader(
                    stdout,
                    self.name.clone(),
                    local,
                    shutdown.clone(),
                    ready,
                    true,
                    self.log_sink.clone(),
                );
                (task, Some(failure))
            }
        };

        // If the child binds but never readies and is then shut down, the readiness sender is dropped
        // unsent and the aggregator synthesizes `Fatal{exited before ready}`.
        let end = supervise_plugin(
            &self.name,
            &mut child,
            &shutdown,
            SHUTDOWN_GRACE,
            stdout_task,
            stderr_task,
            failure,
        )
        .await?;
        match end {
            PluginEnd::ShutDown => Ok(()),
            PluginEnd::Exited(status) if status.success() => Ok(()),
            PluginEnd::Exited(status) => match status.code() {
                Some(code) => Err(crate::Error::PluginExit {
                    name: self.name.clone(),
                    code,
                }),
                None => Err(crate::Error::PluginKilled {
                    name: self.name.clone(),
                }),
            },
        }
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
fn spawn_shared_probe(local: SocketAddr, standdown: CancellationToken, shared: SharedReady) {
    tokio::spawn(async move {
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
/// plugin is taken down. Does nothing once readiness is decided (a `ready`, or an earlier failure).
async fn hold_failure(
    shared: &SharedReady,
    held: &mut Option<oneshot::Sender<HeldFailure>>,
    failed: &CancellationToken,
    error: StartError,
) {
    let Some(ready) = shared.lock().await.take() else {
        return;
    };
    if let Some(held) = held.take() {
        let _ = held.send(HeldFailure { ready, error });
    }
    failed.cancel();
}

/// Where a sitrep reader's start failure waits for the plugin's output. The failure is sent only by
/// [`FailureHold::deliver`], so a caller that learns of it has already seen everything the plugin wrote
/// before.
pub(crate) struct FailureHold {
    held: oneshot::Receiver<HeldFailure>,
    /// Cancelled once the reader has decided the start failed. A child of the chain's shutdown token.
    failed: CancellationToken,
}

impl FailureHold {
    /// Resolves once the reader has decided the start failed.
    pub(crate) async fn failed(&self) {
        self.failed.cancelled().await;
    }

    /// Sends the failure the reader held, if it held one, on the plugin's readiness channel. Call it
    /// once the plugin's output readers have finished or been given up on.
    pub(crate) fn deliver(mut self) {
        if let Ok(HeldFailure { ready, error }) = self.held.try_recv() {
            let _ = ready.send(Err(error));
        }
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
/// down for, drains its output, and only then delivers. The reader keeps relaying lines until stdout
/// closes. `shutdown` ends a probe the reader started.
pub(crate) fn spawn_sitrep_stdout_reader(
    stdout: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    plugin_name: String,
    local: SocketAddr,
    shutdown: CancellationToken,
    ready: oneshot::Sender<Result<PluginReady, StartError>>,
    auto: bool,
    log_sink: Option<LogSink>,
) -> (tokio::task::JoinHandle<()>, FailureHold) {
    use crate::sitrep::{ProtocolSupport, SitrepEvent};

    let shared: SharedReady = Arc::new(tokio::sync::Mutex::new(Some(ready)));
    let (held_tx, held_rx) = oneshot::channel();
    let failed = shutdown.child_token();
    let hold = FailureHold {
        held: held_rx,
        failed: failed.clone(),
    };
    let task = tokio::spawn(async move {
        let mut held = Some(held_tx);
        // Auto: run the self-probe concurrently from the start (mirrors the
        // default `Probe` mode), sharing the send-once sender. A SUPPORTED
        // `hello` cancels `probe_standdown` so the probe defers to sitrep;
        // otherwise the probe readies the plugin (handles a non-sitrep plugin
        // that is silent on stdout — there is no first line to classify on).
        // `probe_standdown` is a child of `shutdown`, so chain shutdown stops it.
        let probe_standdown = shutdown.child_token();
        if auto {
            spawn_shared_probe(local, probe_standdown.clone(), shared.clone());
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
                                        spawn_shared_probe(local, shutdown.clone(), shared.clone());
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
                                hold_failure(&shared, &mut held, &failed, error).await;
                            } else if let Some(tx) = shared.lock().await.take() {
                                let _ = tx.send(Ok(PluginReady { listen, transports }));
                            }
                        }
                        Ok(Some(SitrepEvent::BindConflict { errno, addr })) if handshake_ok => {
                            hold_failure(&shared, &mut held, &failed, StartError::BindConflict { errno, addr }).await;
                        }
                        Ok(Some(SitrepEvent::Fatal { detail, errno })) if handshake_ok => {
                            hold_failure(&shared, &mut held, &failed, StartError::Fatal { detail, errno }).await;
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
        // plugin any more; a probe that owns readiness decides for itself.
        if !probe_owns_readiness {
            let error = StartError::Fatal {
                detail: "plugin closed its sitrep stream before becoming ready".into(),
                errno: None,
            };
            hold_failure(&shared, &mut held, &failed, error).await;
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

impl PluginTree for cosca::tokio::Child {
    fn containment(&self) -> Containment {
        cosca::tokio::Child::containment(self)
    }

    async fn wait_root_exit(&self) -> Result<(), cosca::error::Error> {
        cosca::tokio::Process::from_id(self.id()).wait().await
    }

    async fn wait_root_exit_within(&self, grace: std::time::Duration) -> Result<bool, cosca::error::Error> {
        cosca::tokio::Process::from_id(self.id()).wait_timeout(grace).await
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
    // `BinaryPlugin::run` must be `Send`.
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

/// How [`supervise_plugin`] ended a plugin.
pub(crate) enum PluginEnd {
    /// The plugin exited by itself, with this status.
    Exited(std::process::ExitStatus),
    /// `shutdown` fired, or the plugin's start failed and it did not exit on its own; it was taken down.
    ShutDown,
}

/// Runs a started plugin to its end: waits for its root to exit, for `shutdown`, or for its sitrep
/// reader to decide the start failed, then ends it so that its tree is killed while the root is still
/// unreaped (see [`end_plugin`]). An exit that has already happened is reported as an exit even when a
/// take-down was requested too: when the request wins the select, the root is probed once, without
/// waiting, because the exit watch is `Pending` on its first poll even for a root that is already a
/// zombie. A take-down ends a plugin that is still running; an exit that lands after the probe ends as
/// one (see [`Takedown`]).
///
/// The exit watch is non-reaping and needs `pidfd_open` on Linux, which a kernel before 5.3 lacks
/// and a seccomp profile may deny. Without it the root is reaped first (still ending on a take-down)
/// and the tree is killed only where that stays safe (see [`end_reaped_plugin`]).
///
/// The readiness sender (start-gate for `on_ready`) and the exit's `Err` (lifecycle error driving
/// teardown) are two intentionally separate observers of one exit; a plugin that emits `fatal` then
/// exits nonzero fires both, and neither must be suppressed. See `run_readiness_aggregator` in
/// chain.rs for the full two-channel rationale. The start failure `failure` holds is delivered last,
/// after the plugin's output has been drained (or given up on at its bound): whoever hears of it has
/// been shown the plugin's last words.
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
) -> Result<PluginEnd, cosca::error::Error> {
    let end = supervise(plugin, tree, shutdown, failure.as_ref(), grace, stdout, stderr).await;
    if let Some(failure) = failure {
        failure.deliver();
    }
    end
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
        grace: std::time::Duration,
        stdout: tokio::task::JoinHandle<()>,
        stderr: tokio::task::JoinHandle<()>,
    ) -> Result<PluginEnd, cosca::error::Error> {
        match self {
            Takedown::Shutdown => shut_down_on_request(plugin, tree, grace, stdout, stderr).await,
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
                tracing::debug!(
                    plugin = %plugin,
                    "the plugin's exit cannot be watched ({e}); reaping it before killing its tree"
                );
                tokio::select! {
                    biased;
                    status = reap_root(tree) => match status {
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
                    },
                    takedown = takedown_requested(shutdown, failure) => {
                        takedown.carry_out(plugin, tree, grace, stdout, stderr).await
                    }
                }
            }
        },
        takedown = takedown_requested(shutdown, failure) => {
            if root_has_exited(plugin, tree).await {
                return end_exited_plugin(plugin, tree, stdout, stderr).await;
            }
            takedown.carry_out(plugin, tree, grace, stdout, stderr).await
        }
    }
}

/// Whether the root has already exited: one non-blocking read of its state (a zero-grace watch), not
/// a wait. `false` when the state cannot be read, so the caller acts as for a running root.
async fn root_has_exited(plugin: &str, tree: &impl PluginTree) -> bool {
    match tree.wait_root_exit_within(std::time::Duration::ZERO).await {
        Ok(exited) => exited,
        Err(e) => {
            tracing::debug!(plugin = %plugin, "could not read whether the plugin's root has exited: {e}");
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
            tracing::debug!(plugin = %plugin, "could not watch the plugin exit during shutdown: {e}");
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
/// duplicated into a process outside the job) outlives the drain. On expiry it warns that the output
/// after this point was cut and aborts the readers (so their hold on the readiness sender drops).
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
                if let Err(e) = tree.wait_tree_drained().await {
                    tracing::debug!(plugin = %plugin, "could not wait for the plugin's process tree to drain: {e}");
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
/// sender drops).
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
        stdout.abort();
        stderr.abort();
    }
}
