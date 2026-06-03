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
    /// Self-probe `local` with a TCP connect (the relocated poll_ready).
    /// The conservative default for arbitrary / legacy plugins.
    #[default]
    Probe,
}

/// Resolved SIP003 environment-variable mapping for a `BinaryPlugin`'s
/// child process. The plugin's `(local, remote)` from
/// [`ChainPlugin::run`] is mapped here per the SIP003 spec: in client
/// mode `local → SS_LOCAL_*` and `remote → SS_REMOTE_*`; in server mode
/// the pair is swapped so the binary's own server-mode address swap
/// (v2ray-plugin `parseEnv`, etc.) restores the chain's intended
/// direction. See bindreams/hole#396 for the incident.
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

/// A plugin backed by an external SIP003u binary.
pub struct BinaryPlugin {
    path: PathBuf,
    options: Option<String>,
    name: String,
    pid_sink: Option<PidSink>,
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
            readiness: ReadinessMode::default(),
            extra_env: Vec::new(),
        }
    }

    /// Set a callback that fires with the child PID immediately after spawn.
    pub fn pid_sink(mut self, sink: PidSink) -> Self {
        self.pid_sink = Some(sink);
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
    pub(crate) fn sip003_env(&self, local: SocketAddr, remote: SocketAddr) -> Sip003Env {
        // In server mode the binary itself swaps SS_LOCAL/SS_REMOTE
        // semantics (SS_REMOTE = inbound listener, SS_LOCAL = outbound
        // dial). We swap here first so the binary's swap restores the
        // direction we wanted.
        let (ss_local, ss_remote) = match Mode::from_plugin_options(self.options.as_deref()) {
            Mode::Client => (local, remote),
            Mode::Server => (remote, local),
        };
        Sip003Env {
            ss_local_host: ss_local.ip().to_string(),
            ss_local_port: ss_local.port(),
            ss_remote_host: ss_remote.ip().to_string(),
            ss_remote_port: ss_remote.port(),
        }
    }
}

/// Environment variables always injected into a binary plugin's child
/// process, independent of SIP003 config. `GOTRACEBACK=crash` makes a Go
/// plugin (ex-ray) dump full goroutine state to stderr on a native fault
/// (the bridge relays that stderr through tracing). Harmless to Rust
/// plugins, which ignore it. See bindreams/hole#438.
pub(crate) fn fixed_plugin_env() -> &'static [(&'static str, &'static str)] {
    &[("GOTRACEBACK", "crash")]
}

fn extract_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string()
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
        let env = self.sip003_env(local, remote);
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

        // On Windows, create a new process group so that graceful_stop can
        // send CTRL_BREAK_EVENT targeted at this child's group (SIP003u).
        #[cfg(windows)]
        cmd.creation_flags(windows::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP.0);

        let mut child = cmd
            .spawn()
            .map_err(|e| crate::Error::Chain(format!("failed to spawn '{}': {e}", self.path.display())))?;

        if let (Some(sink), Some(pid)) = (&self.pid_sink, child.id()) {
            sink(pid);
        }

        // Stdout consumer: in Probe mode it forwards lines to tracing and
        // readiness comes from a separate self-probe task; in ExpectSitrep
        // mode it parses sitrep events and IS the readiness source. Build
        // the right one per `self.readiness`.
        let stdout = child.stdout.take().expect("stdout was piped");
        let stdout_task = match self.readiness {
            ReadinessMode::Probe => {
                // Tier-2: the stdout reader is a pure log passthrough
                // (unchanged from the pre-sitrep behavior); a separate
                // self-probe task owns readiness.
                let plugin_name = self.name.clone();
                let log_task = tokio::spawn(async move {
                    let reader = BufReader::new(stdout);
                    let mut lines = reader.lines();
                    loop {
                        match lines.next_line().await {
                            Ok(Some(line)) => {
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
                // readiness; on shutdown-first, drop `ready` unsent
                // (RecvError, matching the old "shutdown before ready"
                // semantics).
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

                log_task
            }
            ReadinessMode::ExpectSitrep => {
                spawn_sitrep_stdout_reader(stdout, self.name.clone(), local, shutdown.clone(), ready)
            }
        };

        // Capture stderr
        let stderr = child.stderr.take().expect("stderr was piped");
        let plugin_name = self.name.clone();
        let stderr_task = tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
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

        // Wait for child exit or shutdown signal.
        //
        // Readiness duality / backstop (see the trait + chain aggregator):
        //
        // - DOUBLE-REPORT IS CORRECT. In ExpectSitrep a plugin that emits
        //   `fatal` then exits nonzero produces BOTH a `StartError::Fatal`
        //   via the readiness sender (the START-GATE for `on_ready`) AND the
        //   `child.wait()` → `Err` return below (the LIFECYCLE error that
        //   drives `record_exit`/teardown). Keep both; do NOT suppress
        //   either — they are intentionally separate observers of one event.
        //
        // - ORPHANED READINESS ON CLEAN SHUTDOWN IS THE INTENDED BACKSTOP.
        //   If the child binds, never emits `ready`, then the parent shuts
        //   down, the sitrep reader holds the readiness sender until stdout
        //   EOF; the 100ms drain may abandon the task, dropping the sender
        //   unsent → the aggregator sees RecvError → `Fatal{"exited before
        //   ready"}`. That is CORRECT — the plugin did fail to ready.
        let drain_timeout = std::time::Duration::from_secs(5);
        tokio::select! {
            status = child.wait() => {
                let status = status?;
                // Drain remaining log lines (tasks will EOF when child's pipes close)
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    async { let _ = tokio::join!(stdout_task, stderr_task); }
                ).await;
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
                shutdown::graceful_stop(&mut child, drain_timeout).await?;
                // Drain remaining log lines (tasks will EOF when child's pipes close)
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    async { let _ = tokio::join!(stdout_task, stderr_task); }
                ).await;
                Ok(())
            }
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

/// Spawn the ExpectSitrep stdout reader.
///
/// The reader is the readiness source: it parses `@sitrep` events and
/// sends exactly one readiness result. On an unknown protocol major
/// (`FallBackToTier2`) it hands readiness ownership to a self-probe task
/// (the tier-2 strategy), sharing the single sender via [`SharedReady`]
/// so at most one send ever happens. Non-event lines pass through to
/// tracing as ordinary logs. On stdout EOF without ever sending, the
/// sender drops unsent → the chain aggregator synthesizes a process-exit
/// failure (the intended backstop).
fn spawn_sitrep_stdout_reader(
    stdout: tokio::process::ChildStdout,
    plugin_name: String,
    local: SocketAddr,
    shutdown: CancellationToken,
    ready: oneshot::Sender<Result<PluginReady, StartError>>,
) -> tokio::task::JoinHandle<()> {
    use crate::sitrep::{ProtocolSupport, SitrepEvent};

    let shared: SharedReady = Arc::new(tokio::sync::Mutex::new(Some(ready)));
    tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let mut handshake_ok = false;
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => match crate::sitrep::parse_event(&line) {
                    Ok(Some(SitrepEvent::Hello { protocol })) => {
                        match crate::sitrep::protocol_support(&protocol) {
                            ProtocolSupport::Supported => {
                                handshake_ok = true;
                                tracing::debug!(plugin = %plugin_name, %protocol, "sitrep handshake");
                            }
                            ProtocolSupport::FallBackToTier2 => {
                                tracing::info!(
                                    plugin = %plugin_name,
                                    %protocol,
                                    "unknown sitrep protocol major; readiness falls back to probe"
                                );
                                // Hand readiness to a tier-2 self-probe,
                                // sharing the single sender. The reader
                                // continues only as a log passthrough (it
                                // never sends readiness again).
                                let probe_shared = shared.clone();
                                let probe_local = local;
                                let probe_shutdown = shutdown.clone();
                                tokio::spawn(async move {
                                    if let Some(addr) = crate::chain::poll_ready(probe_local, probe_shutdown).await {
                                        if let Some(tx) = probe_shared.lock().await.take() {
                                            let _ = tx.send(Ok(PluginReady {
                                                listen: addr,
                                                transports: crate::sitrep::Transports::TCP,
                                            }));
                                        }
                                    }
                                });
                                // Drain the rest of stdout as logs so the
                                // child's pipe never blocks; the probe task
                                // owns readiness from here on.
                                drain_remaining_logs(&mut lines, &plugin_name).await;
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
                    _ => tracing::info!(plugin = %plugin_name, "{line}"),
                },
                Ok(None) => break, // EOF
                Err(e) => {
                    tracing::debug!(plugin = %plugin_name, "log reader error: {e}");
                    break;
                }
            }
        }
        // If the child closed stdout without ever sending readiness,
        // dropping the shared sender here signals process-exit to the
        // aggregator (the intended backstop).
    })
}

/// Forward all remaining stdout lines to tracing as ordinary logs. Used
/// after a `FallBackToTier2` handoff so the child's stdout pipe never
/// blocks while the self-probe owns readiness.
async fn drain_remaining_logs(lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>, plugin_name: &str) {
    while let Ok(Some(line)) = lines.next_line().await {
        tracing::info!(plugin = %plugin_name, "{line}");
    }
}
