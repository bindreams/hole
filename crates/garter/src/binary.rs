use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use crate::plugin::ChainPlugin;
use crate::shutdown;

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
        }
    }

    /// Set a callback that fires with the child PID immediately after spawn.
    pub fn pid_sink(mut self, sink: PidSink) -> Self {
        self.pid_sink = Some(sink);
        self
    }
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
    ) -> crate::Result<()> {
        let mut cmd = Command::new(&self.path);
        cmd.env("SS_LOCAL_HOST", local.ip().to_string());
        cmd.env("SS_LOCAL_PORT", local.port().to_string());
        cmd.env("SS_REMOTE_HOST", remote.ip().to_string());
        cmd.env("SS_REMOTE_PORT", remote.port().to_string());
        if let Some(ref opts) = self.options {
            cmd.env("SS_PLUGIN_OPTIONS", opts);
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

        // Capture stdout
        let stdout = child.stdout.take().expect("stdout was piped");
        let plugin_name = self.name.clone();
        let stdout_task = tokio::spawn(async move {
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

        // Wait for child exit or shutdown signal
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
