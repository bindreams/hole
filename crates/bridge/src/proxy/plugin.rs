// Garter-based plugin lifecycle management.
//
// Replaces shadowsocks-service's built-in `PluginConfig` spawning with
// Garter's `BinaryPlugin` + `ChainRunner`, giving us structured log
// capture, SIP003u-compliant graceful shutdown, and future chain
// composition support.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hole_common::plugin::plugin_protocols;
use hole_common::port_alloc;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::ProxyError;

const READINESS_TIMEOUT: Duration = Duration::from_secs(30);

/// A running plugin chain managed by Garter.
///
/// Owns the tokio task running the chain and a cancellation token for
/// graceful shutdown. Drop cancels the token (SIP003u: SIGTERM on Unix,
/// CTRL_BREAK on Windows, 5s drain timeout) and aborts the task as a
/// safety net.
///
/// If `state_dir` is set, `Drop` clears the plugin state file — this is
/// the clean-shutdown path that makes the startup reaper a no-op.
pub struct PluginChain {
    handle: tokio::task::JoinHandle<garter::Result<()>>,
    cancel: CancellationToken,
    local_addr: SocketAddr,
    state_dir: Option<PathBuf>,
}

impl std::fmt::Debug for PluginChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginChain")
            .field("local_addr", &self.local_addr)
            .field("cancelled", &self.cancel.is_cancelled())
            .finish()
    }
}

impl PluginChain {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Explicitly kill all tracked plugin PIDs and clear the state file.
    /// Called from `ProxyManager::stop` before dropping the chain, so the
    /// stop path doesn't race with the OS reaping.
    pub fn kill_tracked(&self) {
        let Some(ref dir) = self.state_dir else { return };
        if let Some(state) = crate::plugin_state::load(dir) {
            for record in &state.plugins {
                if let Err(e) = crate::plugin_recovery::kill_pid(record.pid) {
                    tracing::warn!(pid = record.pid, error = %e, "failed to kill tracked plugin on stop");
                }
            }
        }
    }
}

impl Drop for PluginChain {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.handle.abort();
        if let Some(ref dir) = self.state_dir {
            if let Err(e) = crate::plugin_state::clear(dir) {
                tracing::warn!(error = %e, "failed to clear plugin state file on drop");
            }
        }
    }
}

/// Start a plugin chain with a single binary plugin.
///
/// When `state_dir` is `Some`, plugin PIDs are recorded to
/// `bridge-plugins.json` synchronously at spawn time (via Garter's
/// `pid_sink` callback), enabling crash recovery on next startup.
/// When `None`, no state is tracked (used by `server_test` for one-shot
/// probes that die with the bridge).
///
/// `plugin_name` selects the protocol set for the local port allocation
/// — UDP-capable plugins (galoshes) need the port verified for both TCP
/// and UDP so their internal dual bind on the local address can't hit
/// the Windows cross-protocol excluded-port race. See
/// [`hole_common::plugin::plugin_protocols`].
///
/// Goes through [`port_alloc::bind_with_retry`] for structural
/// consistency with the other ephemeral-bind sites in the workspace.
/// The retry envelope is decorative for this site: the plugin
/// subprocess binds `local_addr` itself, so a Windows excluded-range
/// failure surfaces as a `ProxyError::Plugin` (oneshot timeout / exit
/// before ready) rather than an `io::Error`, and `is_bind_race` cannot
/// classify it. Plugin failures are converted to `io::Error::other`
/// (non-bind-race), which `bind_with_retry` propagates immediately.
/// `free_port`'s internal probe-side retry covers the practical
/// exposure. See bindreams/hole#285 §"Where the fix actually lands".
pub async fn start_plugin_chain(
    plugin_name: &str,
    plugin_path: &str,
    plugin_opts: Option<&str>,
    server_host: &str,
    server_port: u16,
    state_dir: Option<&Path>,
) -> Result<PluginChain, ProxyError> {
    // Inject a debug-level log directive into the plugin's
    // SS_PLUGIN_OPTIONS unconditionally — Hole owns plugin stderr (it's
    // captured into `bridge.log` by `garter::binary`) and filters it via
    // `HOLE_BRIDGE_LOG`, so the cost of always-on debug logs is paid by
    // log-volume, not user UX. The diagnostic value (catching
    // plugin-side handshake / dial / WebSocket failures) is high.
    //
    // Per-plugin syntax differs; for plugins we don't have a known
    // directive for, the options pass through unchanged.
    let merged_opts = inject_plugin_debug_logging(plugin_name, plugin_opts);
    let protocols = plugin_protocols(plugin_name);

    let (_port, (handle, cancel, ready_addr)) = port_alloc::bind_with_retry(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        protocols,
        port_alloc::BIND_RETRY_ATTEMPTS,
        |port| {
            // The Fn closure cannot move `merged_opts` (owned String) into
            // an `async move`; clone per attempt instead. `&str`/`&Path`
            // arguments are Copy and pass through unchanged.
            let merged_opts = merged_opts.clone();
            async move {
                let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
                spawn_plugin_runner_at(
                    plugin_name,
                    plugin_path,
                    merged_opts.as_deref(),
                    local_addr,
                    server_host,
                    server_port,
                    state_dir,
                )
                .await
                .map_err(proxy_err_to_io_err)
            }
        },
    )
    .await
    .map_err(|e| ProxyError::Plugin(format!("plugin chain start failed: {e}")))?;

    Ok(PluginChain {
        handle,
        cancel,
        local_addr: ready_addr,
        state_dir: state_dir.map(Path::to_path_buf),
    })
}

/// Single-attempt plugin-runner spawn. Constructs `BinaryPlugin`
/// (with optional `pid_sink`), wraps in `TapPlugin` when
/// `HOLE_BRIDGE_PLUGIN_TAP=1`, builds the `ChainRunner`, spawns it,
/// and awaits readiness with a 30-second timeout. On failure runs
/// `cancel.cancel(); handle.abort()` so a retried attempt by
/// `bind_with_retry` doesn't leak the previous attempt's task. On
/// success returns `(handle, cancel, ready_addr)` — the caller wraps
/// these in a [`PluginChain`].
async fn spawn_plugin_runner_at(
    plugin_name: &str,
    plugin_path: &str,
    merged_opts: Option<&str>,
    local_addr: SocketAddr,
    server_host: &str,
    server_port: u16,
    state_dir: Option<&Path>,
) -> Result<
    (
        tokio::task::JoinHandle<garter::Result<()>>,
        CancellationToken,
        SocketAddr,
    ),
    ProxyError,
> {
    let mut plugin = garter::BinaryPlugin::new(plugin_path, merged_opts);

    if let Some(dir) = state_dir {
        let dir = dir.to_path_buf();
        let sink: garter::PidSink = Arc::new(move |pid| {
            let start_time = crate::plugin_recovery::process_start_time(pid).unwrap_or(0);
            if let Err(e) = crate::plugin_state::append_record(
                &dir,
                crate::plugin_state::PluginRecord {
                    pid,
                    start_time_unix_ms: start_time,
                },
            ) {
                tracing::warn!(pid, error = %e, "failed to persist plugin PID to state file");
            }
        });
        plugin = plugin.pid_sink(sink);
    }

    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = oneshot::channel();

    let env = garter::PluginEnv {
        local_host: local_addr.ip(),
        local_port: local_addr.port(),
        remote_host: server_host.to_string(),
        remote_port: server_port,
        // Use the merged options here too so any environment-source path
        // for SS_PLUGIN_OPTIONS sees the same loglevel directive as the
        // direct `cmd.env` set in `BinaryPlugin::run`.
        plugin_options: merged_opts.map(String::from),
    };

    // #267: when `HOLE_BRIDGE_PLUGIN_TAP=1` is set, wrap the plugin in a
    // counting tap so per-connection byte flow becomes visible in
    // `bridge.log` (`bytes_to_plugin`, `bytes_from_plugin`, `ttfb_ms`,
    // `close_kind`). Dev-mode only — env vars do not survive into
    // SCM/launchd service contexts. Off by default; the extra loopback
    // hop is cheap on debug-mode reproduction but inappropriate at
    // browser-traffic scale.
    let plugin: Box<dyn garter::ChainPlugin> = if std::env::var_os("HOLE_BRIDGE_PLUGIN_TAP").is_some() {
        tracing::info!(
            plugin = plugin_name,
            "HOLE_BRIDGE_PLUGIN_TAP=1: wrapping plugin in TapPlugin"
        );
        Box::new(garter::TapPlugin::wrap(Box::new(plugin)))
    } else {
        Box::new(plugin)
    };

    let runner = garter::ChainRunner::new()
        .add(plugin)
        .cancel_token(cancel.clone())
        .on_ready(ready_tx);

    let handle = tokio::spawn(async move { runner.run(env).await });

    let ready_addr = match tokio::time::timeout(READINESS_TIMEOUT, ready_rx).await {
        Ok(Ok(addr)) => addr,
        Ok(Err(_)) => {
            cancel.cancel();
            handle.abort();
            return Err(ProxyError::Plugin("plugin exited before becoming ready".into()));
        }
        Err(_) => {
            cancel.cancel();
            handle.abort();
            return Err(ProxyError::Plugin("plugin did not become ready within 30s".into()));
        }
    };

    Ok((handle, cancel, ready_addr))
}

/// Convert a [`ProxyError`] from `spawn_plugin_runner_at` into a
/// non-bind-race [`io::Error`] so [`port_alloc::bind_with_retry`]
/// propagates it immediately. Plugin failures (subprocess exit before
/// ready, readiness timeout) are not bind races we can deterministically
/// retry through; only `free_port`'s own probe failures (already
/// retried inside `bind_with_retry`) trigger the outer retry.
///
/// `spawn_plugin_runner_at` only emits `ProxyError::Plugin`; the
/// `unreachable!` arm is the contract guard. Future contributors who
/// add new variants must update this site to map them appropriately.
fn proxy_err_to_io_err(e: ProxyError) -> std::io::Error {
    match e {
        ProxyError::Plugin(msg) => std::io::Error::other(msg),
        other => unreachable!("spawn_plugin_runner_at only emits ProxyError::Plugin, got: {other}"),
    }
}

/// Append a debug-level log directive to a plugin's `SS_PLUGIN_OPTIONS`
/// when the directive shape is known for that plugin.
///
/// Hole captures plugin stderr via `garter::binary` and routes it through
/// the bridge's tracing subscriber, so the cost of always-on plugin
/// debug logs is paid in `bridge.log` volume rather than user-visible
/// noise. The diagnostic value (catching plugin-side handshake / dial /
/// WebSocket failures) is high — the lack of plugin diagnostics has
/// been the recurring blocker on #248-class tunnel issues.
///
/// Per-plugin syntax differs:
///
/// - **`v2ray-plugin`**: appends `loglevel=debug` (semicolon-separated;
///   v2ray-plugin honors the LAST occurrence of any duplicate key, so a
///   user's earlier `loglevel=warning` still loses to our debug).
/// - Anything else: pass through unchanged. (`galoshes` is a Rust
///   `ChainPlugin` and not started via this binary path; future binary
///   plugins can be added here.)
fn inject_plugin_debug_logging(plugin_name: &str, opts: Option<&str>) -> Option<String> {
    match plugin_name {
        "v2ray-plugin" => Some(append_sip003_directive(opts, "loglevel=debug")),
        _ => opts.map(String::from),
    }
}

/// Append a `key=value` directive to a SIP003-style options string,
/// inserting the `;` separator when needed. An empty / `None` input
/// becomes just the directive.
fn append_sip003_directive(opts: Option<&str>, directive: &str) -> String {
    match opts {
        None | Some("") => directive.to_string(),
        Some(existing) => {
            let trimmed = existing.trim_end_matches(';');
            format!("{trimmed};{directive}")
        }
    }
}

#[cfg(test)]
mod inject_tests {
    use super::*;

    #[skuld::test]
    fn v2ray_plugin_no_opts_gets_loglevel_debug() {
        assert_eq!(
            inject_plugin_debug_logging("v2ray-plugin", None).as_deref(),
            Some("loglevel=debug")
        );
    }

    #[skuld::test]
    fn v2ray_plugin_existing_opts_get_loglevel_appended() {
        assert_eq!(
            inject_plugin_debug_logging("v2ray-plugin", Some("host=example.com;path=/foo")).as_deref(),
            Some("host=example.com;path=/foo;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn v2ray_plugin_user_loglevel_warning_overridden_by_appended_debug() {
        // v2ray-plugin honors the LAST occurrence; appended debug wins.
        assert_eq!(
            inject_plugin_debug_logging("v2ray-plugin", Some("loglevel=warning;path=/foo")).as_deref(),
            Some("loglevel=warning;path=/foo;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn v2ray_plugin_trailing_semicolon_collapsed() {
        assert_eq!(
            inject_plugin_debug_logging("v2ray-plugin", Some("host=example.com;")).as_deref(),
            Some("host=example.com;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn v2ray_plugin_empty_string_treated_as_no_opts() {
        assert_eq!(
            inject_plugin_debug_logging("v2ray-plugin", Some("")).as_deref(),
            Some("loglevel=debug")
        );
    }

    #[skuld::test]
    fn unknown_plugin_passes_through_unchanged() {
        assert_eq!(
            inject_plugin_debug_logging("some-future-plugin", Some("k=v")).as_deref(),
            Some("k=v")
        );
        assert_eq!(inject_plugin_debug_logging("some-future-plugin", None), None);
    }
}

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod plugin_tests;
