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

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use util::port_alloc;

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
    /// Transports the live chain reported via its sitrep `ready` message —
    /// the end-to-end intersection across every hop. The UDP-drop policy in
    /// `proxy_manager.rs` reads this as the authoritative runtime signal.
    transports: garter::Transports,
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

    /// Transports the live chain reported via its sitrep `ready` message.
    /// The UDP-drop policy reads this to decide whether `Proxy`-routed UDP
    /// flows can be carried through the tunnel or must be dropped.
    pub fn transports(&self) -> garter::Transports {
        self.transports
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
/// the Windows cross-protocol excluded-port race. The config name is
/// first resolved to its on-disk binary name, then mapped via
/// [`hole_common::plugin::plugin_alloc_protocols`].
///
/// Allocates the handoff port via [`port_alloc::bind_ephemeral`]. The
/// plugin subprocess binds `local_addr` out-of-process, so its bind
/// failures arrive as `ProxyError::Plugin` (oneshot timeout / exit before
/// ready), are converted to `io::Error::other` (non-bind-race), and
/// propagate immediately. `bind_ephemeral`'s in-process probe step (run
/// before each `op` call) is what catches the Windows excluded-range
/// race class here, before the subprocess spawn. The residual
/// probe-drop-to-subprocess-bind TOCTOU is tracked in bindreams/hole#304.
#[allow(clippy::too_many_arguments)] // 8 args — bundling into a struct adds more noise than the warning; matches spawn_plugin_runner_at below.
pub async fn start_plugin_chain(
    plugin_name: &str,
    plugin_path: &str,
    plugin_opts: Option<&str>,
    server_host: &str,
    server_port: u16,
    state_dir: Option<&Path>,
    diagnostic_tap: bool,
    cancel: &CancellationToken,
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
    // Resolve the config name to its on-disk binary name before sizing the
    // handoff port — `plugin_alloc_protocols` is keyed by binary name so
    // `v2ray-plugin` (→ `ex-ray`) and unknown plugins get a TCP-only port
    // while galoshes gets a UDP-capable one (#414).
    let binary = hole_common::plugin::lookup(plugin_name)
        .map(|d| d.binary_name)
        .unwrap_or(plugin_name);
    let protocols = hole_common::plugin::plugin_alloc_protocols(binary);

    let (_port, (handle, cancel, ready_addr, transports)) =
        port_alloc::bind_ephemeral(IpAddr::V4(Ipv4Addr::LOCALHOST), protocols, |port| {
            // The Fn closure cannot move `merged_opts` (owned String) into
            // an `async move`; clone per attempt instead. `&str`/`&Path`
            // arguments are Copy and pass through unchanged.
            let merged_opts = merged_opts.clone();
            // Each attempt gets its own child token derived from the
            // bridge cancel: cancelling the bridge cancels every attempt;
            // a failed attempt that drops its child does not signal the
            // bridge or sibling retries.
            let attempt_cancel = cancel.child_token();
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
                    diagnostic_tap,
                    attempt_cancel,
                )
                .await
                .map_err(proxy_err_to_io_err)
            }
        })
        .await
        .map_err(|e| {
            // A cancel-attributed io::Error (from spawn_plugin_runner_at
            // observing the child token) re-surfaces as Cancelled so the
            // caller short-circuits cleanly instead of seeing
            // ProxyError::Plugin("...cancelled").
            if cancel.is_cancelled() {
                ProxyError::Cancelled
            } else {
                ProxyError::Plugin(format!("plugin chain start failed: {e}"))
            }
        })?;

    Ok(PluginChain {
        handle,
        cancel,
        local_addr: ready_addr,
        transports,
        state_dir: state_dir.map(Path::to_path_buf),
    })
}

/// Sourced gate for the plugin tap. The IPC config flag is the primary
/// knob (reaches service mode); the env var stays as the dev-shell
/// fallback for `scripts/dev.py` / hand-run `hole bridge run`.
#[derive(Debug, Clone, Copy)]
enum TapSource {
    Config,
    EnvVar,
    None,
}

impl std::fmt::Display for TapSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Config => "AppConfig.diagnostic_plugin_tap",
            Self::EnvVar => "HOLE_BRIDGE_PLUGIN_TAP env",
            Self::None => "off",
        })
    }
}

fn resolve_tap_source(diagnostic_tap: bool) -> TapSource {
    if diagnostic_tap {
        TapSource::Config
    } else if std::env::var_os("HOLE_BRIDGE_PLUGIN_TAP").is_some() {
        TapSource::EnvVar
    } else {
        TapSource::None
    }
}

/// Single-attempt plugin-runner spawn. Constructs `BinaryPlugin`
/// (with optional `pid_sink`), wraps in `TapPlugin` when
/// `HOLE_BRIDGE_PLUGIN_TAP=1`, builds the `ChainRunner`, spawns it,
/// and awaits readiness with a 30-second timeout. On failure runs
/// `cancel.cancel(); handle.abort()` so a retried attempt by
/// `bind_ephemeral` doesn't leak the previous attempt's task. On
/// success returns `(handle, cancel, ready_addr, transports)` — the
/// caller wraps these in a [`PluginChain`]. The `transports` is the
/// sitrep-reported end-to-end transport set (#414), threaded into the
/// bridge's UDP-drop policy.
///
/// A plugin `StartError::BindConflict` (the only retryable start class)
/// maps to [`ProxyError::BindRace`] so the outer `bind_ephemeral` retries
/// on a fresh port; a `StartError::Fatal` maps to [`ProxyError::Plugin`].
#[allow(clippy::too_many_arguments)] // 9 args — bundling into a struct adds more noise than the warning.
async fn spawn_plugin_runner_at(
    plugin_name: &str,
    plugin_path: &str,
    merged_opts: Option<&str>,
    local_addr: SocketAddr,
    server_host: &str,
    server_port: u16,
    state_dir: Option<&Path>,
    diagnostic_tap: bool,
    cancel: CancellationToken,
) -> Result<
    (
        tokio::task::JoinHandle<garter::Result<()>>,
        CancellationToken,
        SocketAddr,
        garter::Transports,
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

    // `cancel` is the externally-supplied child token from
    // `start_plugin_chain`. Cancelling the bridge's start cancel cancels
    // this token via the child link; PluginChain::Drop also cancels it
    // (subtree-only) so the chain's RAII teardown stays self-contained.
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

    // Wrap plugin in counting `TapPlugin` so per-TCP connection byte flow
    // + close-kind become visible in `bridge.log`. Two gates compose:
    //   - `AppConfig.diagnostic_plugin_tap` via `ProxyConfig` IPC field
    //     (reaches service mode).
    //   - `HOLE_BRIDGE_PLUGIN_TAP=1` env var (dev shell only — env vars
    //     don't survive into SCM/launchd contexts).
    // Off by default; the extra loopback hop is cheap on debug-mode
    // reproduction but inappropriate at browser-traffic scale.
    let tap_source = resolve_tap_source(diagnostic_tap);
    let plugin: Box<dyn garter::ChainPlugin> = if matches!(tap_source, TapSource::None) {
        Box::new(plugin)
    } else {
        tracing::info!(plugin = plugin_name, %tap_source, "wrapping plugin in TapPlugin");
        Box::new(garter::TapPlugin::wrap(Box::new(plugin)))
    };

    let runner = garter::ChainRunner::new()
        .add(plugin)
        .cancel_token(cancel.clone())
        .on_ready(ready_tx);

    let handle = tokio::spawn(async move { runner.run(env).await });

    // Race readiness against the bridge cancel: if the user cancels the
    // start mid-spawn, abort the partially-spawned chain and return
    // ProxyError::Cancelled so the caller short-circuits cleanly instead
    // of waiting up to READINESS_TIMEOUT for a chain it no longer wants.
    // `ready_rx` now yields `Result<ChainReady, StartError>` (per-plugin
    // readiness aggregated by the runner — #414); the timeout adds one
    // `Result` layer and the channel another. Flatten and extract the
    // chain-public listen address + reported transports.
    let chain_ready = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            handle.abort();
            return Err(ProxyError::Cancelled);
        }
        // sync-exception(external-event, CLAUDE.md class 2): READINESS_TIMEOUT is the
        // terminal failure-to-human bound for a plugin subprocess that may never become
        // ready (wedged child); it is NOT intra-process sync. Cooperative cancel via the
        // biased cancel arm above is the primary escape; this timeout only bounds the
        // genuinely-stuck case.
        r = tokio::time::timeout(READINESS_TIMEOUT, ready_rx) => match r {
            Ok(Ok(Ok(chain_ready))) => chain_ready,
            // The only retryable start class: a plugin reported it could
            // not bind its listener. Surface as `ProxyError::BindRace` so
            // `bind_ephemeral` (via `proxy_err_to_io_err`) retries on a
            // fresh port. The errno is preserved for `bridge.log`.
            Ok(Ok(Err(garter::StartError::BindConflict { errno, addr }))) => {
                cancel.cancel();
                handle.abort();
                return Err(ProxyError::BindRace { errno, addr });
            }
            // Terminal start failure (config error, upstream-dial failure,
            // bare process exit) — never retried.
            Ok(Ok(Err(garter::StartError::Fatal { detail, .. }))) => {
                cancel.cancel();
                handle.abort();
                return Err(ProxyError::Plugin(format!("plugin failed to start: {detail}")));
            }
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
        },
    };

    Ok((handle, cancel, chain_ready.listen, chain_ready.transports))
}

/// Convert a [`ProxyError`] from `spawn_plugin_runner_at` into an
/// [`io::Error`] so [`port_alloc::bind_ephemeral`] can classify it.
///
/// `spawn_plugin_runner_at` emits exactly three variants:
///
/// - [`ProxyError::BindRace`] (a plugin's `StartError::BindConflict`)
///   — synthesized into an `AddrInUse`-kind `io::Error` so
///   [`util::retry::is_bind_race`] classifies it as retryable and
///   `bind_ephemeral` allocates a fresh port. This is the load-bearing
///   case: a plugin that loses its local-port bind race gets retried
///   in-band like the in-process binders, instead of failing the start.
/// - [`ProxyError::Plugin`] (subprocess exit before ready, readiness
///   timeout, fatal start error) — a non-bind-race `io::Error::other`
///   so `bind_ephemeral` propagates it immediately. These are not bind
///   races we can in-band classify; the in-process probe step inside
///   `bind_ephemeral` already catches Windows excluded-range
///   disagreements before the subprocess spawn (stderr-based
///   classification of subprocess bind failures is bindreams/hole#304).
/// - [`ProxyError::Cancelled`] (bridge cancel observed mid-spawn)
///   — a non-bind-race `io::Error::other`; the outer `start_plugin_chain`
///   distinguishes it via `cancel.is_cancelled()` to re-emit the
///   canonical variant.
///
/// The `unreachable!` arm is the contract guard for any OTHER variant.
fn proxy_err_to_io_err(e: ProxyError) -> std::io::Error {
    match e {
        ProxyError::BindRace { errno, addr } => {
            // Synthesize an AddrInUse-kind io::Error DIRECTLY so is_bind_race
            // (which keys on ErrorKind, not raw_os_error) classifies it on
            // every OS regardless of the platform-native errno value
            // (errno 48 is AddrInUse on macOS but garbage on Windows). The
            // errno is preserved in the message for bridge.log diagnostics.
            std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("plugin bind conflict on {addr} (errno {errno})"),
            )
        }
        ProxyError::Plugin(msg) => std::io::Error::other(msg),
        ProxyError::Cancelled => std::io::Error::other("plugin spawn cancelled"),
        other => {
            unreachable!("spawn_plugin_runner_at only emits ProxyError::BindRace, ProxyError::Plugin, or ProxyError::Cancelled, got: {other}")
        }
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
/// - **`v2ray-plugin`** / **`ex-ray`**: appends `loglevel=debug`
///   (semicolon-separated). Both honor the LAST occurrence of any
///   duplicate key (same v2ray-core log config), so a user's earlier
///   `loglevel=warning` still loses to our debug. The friendly wire name
///   `v2ray-plugin` resolves to the first-party `ex-ray` binary
///   (`hole_common::plugin`), but a config may also name `ex-ray`
///   directly; this arm covers both spellings (#414).
/// - Anything else: pass through unchanged. (`galoshes` is a Rust
///   `ChainPlugin` and not started via this binary path; future binary
///   plugins can be added here.)
fn inject_plugin_debug_logging(plugin_name: &str, opts: Option<&str>) -> Option<String> {
    match plugin_name {
        "v2ray-plugin" | "ex-ray" => Some(append_sip003_directive(opts, "loglevel=debug")),
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
    fn ex_ray_no_opts_gets_loglevel_debug() {
        assert_eq!(
            inject_plugin_debug_logging("ex-ray", None).as_deref(),
            Some("loglevel=debug")
        );
    }

    #[skuld::test]
    fn ex_ray_existing_opts_get_loglevel_appended() {
        assert_eq!(
            inject_plugin_debug_logging("ex-ray", Some("host=example.com;path=/foo")).as_deref(),
            Some("host=example.com;path=/foo;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn ex_ray_user_loglevel_warning_overridden_by_appended_debug() {
        // ex-ray uses the same v2ray-core log config: it honors the LAST
        // occurrence; appended debug wins.
        assert_eq!(
            inject_plugin_debug_logging("ex-ray", Some("loglevel=warning;path=/foo")).as_deref(),
            Some("loglevel=warning;path=/foo;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn ex_ray_trailing_semicolon_collapsed() {
        assert_eq!(
            inject_plugin_debug_logging("ex-ray", Some("host=example.com;")).as_deref(),
            Some("host=example.com;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn ex_ray_empty_string_treated_as_no_opts() {
        assert_eq!(
            inject_plugin_debug_logging("ex-ray", Some("")).as_deref(),
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
