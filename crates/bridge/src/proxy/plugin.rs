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
#[allow(clippy::too_many_arguments)] // bundling into a struct adds more noise than the warning; matches spawn_plugin_runner_at below.
pub async fn start_plugin_chain(
    plugin_name: &str,
    plugin_path: &str,
    plugin_opts: Option<&str>,
    server_host: &str,
    server_port: u16,
    state_dir: Option<&Path>,
    owner: Option<(u32, u32)>,
    diagnostic_tap: bool,
    cancel: &CancellationToken,
    ech_doh: Option<&crate::dns::ech::EchDoh>,
) -> Result<PluginChain, ProxyError> {
    // Inject Hole-owned SIP003 directives — see `inject_plugin_directives`.
    let merged_opts = inject_plugin_directives(plugin_name, plugin_opts, ech_doh)?;
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
                    owner,
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
/// fallback for dev-console / hand-run `hole bridge run`.
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
#[allow(clippy::too_many_arguments)] // 10 args — bundling into a struct adds more noise than the warning.
async fn spawn_plugin_runner_at(
    plugin_name: &str,
    plugin_path: &str,
    merged_opts: Option<&str>,
    local_addr: SocketAddr,
    server_host: &str,
    server_port: u16,
    state_dir: Option<&Path>,
    owner: Option<(u32, u32)>,
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
    let mut plugin = garter::BinaryPlugin::new(plugin_path, merged_opts).readiness(readiness_for(plugin_name));

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
                owner,
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

/// Remove any existing copy of a key Hole is about to set, then append it.
/// ex-ray's `Args.Get` is first-wins, so an appended duplicate would silently
/// lose to a user's, and postern writes `ech-doh` before Hole ever sees the
/// string. `ech` is never touched: `ech=always` sets `RequireEch`, and dropping
/// a user's mode would silently downgrade a deliberate fail-closed posture.
///
/// Only the v2ray-family plugins receive these: `v2ray-plugin` resolves to the
/// first-party `ex-ray` binary, but a config may also name `ex-ray` directly,
/// so both spellings are covered; `galoshes` ignores the keys itself but
/// forwards the whole options string to its inner ex-ray.
fn inject_plugin_directives(
    plugin_name: &str,
    opts: Option<&str>,
    ech_doh: Option<&crate::dns::ech::EchDoh>,
) -> Result<Option<String>, ProxyError> {
    match plugin_name {
        "v2ray-plugin" | "ex-ray" | "galoshes" => {
            let opts = opts.unwrap_or_default();
            // Refuse rather than forward — see `ProxyError::MalformedPluginOptions`.
            // Position only in the message; a segment can carry a secret.
            let segments = garter::split_plugin_options(opts)
                .map_err(|e| ProxyError::MalformedPluginOptions(format!("{plugin_name}: {e}")))?;

            let config_ech_doh = segments.iter().find(|s| s.key == "ech-doh");
            // Hole's URL is name-free, so it displaces one whose authority is a
            // name — that lookup is the defect. Against an IP-literal value there
            // is no leak to fix, so only a resolver that ANSWERED outranks the
            // operator's own choice.
            let displaces = match (ech_doh, config_ech_doh) {
                (Some(e), Some(s)) => e.pinned || crate::dns::ech::authority_is_a_name(&s.value),
                _ => false,
            };
            // Strip only what we are about to set, so an override never becomes
            // a deletion. Keys compare as the PLUGIN decodes them.
            let owned: &[&str] = if displaces {
                &["loglevel", "ech-doh"]
            } else {
                &["loglevel"]
            };

            // Which ECH source won, and how much is known about it. Every outcome
            // reaches ex-ray as one URL, so this is the only record of the choice.
            let fail_closed = segments.iter().any(|s| s.key == "ech" && s.value == "always");
            match (ech_doh, config_ech_doh) {
                // Ours yields: theirs already names an IP, and nothing here
                // demonstrated that our resolver answers.
                (Some(_), Some(s)) if !displaces => tracing::warn!(
                    plugin = %plugin_name,
                    "no resolver answered, so the config's own name-free ech-doh stands: {}", s.raw
                ),
                // Ours is what the plugin will fetch from, but no resolver
                // answered the bootstrap, so nothing has demonstrated it works.
                (Some(e), _) if !e.pinned => tracing::warn!(
                    plugin = %plugin_name, fail_closed,
                    "no resolver answered; the ECH lookup falls back to an unverified resolver: {}", e.url
                ),
                (Some(_), _) => {}
                // Stripping this would disarm ECH altogether, so it stands — but
                // a name authority is resolved over plaintext system DNS.
                (None, Some(s)) => tracing::warn!(
                    plugin = %plugin_name,
                    "no configured resolver to pin the ECH lookup to; the config's own ech-doh stands: {}", s.raw
                ),
                // ECH is armed only by `ech-doh`, so there is none. Under
                // `ech=always` ex-ray refuses to start over exactly this.
                (None, None) => tracing::warn!(
                    plugin = %plugin_name,
                    fail_closed,
                    "no ech-doh from any source; ECH is off"
                ),
            }

            let directive = ech_doh.map(|e| format!("ech-doh={}", e.url));

            Ok(Some(garter::join_plugin_options(
                segments
                    .iter()
                    .filter(|s| !owned.contains(&s.key.as_str()))
                    .map(|s| s.raw)
                    .chain(["loglevel=debug"])
                    .chain(directive.as_deref()),
            )))
        }
        _ => Ok(opts.map(String::from)),
    }
}

/// Plugin-readiness mode for the spawn.
///
/// Bundled plugins (galoshes, ex-ray / v2ray-plugin) speak the sitrep
/// handshake, so [`ReadinessMode::ExpectSitrep`] reads their AUTHORITATIVE
/// transports — the UDP-drop policy needs `tcp,udp` from galoshes, which the
/// `Probe` self-probe (a TCP connect, hardcoded TCP-only) would discard (#536).
/// An unknown plugin (an arbitrary binary resolved via PATH — see
/// [`resolve_plugin_path`] / #414) may not speak sitrep, so it keeps the
/// conservative `Probe` readiness rather than hanging until the readiness
/// timeout waiting for a sitrep that never comes.
///
/// [`ReadinessMode::ExpectSitrep`]: garter::ReadinessMode::ExpectSitrep
fn readiness_for(plugin_name: &str) -> garter::ReadinessMode {
    if hole_common::plugin::is_known(plugin_name) {
        garter::ReadinessMode::ExpectSitrep
    } else {
        garter::ReadinessMode::Probe
    }
}

#[cfg(test)]
mod inject_tests {
    use super::*;
    use crate::dns::ech::EchDoh;

    /// The merged options, or panic — for inputs that are not testing rejection.
    fn merged(plugin: &str, opts: Option<&str>, ech_doh: Option<&EchDoh>) -> Option<String> {
        inject_plugin_directives(plugin, opts, ech_doh).expect("well-formed options")
    }

    /// An `ech-doh` naming a resolver that ANSWERED the bootstrap.
    fn pinned(url: &str) -> EchDoh {
        EchDoh {
            url: url.to_string(),
            pinned: true,
        }
    }

    /// An `ech-doh` Hole guessed because no resolver answered.
    fn unpinned(url: &str) -> EchDoh {
        EchDoh {
            url: url.to_string(),
            pinned: false,
        }
    }

    #[skuld::test]
    fn v2ray_plugin_no_opts_gets_loglevel_debug() {
        assert_eq!(merged("v2ray-plugin", None, None).as_deref(), Some("loglevel=debug"));
    }

    #[skuld::test]
    fn v2ray_plugin_existing_opts_get_loglevel_appended() {
        assert_eq!(
            merged("v2ray-plugin", Some("host=example.com;path=/foo"), None).as_deref(),
            Some("host=example.com;path=/foo;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn v2ray_plugin_user_loglevel_is_removed_not_shadowed() {
        // `Args.Get` is first-wins, so an appended duplicate would lose.
        assert_eq!(
            merged("v2ray-plugin", Some("loglevel=warning;path=/foo"), None).as_deref(),
            Some("path=/foo;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn v2ray_plugin_trailing_semicolon_collapsed() {
        assert_eq!(
            merged("v2ray-plugin", Some("host=example.com;"), None).as_deref(),
            Some("host=example.com;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn v2ray_plugin_empty_string_treated_as_no_opts() {
        assert_eq!(
            merged("v2ray-plugin", Some(""), None).as_deref(),
            Some("loglevel=debug")
        );
    }

    #[skuld::test]
    fn ex_ray_no_opts_gets_loglevel_debug() {
        assert_eq!(merged("ex-ray", None, None).as_deref(), Some("loglevel=debug"));
    }

    #[skuld::test]
    fn ex_ray_existing_opts_get_loglevel_appended() {
        assert_eq!(
            merged("ex-ray", Some("host=example.com;path=/foo"), None).as_deref(),
            Some("host=example.com;path=/foo;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn ex_ray_user_loglevel_is_removed_not_shadowed() {
        assert_eq!(
            merged("ex-ray", Some("loglevel=warning;path=/foo"), None).as_deref(),
            Some("path=/foo;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn ex_ray_trailing_semicolon_collapsed() {
        assert_eq!(
            merged("ex-ray", Some("host=example.com;"), None).as_deref(),
            Some("host=example.com;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn ex_ray_empty_string_treated_as_no_opts() {
        assert_eq!(merged("ex-ray", Some(""), None).as_deref(), Some("loglevel=debug"));
    }

    #[skuld::test]
    fn galoshes_existing_opts_get_loglevel_appended() {
        // galoshes ignores `loglevel` itself but forwards the whole options
        // string to its inner ex-ray, so the directive reaches that hop.
        assert_eq!(
            merged("galoshes", Some("host=cloudfront.com;path=/"), None).as_deref(),
            Some("host=cloudfront.com;path=/;loglevel=debug"),
        );
    }

    #[skuld::test]
    fn unknown_plugin_passes_through_unchanged() {
        assert_eq!(merged("some-future-plugin", Some("k=v"), None).as_deref(), Some("k=v"));
        assert_eq!(merged("some-future-plugin", None, None), None);
    }

    #[skuld::test]
    fn v2ray_plugin_gets_ech_doh_after_loglevel() {
        let out = merged(
            "v2ray-plugin",
            Some("host=example.com"),
            Some(&pinned("https://1.1.1.1/dns-query")),
        );
        assert_eq!(
            out.as_deref(),
            Some("host=example.com;loglevel=debug;ech-doh=https://1.1.1.1/dns-query"),
        );
    }

    #[skuld::test]
    fn galoshes_gets_ech_doh() {
        let out = merged("galoshes", None, Some(&pinned("https://dns.google/dns-query")));
        assert_eq!(
            out.as_deref(),
            Some("loglevel=debug;ech-doh=https://dns.google/dns-query")
        );
    }

    #[skuld::test]
    fn ex_ray_gets_ech_doh() {
        let out = merged("ex-ray", Some("path=/x"), Some(&pinned("https://9.9.9.9/dns-query")));
        assert_eq!(
            out.as_deref(),
            Some("path=/x;loglevel=debug;ech-doh=https://9.9.9.9/dns-query")
        );
    }

    #[skuld::test]
    fn no_ech_doh_url_appends_only_loglevel() {
        let out = merged("ex-ray", Some("path=/x"), None);
        assert_eq!(out.as_deref(), Some("path=/x;loglevel=debug"));
    }

    #[skuld::test]
    fn unknown_plugin_passes_through_even_with_ech_doh() {
        let out = merged(
            "some-future-plugin",
            Some("k=v"),
            Some(&pinned("https://1.1.1.1/dns-query")),
        );
        assert_eq!(out.as_deref(), Some("k=v"));
    }

    // The production shape: postern appends `;ech=<mode>;ech-doh=<url>` before
    // Hole sees the string, so a Hole URL that merely followed it would lose.
    #[skuld::test]
    fn a_postern_style_ech_doh_is_replaced_by_holes() {
        let out = merged(
            "v2ray-plugin",
            Some("host=example.com;tls;ech=always;ech-doh=https://cloudflare-dns.com/dns-query"),
            Some(&pinned("https://1.1.1.1/dns-query")),
        );
        assert_eq!(
            out.as_deref(),
            Some("host=example.com;tls;ech=always;loglevel=debug;ech-doh=https://1.1.1.1/dns-query"),
        );
    }

    // Hole injects no `ech`, so it removes none: `ech=always` sets RequireEch,
    // which aborts a dial rather than completing a cleartext-SNI handshake.
    #[skuld::test]
    fn a_user_ech_mode_survives_untouched() {
        for mode in ["always", "auto", "never"] {
            let out = merged("ex-ray", Some(&format!("ech={mode}")), None);
            assert_eq!(out.as_deref(), Some(&*format!("ech={mode};loglevel=debug")));
        }
    }

    // With no URL to put in its place, removing the user's source would leave
    // ECH with none at all — an override overrides, it does not delete.
    #[skuld::test]
    fn a_user_ech_doh_survives_when_hole_has_no_url() {
        let out = merged("ex-ray", Some("ech-doh=https://example.net/dns-query"), None);
        assert_eq!(
            out.as_deref(),
            Some("ech-doh=https://example.net/dns-query;loglevel=debug"),
        );
    }

    // Unpinned, Hole's URL is a guess — on a failed bootstrap, a resolver that
    // just failed — so a config value that is ALREADY name-free keeps first-wins
    // precedence: there is no plaintext lookup to remove by displacing it.
    #[skuld::test]
    fn an_unpinned_url_yields_to_a_name_free_config_value() {
        for their_url in ["https://8.8.8.8/dns-query", "https://[2620:fe::fe]/dns-query"] {
            let out = merged(
                "ex-ray",
                Some(&format!("ech-doh={their_url}")),
                Some(&unpinned("https://1.1.1.1/dns-query")),
            );
            assert_eq!(
                out.as_deref(),
                Some(&*format!(
                    "ech-doh={their_url};loglevel=debug;ech-doh=https://1.1.1.1/dns-query"
                )),
            );
        }
    }

    // The cohort a pin-only rule would miss: a literal-IP server entry needs no
    // bootstrap query, so nothing is pinned — yet postern's hostname URL would
    // still win under first-wins and cost the plaintext lookup #694 is about.
    #[skuld::test]
    fn an_unpinned_url_still_displaces_a_name_config_value() {
        let out = merged(
            "ex-ray",
            Some("ech=always;ech-doh=https://cloudflare-dns.com/dns-query"),
            Some(&unpinned("https://1.1.1.1/dns-query")),
        );
        assert_eq!(
            out.as_deref(),
            Some("ech=always;loglevel=debug;ech-doh=https://1.1.1.1/dns-query"),
        );
    }

    // With nothing to lose to, an unpinned guess is still the only ECH source
    // there is, so it is injected.
    #[skuld::test]
    fn an_unpinned_url_is_injected_when_the_config_carries_none() {
        let out = merged("ex-ray", Some("path=/x"), Some(&unpinned("https://1.1.1.1/dns-query")));
        assert_eq!(
            out.as_deref(),
            Some("path=/x;loglevel=debug;ech-doh=https://1.1.1.1/dns-query"),
        );
    }

    // Only whole keys are matched — a key that merely starts with an owned one
    // belongs to the user.
    #[skuld::test]
    fn a_key_that_merely_prefixes_an_owned_one_is_kept() {
        let out = merged("ex-ray", Some("ech-doh-backup=x;loglevelly=y"), None);
        assert_eq!(out.as_deref(), Some("ech-doh-backup=x;loglevelly=y;loglevel=debug"));
    }

    // Values pass through byte-identically: an escaped `;` is part of the value,
    // never a separator, and nothing re-escapes it.
    #[skuld::test]
    fn an_escaped_semicolon_in_a_value_is_preserved() {
        let out = merged("ex-ray", Some(r"path=/a\;b;loglevel=warning"), None);
        assert_eq!(out.as_deref(), Some(r"path=/a\;b;loglevel=debug"));
    }

    // A value ending in an escaped `;` still gets its own separator, so the
    // appended directive is not swallowed into that value.
    #[skuld::test]
    fn a_value_ending_in_an_escaped_semicolon_still_separates() {
        let out = merged("ex-ray", Some(r"path=/a\;"), None);
        assert_eq!(out.as_deref(), Some(r"path=/a\;;loglevel=debug"));
    }

    // A key is stripped by the name the PLUGIN reads, not the name a narrower
    // unescaper reports: `ech\-doh` IS `ech-doh` to ex-ray, and leaving it would
    // let a user-supplied hostname URL win under first-wins.
    #[skuld::test]
    fn an_escaped_spelling_of_an_owned_key_is_still_stripped() {
        let out = merged(
            "ex-ray",
            Some(r"ech\-doh=https://evil.example/dns-query;log\level=warning"),
            Some(&pinned("https://9.9.9.9/dns-query")),
        );
        assert_eq!(out.as_deref(), Some("loglevel=debug;ech-doh=https://9.9.9.9/dns-query"),);
    }

    // ex-ray discards the whole SS_* environment on a parse error and reports
    // `ready` on its default port, so forwarding these would produce a dead
    // tunnel that looks healthy. Refuse the start instead.
    #[skuld::test]
    fn malformed_options_fail_the_start() {
        for opts in [r"path=/a\", "host=h;=v;mux=0", "a=1;;b=2"] {
            let err = inject_plugin_directives("ex-ray", Some(opts), Some(&pinned("https://1.1.1.1/dns-query")))
                .expect_err("malformed options must not reach the plugin");
            assert!(
                matches!(err, ProxyError::MalformedPluginOptions(_)),
                "expected MalformedPluginOptions for {opts:?}, got {err:?}"
            );
            // The segment can carry a per-connection secret; only its position
            // and the fault class are reportable.
            let msg = err.to_string();
            assert!(
                !msg.contains("/a") && !msg.contains("mux"),
                "message leaks option contents: {msg}"
            );
        }
    }

    // A bare key must stay bare: ex-ray reads a bare key as "1" but `key=` as
    // "", so rewriting one into the other corrupts the value.
    #[skuld::test]
    fn bare_and_valued_keys_keep_their_written_form() {
        let out = merged("ex-ray", Some("tls;mux;path="), None);
        assert_eq!(out.as_deref(), Some("tls;mux;path=;loglevel=debug"));
    }

    #[skuld::test]
    fn galoshes_user_duplicates_are_removed_too() {
        // galoshes ignores these keys but forwards the whole string to its inner
        // ex-ray, so a duplicate would win at that hop.
        let out = merged(
            "galoshes",
            Some("loglevel=warning;ech-doh=https://stale.example/dns-query"),
            Some(&pinned("https://9.9.9.9/dns-query")),
        );
        assert_eq!(out.as_deref(), Some("loglevel=debug;ech-doh=https://9.9.9.9/dns-query"),);
    }

    // An unknown plugin gets no injection, so it gets no strip either.
    #[skuld::test]
    fn unknown_plugin_keeps_its_own_loglevel() {
        assert_eq!(
            merged(
                "some-future-plugin",
                Some("loglevel=warning"),
                Some(&pinned("https://1.1.1.1/dns-query")),
            )
            .as_deref(),
            Some("loglevel=warning"),
        );
    }

    // The full bridge-side path for a postern-issued config: derive the URL from
    // the resolver that answered, then inject it over postern's own. Neither unit
    // test would catch the two being wired together wrongly.
    #[skuld::test]
    fn a_postern_config_composes_into_holes_pinned_url() {
        use std::net::IpAddr;

        use hole_common::config::DnsConfig;

        use crate::dns::ech::{ech_doh_url, PinSource};

        let answering: IpAddr = "9.9.9.9".parse().expect("test IP literal");
        let dns = DnsConfig {
            servers: vec!["1.1.1.1".parse().expect("test IP literal"), answering],
            ..Default::default()
        };
        let ech_doh = ech_doh_url(&dns, PinSource::Answered(answering)).expect("a resolver is configured");

        let out = merged(
            "v2ray-plugin",
            Some("mode=websocket;host=cdn.example;tls;ech=always;ech-doh=https://cloudflare-dns.com/dns-query"),
            Some(&ech_doh),
        );

        assert_eq!(
            out.as_deref(),
            Some("mode=websocket;host=cdn.example;tls;ech=always;loglevel=debug;ech-doh=https://9.9.9.9/dns-query"),
        );
    }

    #[skuld::test]
    fn readiness_known_plugins_expect_sitrep_unknown_probes() {
        use garter::ReadinessMode;
        // Bundled, sitrep-speaking plugins: authoritative transports.
        assert_eq!(readiness_for("galoshes"), ReadinessMode::ExpectSitrep);
        assert_eq!(readiness_for("v2ray-plugin"), ReadinessMode::ExpectSitrep);
        assert_eq!(readiness_for("ex-ray"), ReadinessMode::ExpectSitrep);
        // Arbitrary PATH plugin (may not speak sitrep): conservative probe.
        assert_eq!(readiness_for("some-future-plugin"), ReadinessMode::Probe);
    }
}

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod plugin_tests;
