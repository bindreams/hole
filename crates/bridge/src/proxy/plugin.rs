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
    log: Arc<crate::proxy::plugin_log::PluginLog>,
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

    /// The chain's kept log lines — see [`crate::proxy::plugin_log`].
    pub fn log(&self) -> &Arc<crate::proxy::plugin_log::PluginLog> {
        &self.log
    }

    /// Build a `PluginChain` around a pre-seeded log, with no real plugin
    /// subprocess behind it. For tests that need a genuinely `Some`
    /// `PluginChain` to prove a CALL SITE reads whatever `log()` returns —
    /// the spawn/readiness machinery itself is proven separately, against a
    /// real child, by `tests/plugin_chain.rs`. `cancel` is caller-supplied
    /// so this stays out of the disallowed-fresh-token lint (test callers
    /// carry the sanctioned module-level allow; this constructor does not
    /// need to).
    #[cfg(test)]
    pub(crate) fn for_test(log: Arc<crate::proxy::plugin_log::PluginLog>, cancel: CancellationToken) -> Self {
        Self {
            handle: tokio::spawn(async { Ok(()) }),
            cancel,
            local_addr: SocketAddr::from(([127, 0, 0, 1], 1)),
            transports: garter::Transports::TCP,
            state_dir: None,
            log,
        }
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
    // Built before `bind_ephemeral` so every bind-retry attempt feeds the same
    // ring — a losing attempt's output explains the retry.
    let log = crate::proxy::plugin_log::PluginLog::new();

    let (_port, (handle, cancel, ready_addr, transports)) =
        port_alloc::bind_ephemeral(IpAddr::V4(Ipv4Addr::LOCALHOST), protocols, |port| {
            // The Fn closure cannot move `merged_opts` (owned String) into
            // an `async move`; clone per attempt instead. `&str`/`&Path`
            // arguments are Copy and pass through unchanged.
            let merged_opts = merged_opts.clone();
            let log = Arc::clone(&log);
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
                    &log,
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
                return ProxyError::Cancelled;
            }
            // The chain never became a `PluginChain`, so nothing downstream can
            // reach its ring. "exited before becoming ready" and "did not become
            // ready within 30s" carry no detail of their own, and the plugin's
            // own last lines are the only account of why — emit them here, once,
            // after every bind retry has had its say.
            crate::proxy::plugin_log::warn_recent(&log);
            ProxyError::Plugin(format!("plugin chain start failed: {e}"))
        })?;

    Ok(PluginChain {
        handle,
        cancel,
        local_addr: ready_addr,
        transports,
        state_dir: state_dir.map(Path::to_path_buf),
        log,
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
#[allow(clippy::too_many_arguments)] // 11 args — bundling into a struct adds more noise than the warning.
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
    log: &Arc<crate::proxy::plugin_log::PluginLog>,
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
    // Before the tap wrap: `TapPlugin` delegates `run`, so the sink still fires.
    plugin = plugin.log_sink(log.sink());

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

/// Why no resolver is pinned, in the words of the reason itself — "no resolver
/// answered" is false for a literal server entry, where none was ever asked.
fn unpinned_reason(ech_doh: Option<&crate::dns::ech::EchDoh>) -> &'static str {
    use crate::dns::ech::PinSource;
    match ech_doh.map(|e| e.source) {
        Some(PinSource::NoQueryNeeded) => "the server entry is a literal IP, so no resolver was consulted",
        Some(PinSource::SecureBootstrapFailed) => "no configured resolver completed a DoH exchange",
        Some(PinSource::ResolverDeselected) => "the cached resolver is no longer configured",
        Some(PinSource::Answered(_)) | None => {
            debug_assert!(false, "unpinned_reason is only reached for an unpinned EchDoh");
            "no resolver is pinned"
        }
    }
}

/// The v2ray-family plugin names `inject_plugin_directives` rewrites
/// `ech-doh` for. `v2ray-plugin` resolves to the first-party `ex-ray` binary,
/// but a config may also name `ex-ray` directly, so both spellings are
/// covered; `galoshes` ignores the keys itself but forwards the whole options
/// string to its inner ex-ray. Every OTHER plugin name is passed through
/// `inject_plugin_directives` completely unmodified — no `ech-doh` is ever
/// injected, so nothing that plugin does can be influenced by Hole's ECH
/// derivation at all.
fn takes_ech_directives(plugin_name: &str) -> bool {
    matches!(plugin_name, "v2ray-plugin" | "ex-ray" | "galoshes")
}

/// Whether Hole's OWN `ech_doh` outranks (and should replace) an operator's
/// existing `ech-doh` value already present in `plugin_opts`: only a resolver
/// that ANSWERED the bootstrap, or a name-authority operator value carrying
/// the plaintext-DNS leak Hole's own pin exists to close. Against an
/// IP-literal operator value with an unpinned Hole guess, the operator's own
/// choice stands. The ONE formula both `inject_plugin_directives` (decides
/// whether to STRIP the operator's entry) and `ech_doh_will_reach_ex_ray`
/// (decides whether Hole's directive — appended either way — is what
/// actually reaches ex-ray) read, so the two can never silently disagree.
fn hole_ech_doh_outranks(ech_doh: &crate::dns::ech::EchDoh, config_value: &str) -> bool {
    ech_doh.is_pinned() || crate::dns::ech::authority_is_a_name(config_value)
}

/// Which `ech-doh` value (if any) will actually reach ex-ray once
/// `inject_plugin_directives` runs — computed ONCE inside it, so
/// `ProxyManager`'s cover-permit and residual-warning decisions and the
/// actual plugin spawn always agree on the same answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EffectiveEchDoh {
    /// A non-ECH-capable plugin, or an ECH-capable one with no `ech-doh`
    /// from any source — ECH is off, nothing will be fetched.
    None,
    /// Hole's own `ech_doh` is the value ex-ray will fetch.
    Holes,
    /// An OPERATOR's own `ech-doh` (already in `plugin_opts`, not displaced
    /// by Hole's) is the value ex-ray will fetch instead — carried so a
    /// caller can name the address in a diagnostic. Hole's fail-closed cover
    /// never permits an operator-chosen address: the permit rests on
    /// config-authorship trust — Hole itself authored the address (see
    /// `hole_bridge::dns::ech::EchDoh`'s doc) — and an operator-supplied
    /// address carries no such guarantee, so permitting it would be a real
    /// widening. A covered start with this outcome is therefore a disclosed
    /// residual: ex-ray will dial an address the cover does not permit and
    /// can stall.
    Operators(String),
}

/// Whether ex-ray will actually receive HOLE'S `ech_doh` as the winning
/// `ech-doh=` value once `inject_plugin_directives` runs on this exact
/// `(plugin_name, opts)` pair. Test-only: production code (`ProxyManager`)
/// reads the full [`EffectiveEchDoh`] off [`effective_ech_doh`] directly, so
/// it can ALSO warn about the `Operators` case — this bool-only view is a
/// convenience for tests that only care about the `Holes` outcome.
#[cfg(test)]
pub(crate) fn ech_doh_will_reach_ex_ray(
    plugin_name: &str,
    opts: Option<&str>,
    ech_doh: Option<&crate::dns::ech::EchDoh>,
) -> bool {
    matches!(effective_ech_doh(plugin_name, opts, ech_doh), EffectiveEchDoh::Holes)
}

/// Which `ech-doh` value ex-ray will actually dial for this exact
/// `(plugin_name, opts, ech_doh)` triple — a PURE query, no logging. Shares
/// [`classify_ech_doh`] with `inject_plugin_directives`, so the "will
/// something fetch an ECH config, and whose value" question and the actual
/// plugin spawn read the exact same parse and the exact same outrank
/// decision (they cannot drift the way two independent re-derivations of
/// `takes_ech_directives` + `hole_ech_doh_outranks` could), WITHOUT also
/// re-triggering `inject_plugin_directives`'s `tracing::warn!` calls: this
/// is queried once per start attempt from the permit-derivation path
/// (`ProxyManager::start_cancellable`), and the eventual plugin spawn calls
/// `inject_plugin_directives` again for real — calling that function here
/// too would double-emit every ECH-posture warning on every start. A
/// malformed `opts` string reads as `None` too — the same input that would
/// make `inject_plugin_directives` return `Err`, so the plugin chain never
/// starts and nothing ech-doh-shaped ever reaches ex-ray.
pub(crate) fn effective_ech_doh(
    plugin_name: &str,
    opts: Option<&str>,
    ech_doh: Option<&crate::dns::ech::EchDoh>,
) -> EffectiveEchDoh {
    if !takes_ech_directives(plugin_name) {
        return EffectiveEchDoh::None;
    }
    let Ok(segments) = garter::split_plugin_options(opts.unwrap_or_default()) else {
        return EffectiveEchDoh::None;
    };
    classify_ech_doh(&segments, ech_doh).0
}

/// ex-ray's own default for the `host` option
/// (`crates/ex-ray/config.go:45`: `flag.String("host", "cloudfront.com", ...)`)
/// — a real DOMAIN, not "no SNI". An absent `host` segment is NOT the same
/// as an unreachable config; see `ex_ray_default_host_matches_vendored_config_go`
/// for the executable pin against the vendored Go source (can't run the Go
/// code itself, but a text-level assertion still fails loudly if the
/// literal ever changes there without a matching edit here).
const EX_RAY_DEFAULT_HOST: &str = "cloudfront.com";

/// Whether ex-ray's own config-build step — `registerTCPKeepAlive` +
/// `generateConfig` (main.go:206-213,223-226,237-243), run before
/// `server.Start()` — would REJECT this segment set outright, in which case
/// the whole plugin process exits (23) before it dials anything at all,
/// ECH-config fetch included. Returns the rejecting key, first-wins
/// (matching `Args.Get`) among segments sharing a key, checked in ex-ray's
/// OWN evaluation order below so the diagnostic names the key ex-ray itself
/// would report first (the cover-permit / reachability side only needs
/// `.is_some()`, order-independent):
/// - `tcp-keepalive` (config.go's `tcpKeepAliveParams`): called from
///   `registerTCPKeepAlive` BEFORE `generateConfig` even starts, but only
///   in CLIENT mode — `registerTCPKeepAlive` returns early under `*server`
///   (config.go:153-155; the `server` residual below is why the ordering
///   claim above assumes client mode) — and called AGAIN, unconditionally
///   regardless of `*server`, inside `generateConfig` itself
///   (config.go:306-309). Either call: a value ex-ray's own `strconv.Atoi`
///   (main.go) parses successfully but that falls outside `0..=32767` is a
///   build error. A value `Atoi` fails to parse at all is NOT an error —
///   ex-ray logs a warning and silently keeps the default.
/// - `localPort`: `"0"` or `""` is rejected unconditionally, before
///   `generateConfig` even runs (main.go:223-226 — ex-ray cannot honor
///   port-0 OS-assignment). Otherwise `net.PortFromString` requires an
///   unsigned base-10 literal `<=65535`
///   (third_party/v2ray-core/common/net/port.go).
/// - `remotePort`: `strconv.ParseUint(s, 10, 32)` directly (config.go) — an
///   unsigned base-10 literal `<=u32::MAX`, with NO further upper bound
///   (ex-ray does not route it through `net.Port` at all).
/// - `mux`/`fwmark` (config.go's `uint32Opt`, called unconditionally at
///   config.go:260-267): a value that parses successfully but falls outside
///   `0..=u32::MAX` is a build error; a parse failure is not (same rule as
///   `tcp-keepalive`).
/// - `mode` is a CLOSED enum (`switch *mode`, config.go:279-297,
///   unconditional): outside `websocket`/`quic` is a build error.
/// - `ech` is a CLOSED enum too (`switch *echMode`, config.go:209-223), but
///   that switch lives INSIDE `buildTLSConfig`, called only `if
///   *tlsEnabled` (config.go:290-294,334) — an invalid value on a plain,
///   non-quic transport with no `tls` flag is never looked at, so it's
///   inert, not fatal (mirrors `ech_fetch_is_reachable`'s own
///   `tls_enabled`). Within that same switch, `ech=always` additionally
///   requires a non-empty RESOLVED `ech-doh` (config.go:218-220) — the
///   value ex-ray actually receives once Hole's own injection wins or loses
///   against the operator's; see [`resolved_ech_doh_is_empty`] for why that
///   is recomputed rather than shared with [`classify_ech_doh`].
/// - `mux`, again, but LATER than its own `uint32Opt` check above: once
///   `generateConfig` has fully succeeded, `core.New` (`buildV2Ray`,
///   main.go:143-149) separately rejects a non-zero `Concurrency` outside
///   `1..=1024` on the websocket transport ONLY
///   (third_party/v2ray-core/app/proxyman/outbound/handler.go:114-116) —
///   `quic`'s mux is never read (config.go:287-289's `connectionReuse`
///   only sets under `case "websocket"`).
///
/// **Disclosed, deliberately unmodeled:** `cert` requires filesystem I/O
/// this otherwise-pure gate doesn't perform; `server` cross-assigns
/// `localPort`/`remotePort` but Hole never spawns ex-ray as one. See
/// CONTRIBUTING.md's "ECH-config-fetch reachability gate" section for why.
fn ex_ray_fatal_config_error(
    segments: &[garter::OptionSegment<'_>],
    ech_doh: Option<&crate::dns::ech::EchDoh>,
) -> Option<&'static str> {
    if segments.iter().find(|s| s.key == "tcp-keepalive").is_some_and(|s| {
        ex_ray_flag_value(s)
            .parse::<i64>()
            .is_ok_and(|v| !(0..=32767).contains(&v))
    }) {
        return Some("tcp-keepalive");
    }
    if let Some(s) = segments.iter().find(|s| s.key == "localPort") {
        let v = ex_ray_flag_value(s);
        if v == "0" || v.is_empty() || !matches!(ex_ray_parses_as_uint32(v), Some(p) if p <= 65535) {
            return Some("localPort");
        }
    }
    if segments
        .iter()
        .find(|s| s.key == "remotePort")
        .is_some_and(|s| ex_ray_parses_as_uint32(ex_ray_flag_value(s)).is_none())
    {
        return Some("remotePort");
    }
    for key in ["mux", "fwmark"] {
        if segments.iter().find(|s| s.key == key).is_some_and(|s| {
            ex_ray_flag_value(s)
                .parse::<i64>()
                .is_ok_and(|v| v < 0 || v > i64::from(u32::MAX))
        }) {
            return Some(key);
        }
    }
    let mode = segments.iter().find(|s| s.key == "mode").map(ex_ray_flag_value);
    if let Some(v) = mode {
        if !matches!(v, "websocket" | "quic") {
            return Some("mode");
        }
    }
    let tls_enabled = segments.iter().any(|s| s.key == "tls") || mode == Some("quic");
    if tls_enabled {
        if let Some(s) = segments.iter().find(|s| s.key == "ech") {
            let v = ex_ray_flag_value(s);
            if !matches!(v, "never" | "auto" | "always") {
                return Some("ech");
            }
            if v == "always" && resolved_ech_doh_is_empty(segments, ech_doh) {
                return Some("ech-doh");
            }
        }
    }
    // Same 1..=1024 concurrency bound as the `mux` bullet above (core.New,
    // only on websocket, only when non-zero). The effective value defaults
    // to ex-ray's own flag default (`1`) unless a segment both exists AND
    // parses. `MultiplexSettings` is CLIENT-mode only (config.go:351-387 —
    // the `server` branch never builds it), so this check is skipped
    // alongside the rest of the disclosed, deliberately-unmodeled `server`
    // residual below, not a separate gap.
    if mode != Some("quic") && !segments.iter().any(|s| s.key == "server") {
        let mux = segments
            .iter()
            .find(|s| s.key == "mux")
            .and_then(|s| ex_ray_flag_value(s).parse::<i64>().ok())
            .unwrap_or(1);
        if mux != 0 && !(1..=1024).contains(&mux) {
            return Some("mux");
        }
    }
    None
}

/// The `ech-doh` value ex-ray will actually receive, reduced to just
/// "empty or not": the same precedence [`classify_ech_doh`] resolves for
/// its `effective` result (Hole's own URL wins when it outranks the
/// config's or none competes; otherwise the config's own, first-wins).
/// [`classify_ech_doh`] itself calls [`ech_fetch_is_reachable`], which calls
/// [`ex_ray_fatal_config_error`] — this is recomputed independently, from
/// the same segments and `ech_doh`, rather than threaded through, so that
/// path never cycles back through `classify_ech_doh`.
fn resolved_ech_doh_is_empty(
    segments: &[garter::OptionSegment<'_>],
    ech_doh: Option<&crate::dns::ech::EchDoh>,
) -> bool {
    let config_ech_doh = segments.iter().find(|s| s.key == "ech-doh");
    let displaces = ech_doh_displaces(segments, ech_doh);
    if let Some(e) = ech_doh.filter(|_| config_ech_doh.is_none() || displaces) {
        debug_assert!(
            !e.url.is_empty(),
            "EchDoh::url is never empty by construction (doh_url_for_ip) — if it ever is, this \
             arm would silently under-report ech=always as reachable"
        );
        false // Hole's own URL wins; always non-empty by construction.
    } else {
        config_ech_doh.map(ex_ray_flag_value).is_none_or(str::is_empty)
    }
}

/// Whether ex-ray's own port parser (`net.PortFromString`/`strconv.ParseUint`
/// for `localPort`/`remotePort`, base 10, 32-bit) would accept `v` — NOT the
/// same set Rust's `u32::from_str` accepts: Go's `ParseUint` rejects a
/// leading `+` (`"+8080"` is `invalid syntax`), while Rust's parser allows
/// one (`"+8080".parse::<u32>()` is `Ok(8080)`); verified against both
/// toolchains directly, not assumed. `v.parse()` alone would therefore
/// UNDER-report `ex_ray_fatal_config_error`'s port checks on a signed value
/// ex-ray itself rejects.
fn ex_ray_parses_as_uint32(v: &str) -> Option<u32> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse::<u32>().ok()
}

/// Whether ex-ray will even ATTEMPT an ECH-config fetch for this segment
/// set, independent of which `ech-doh` value would win. Neither the cover
/// permit, the residual-stall warning, nor `inject_plugin_directives`'s own
/// ECH-posture logging may treat a fetch that provably cannot happen as one
/// that will — four independent conditions, each first-wins (matching
/// `Args.Get`):
/// - [`ex_ray_fatal_config_error`] is `Some` — the whole plugin process
///   exits before it ever starts, so no dial of any kind happens.
/// - `ech=never` short-circuits ECH entirely before it ever looks at
///   `ech-doh` (crates/ex-ray/config.go:209-211).
/// - TLS must be enabled at all — an explicit `tls` flag, or `mode=quic`
///   forcing it on — since `buildTLSConfig` (which contains the whole `ech`
///   switch) is called only when `tlsEnabled` (config.go:290-294, 334); a
///   plain non-quic transport (e.g. `mode=websocket` with no `tls`) never
///   calls it.
/// - `ApplyECH` bails before dialing DoH unless the TLS `ServerName` is a
///   DOMAIN: ex-ray sets `tlsConfig.ServerName = *host` directly
///   (config.go:177), and an ABSENT `host` falls back to ex-ray's own
///   [`EX_RAY_DEFAULT_HOST`], a real domain, so it's reachable. An EXPLICIT
///   `host=<value>` wins outright, domain or not. But an EXPLICIT EMPTY
///   `host=` is NOT "no SNI": `Config.parseServerName` treats a
///   zero-length `ServerName` as absent (config.go:262 in the
///   third_party path, `len(sn) > 0`) and `tls.WithDestination` then fills
///   `ServerName` from the DIAL DESTINATION instead
///   (third_party/.../transport/internet/tls/config.go:371-382,
///   `websocket/dialer.go:67`) — and that destination is `remoteAddr`, a
///   `plugin_opts` option in its own right (main.go:102-108) that can be a
///   domain, first-wins same as every other key here. `remoteAddr` ABSENT
///   falls back to Hole's OWN `SS_REMOTE_HOST`, which this function cannot
///   see (env, not `plugin_opts`) — but is ALWAYS an IP literal in Hole's
///   own spawn path (`crate::proxy::plugin` never resolves a domain later
///   than `garter::binary::sip003_env`, which passes an already-resolved
///   `SocketAddr`), so an absent `remoteAddr` is correctly treated as "not
///   a domain" without needing to see it. Normalizing the IP-literal test
///   (for `host` directly, or the `remoteAddr` fallback alike) mirrors
///   v2ray-core's `net.ParseAddress` (only a MATCHED `[...]` pair is
///   stripped, once; whitespace is trimmed only when the first or last
///   byte is non-alphanumeric).
///   (third_party/v2ray-core/transport/internet/tls/ech.go:26-51,
///   config.go:250-264,296-303,371-382;
///   third_party/v2ray-core/common/net/address.go:78-95; main.go:67-69,
///   102-108).
///
/// **Disclosed, on the `remoteAddr` fallback only:** ex-ray applies
/// `ParseAddress` TWICE on that path — once building the dial destination
/// (`generateConfig`), once more computing the ECH domain from the
/// destination-derived `ServerName` — while this normalizes once. The two
/// disagree only for a value a SECOND unwrap would still change, e.g. a
/// doubly-bracketed `remoteAddr=[[::1]]` (one strip leaves `[::1]`, itself
/// still bracketed): this treats it as reachable, real ex-ray does not.
/// Modeling the second pass needs mirroring v2ray-core's `Domain`/`IP`
/// address-family round-trip (`net.NewIPOrDomain`), a materially larger
/// change than a fallback lookup; see CONTRIBUTING.md's "ECH-config-fetch
/// reachability gate" section.
///
/// Every flag read here goes through [`ex_ray_flag_value`] rather than
/// `OptionSegment::value` — see its doc. For `host` the divergence is
/// load-bearing — see `EX_RAY_DEFAULT_HOST`'s doc.
fn ech_fetch_is_reachable(segments: &[garter::OptionSegment<'_>], ech_doh: Option<&crate::dns::ech::EchDoh>) -> bool {
    if ex_ray_fatal_config_error(segments, ech_doh).is_some() {
        return false;
    }
    let ech = segments.iter().find(|s| s.key == "ech").map(ex_ray_flag_value);
    if ech == Some("never") {
        return false;
    }
    let mode = segments.iter().find(|s| s.key == "mode").map(ex_ray_flag_value);
    let tls_enabled = segments.iter().any(|s| s.key == "tls") || mode == Some("quic");
    let host = segments.iter().find(|s| s.key == "host").map(ex_ray_flag_value);
    let sni = match host {
        None => EX_RAY_DEFAULT_HOST,
        Some("") => segments
            .iter()
            .find(|s| s.key == "remoteAddr")
            .map_or("", ex_ray_flag_value),
        Some(v) => v,
    };
    tls_enabled && v2ray_core_parses_as_a_domain(sni)
}

/// A segment's value the way ex-ray's own parser reads it (see
/// [`garter::OptionSegment::has_value`]), not the raw `garter` decode.
fn ex_ray_flag_value<'a>(s: &'a garter::OptionSegment<'_>) -> &'a str {
    if s.has_value {
        &s.value
    } else {
        "1"
    }
}

/// Mirrors v2ray-core's `net.ParseAddress` (see `ech_fetch_is_reachable`'s
/// doc for the exact source lines): strips ONE matched `[...]` bracket pair,
/// then trims surrounding whitespace ONLY when the first or last byte isn't
/// alphanumeric, then tests whether what's left parses as an IP. An empty
/// result (whether from the input or after normalization) is never a
/// domain — `echCacheDomain`'s own caller excludes it explicitly.
fn v2ray_core_parses_as_a_domain(value: &str) -> bool {
    let bytes = value.as_bytes();
    let unbracketed = if !bytes.is_empty() && bytes[0] == b'[' && bytes[bytes.len() - 1] == b']' {
        &value[1..value.len() - 1]
    } else {
        value
    };
    let ub = unbracketed.as_bytes();
    let needs_trim = !ub.is_empty() && (!ub[0].is_ascii_alphanumeric() || !ub[ub.len() - 1].is_ascii_alphanumeric());
    let normalized = if needs_trim { unbracketed.trim() } else { unbracketed };
    !normalized.is_empty() && normalized.parse::<std::net::IpAddr>().is_err()
}

/// The `segments`-based wrapper around [`hole_ech_doh_outranks`] — extracts
/// the operator's own `ech-doh` value (if any) and applies the same
/// precedence formula (see that function's doc for the why). Shared by
/// [`classify_ech_doh`] (where it also decides which keys
/// `inject_plugin_directives` strips) and [`resolved_ech_doh_is_empty`]
/// (which needs the same precedence but, being reachable from
/// `ex_ray_fatal_config_error` via `ech_fetch_is_reachable`, cannot call
/// `classify_ech_doh` itself without cycling).
fn ech_doh_displaces(segments: &[garter::OptionSegment<'_>], ech_doh: Option<&crate::dns::ech::EchDoh>) -> bool {
    let config_ech_doh = segments.iter().find(|s| s.key == "ech-doh");
    match (ech_doh, config_ech_doh) {
        (Some(e), Some(s)) => hole_ech_doh_outranks(e, ex_ray_flag_value(s)),
        _ => false,
    }
}

/// The `(EffectiveEchDoh, displaces)` decision shared by [`effective_ech_doh`]
/// (reads only the first element) and `inject_plugin_directives` (reads
/// both: `displaces` decides which keys to strip) — see `effective_ech_doh`'s
/// doc for why the parse itself is NOT similarly shared (the logging that
/// must stay spawn-side-only lives one level up, in
/// `inject_plugin_directives`, past where `segments` is produced).
fn classify_ech_doh(
    segments: &[garter::OptionSegment<'_>],
    ech_doh: Option<&crate::dns::ech::EchDoh>,
) -> (EffectiveEchDoh, bool) {
    let config_ech_doh = segments.iter().find(|s| s.key == "ech-doh");
    let displaces = ech_doh_displaces(segments, ech_doh);

    if !ech_fetch_is_reachable(segments, ech_doh) {
        return (EffectiveEchDoh::None, displaces);
    }

    // ex-ray only arms ECH_DOHserver when the value is non-empty
    // (config.go:213: `if *echDoh != "" { tlsConfig.Ech_DOHserver = *echDoh }`)
    // — an empty or bare (reads as ex-ray's own `"1"`, not a URL) operator
    // value is silently inert, same as no `ech-doh` at all.
    let effective = if ech_doh.is_some() && (config_ech_doh.is_none() || displaces) {
        EffectiveEchDoh::Holes
    } else if let Some(v) = config_ech_doh.map(ex_ray_flag_value).filter(|v| !v.is_empty()) {
        EffectiveEchDoh::Operators(v.to_string())
    } else {
        EffectiveEchDoh::None
    };
    (effective, displaces)
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
/// forwards the whole options string to its inner ex-ray. Every other plugin
/// name is passed through unmodified — the ONE gate (`takes_ech_directives`)
/// both this function and its callers rely on, checked exactly once, here.
/// Emits the ECH-posture `tracing::warn!` lines — called exactly once per
/// actual plugin spawn (`start_plugin_chain`); the permit-derivation query
/// [`effective_ech_doh`] deliberately does NOT call this, to avoid
/// double-emitting them (see that function's doc).
fn inject_plugin_directives(
    plugin_name: &str,
    opts: Option<&str>,
    ech_doh: Option<&crate::dns::ech::EchDoh>,
) -> Result<Option<String>, ProxyError> {
    if !takes_ech_directives(plugin_name) {
        return Ok(opts.map(String::from));
    }
    {
        let opts = opts.unwrap_or_default();
        // Refuse rather than forward — see `ProxyError::MalformedPluginOptions`.
        // Position only in the message; a segment can carry a secret.
        let segments = garter::split_plugin_options(opts)
            .map_err(|e| ProxyError::MalformedPluginOptions(format!("{plugin_name}: {e}")))?;

        let (_effective, displaces) = classify_ech_doh(&segments, ech_doh);
        let config_ech_doh = segments.iter().find(|s| s.key == "ech-doh");
        // Strip only what we are about to set, so an override never becomes
        // a deletion. Keys compare as the PLUGIN decodes them.
        let owned: &[&str] = if displaces {
            &["loglevel", "ech-doh"]
        } else {
            &["loglevel"]
        };

        // Which ECH source won, and how much is known about it. Every outcome
        // reaches ex-ray as one URL, so this is the only record of the choice.
        // `find`, not `any`: ex-ray reads the FIRST `ech`, so a later one
        // reporting a posture it will never apply would invert the line.
        let fail_closed = segments
            .iter()
            .find(|s| s.key == "ech")
            .is_some_and(|s| ex_ray_flag_value(s) == "always");
        // A rejected config crashes the WHOLE plugin, unconditionally on
        // whether any `ech-doh` is even configured — checked first, and
        // reported as its own condition: unlike every arm below, this is not
        // "ECH is off", it's "the connection attempt fails outright".
        if let Some(key) = ex_ray_fatal_config_error(&segments, ech_doh) {
            tracing::warn!(
                plugin = %plugin_name,
                invalid_key = key,
                "ex-ray will refuse to start: this plugin configuration is invalid ({key}) — the \
                 plugin process exits before dialing anything, ECH-config fetch included"
            );
        } else {
            // Whether ex-ray will even ATTEMPT a fetch — shared with
            // `classify_ech_doh` (see `ech_fetch_is_reachable`'s doc). An
            // `ech-doh` source (Hole's or the config's) that would otherwise
            // read as active must not be reported as such when no fetch will
            // ever happen (`ech=never`, or no TLS-enabled domain SNI) — the
            // `(None, None)` arm stays correct either way, since "ECH is
            // off" holds regardless of reachability.
            let reachable = ech_fetch_is_reachable(&segments, ech_doh);
            // Presence alone isn't enough for the match below: ex-ray only
            // arms `Ech_DOHserver` for a NON-empty value (config.go:213,
            // same rule `classify_ech_doh` already applies to its
            // `Operators` arm) — an explicitly empty `ech-doh=` must read
            // as "no config value", not as one standing.
            let config_ech_doh_value = config_ech_doh.filter(|s| !ex_ray_flag_value(s).is_empty());
            match (ech_doh, config_ech_doh_value) {
                _ if !reachable && (ech_doh.is_some() || config_ech_doh.is_some()) => tracing::warn!(
                    plugin = %plugin_name,
                    fail_closed,
                    "ex-ray will never attempt an ECH-config fetch for this configuration (ech=never, \
                     or no TLS-enabled domain SNI); any ech-doh source is inert"
                ),
                (Some(_), Some(s)) if !displaces => tracing::warn!(
                    plugin = %plugin_name,
                    "{}, so the config's own name-free ech-doh stands: {}",
                    unpinned_reason(ech_doh),
                    s.raw
                ),
                (Some(e), _) if !e.is_pinned() => tracing::warn!(
                    plugin = %plugin_name, fail_closed,
                    "{}; the ECH lookup uses a resolver that has not been exercised: {}",
                    unpinned_reason(ech_doh),
                    e.url
                ),
                (Some(_), _) => {}
                // Stripping this would disarm ECH altogether, so it stands — but
                // a name authority is resolved over plaintext system DNS.
                (None, Some(s)) => tracing::warn!(
                    plugin = %plugin_name,
                    "no configured resolver to pin the ECH lookup to; the config's own ech-doh stands: {}", s.raw
                ),
                // ECH is armed only by `ech-doh`, so there is none. Under
                // `ech=always` WITH TLS enabled, this arm is unreachable —
                // `ex_ray_fatal_config_error`'s `resolved_ech_doh_is_empty`
                // check already routed that combination through the `if let
                // Some(key) = ...` branch above. WITHOUT TLS (no `tls` flag,
                // no `mode=quic`), `ech=always` is inert like everything
                // else here — `buildTLSConfig` never runs, so `fail_closed`
                // can legitimately be `true` on this arm.
                (None, None) => tracing::warn!(
                    plugin = %plugin_name,
                    fail_closed,
                    "no ech-doh from any source; ECH is off"
                ),
            }
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
    use crate::dns::ech::{EchDoh, PinSource};

    /// The merged options, or panic — for inputs that are not testing rejection.
    fn merged(plugin: &str, opts: Option<&str>, ech_doh: Option<&EchDoh>) -> Option<String> {
        inject_plugin_directives(plugin, opts, ech_doh).expect("well-formed options")
    }

    /// The IP `url`'s authority names, per `EchDoh::resolver`'s contract
    /// (Hole always constructs `url` FROM this address, in production) — or
    /// a placeholder when the fixture deliberately uses a NAME authority
    /// (e.g. to exercise `authority_is_a_name`'s injection-priority path):
    /// `resolver` is irrelevant to what those fixtures assert, only `url`
    /// and `source` are.
    fn ip_from_test_url(url: &str) -> IpAddr {
        url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .and_then(|h| h.trim_start_matches('[').trim_end_matches(']').parse().ok())
            .unwrap_or_else(|| "192.0.2.1".parse().expect("test IP literal"))
    }

    /// An `ech-doh` naming a resolver that ANSWERED the bootstrap.
    fn pinned(url: &str) -> EchDoh {
        EchDoh {
            url: url.to_string(),
            resolver: ip_from_test_url(url),
            source: PinSource::Answered(ip_from_test_url(url)),
        }
    }

    /// An `ech-doh` Hole guessed for the given reason, no resolver having answered.
    fn unpinned_for(url: &str, source: PinSource) -> EchDoh {
        EchDoh {
            url: url.to_string(),
            resolver: ip_from_test_url(url),
            source,
        }
    }

    fn unpinned(url: &str) -> EchDoh {
        unpinned_for(url, PinSource::SecureBootstrapFailed)
    }

    /// The WARN lines `inject_plugin_directives` emits for these arguments.
    fn warnings_for(plugin: &str, opts: Option<&str>, ech_doh: Option<&EchDoh>) -> String {
        use tracing_subscriber::layer::{Layer, SubscriberExt};
        let writer = crate::test_support::log_capture::VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        );
        {
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
            let _ = inject_plugin_directives(plugin, opts, ech_doh);
        }
        writer.snapshot_string()
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
                Some(&format!("tls;ech-doh={their_url}")),
                Some(&unpinned("https://1.1.1.1/dns-query")),
            );
            assert_eq!(
                out.as_deref(),
                Some(&*format!(
                    "tls;ech-doh={their_url};loglevel=debug;ech-doh=https://1.1.1.1/dns-query"
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
            Some("tls;ech=always;ech-doh=https://cloudflare-dns.com/dns-query"),
            Some(&unpinned("https://1.1.1.1/dns-query")),
        );
        assert_eq!(
            out.as_deref(),
            Some("tls;ech=always;loglevel=debug;ech-doh=https://1.1.1.1/dns-query"),
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
            Some(r"tls;ech\-doh=https://evil.example/dns-query;log\level=warning"),
            Some(&pinned("https://9.9.9.9/dns-query")),
        );
        assert_eq!(
            out.as_deref(),
            Some("tls;loglevel=debug;ech-doh=https://9.9.9.9/dns-query"),
        );
    }

    // An UNREACHABLE config (`ech=never` here) with a PRE-EXISTING operator
    // `ech-doh=` key and a PINNED Hole candidate. `displaces` must still be computed correctly
    // (pinned always outranks) and the strip must still happen, even though
    // no fetch will ever occur — `classify_ech_doh`'s reachability gate may
    // only change `EffectiveEchDoh`, never silently disable the strip.
    // Exercised at the actual joined-string level, not just the
    // `EffectiveEchDoh` enum.
    #[skuld::test]
    fn displaces_is_still_correct_when_the_config_is_unreachable() {
        let out = merged(
            "ex-ray",
            Some("ech=never;ech-doh=https://evil.example/dns-query"),
            Some(&pinned("https://9.9.9.9/dns-query")),
        );
        assert_eq!(
            out.as_deref(),
            Some("ech=never;loglevel=debug;ech-doh=https://9.9.9.9/dns-query"),
            "exactly one ech-doh key (Hole's), the operator's stripped, even though ech=never means \
             neither will ever be dialed"
        );
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
            Some("tls;loglevel=warning;ech-doh=https://stale.example/dns-query"),
            Some(&pinned("https://9.9.9.9/dns-query")),
        );
        assert_eq!(
            out.as_deref(),
            Some("tls;loglevel=debug;ech-doh=https://9.9.9.9/dns-query"),
        );
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

    // The reason no resolver is pinned is reported in its own words: "no resolver
    // answered" is false for a literal server entry, where none was ever asked.
    #[skuld::test]
    fn each_unpinned_reason_is_reported_in_its_own_words() {
        for (source, expected) in [
            (PinSource::NoQueryNeeded, "the server entry is a literal IP"),
            (
                PinSource::SecureBootstrapFailed,
                "no configured resolver completed a DoH exchange",
            ),
            (
                PinSource::ResolverDeselected,
                "the cached resolver is no longer configured",
            ),
        ] {
            let ech_doh = unpinned_for("https://1.1.1.1/dns-query", source);
            let out = warnings_for("ex-ray", Some("tls;host=cdn.example;path=/x"), Some(&ech_doh));
            assert!(
                out.contains(expected),
                "{source:?} must be reported as {expected:?}, got:
{out}"
            );
            assert!(
                !out.contains("no resolver answered"),
                "{source:?} must not claim a resolver answered nothing, got:
{out}"
            );
        }
    }

    // A pinned resolver is the good case and warns about nothing — for a
    // config where the fetch is actually reachable; an unreachable one has
    // its own dedicated warning (see `ech_fetch_is_reachable`'s callers).
    #[skuld::test]
    fn a_pinned_resolver_warns_about_nothing() {
        let out = warnings_for(
            "ex-ray",
            Some("tls;host=cdn.example;path=/x"),
            Some(&pinned("https://9.9.9.9/dns-query")),
        );
        assert_eq!(out, "", "a pinned ech-doh has nothing to report");
    }

    // The reachability gate: an ech-doh source (pinned or not) that would
    // otherwise read as active must be reported as inert, not silently
    // dropped or misreported as exercised/unexercised.
    #[skuld::test]
    fn an_unreachable_config_reports_any_ech_doh_source_as_inert() {
        let out = warnings_for("ex-ray", Some("path=/x"), Some(&pinned("https://9.9.9.9/dns-query")));
        assert!(
            out.contains("ex-ray will never attempt an ECH-config fetch"),
            "expected the unreachable-config warning; got:\n{out}"
        );
    }

    // An explicitly empty operator `ech-doh=` must not be reported as "the
    // config's own ech-doh stands" — `classify_ech_doh` already treats it
    // as inert (`EffectiveEchDoh::None`, same as no `ech-doh` at all), and
    // the warning here must agree, not contradict it.
    #[skuld::test]
    fn an_empty_operator_ech_doh_is_not_reported_as_standing() {
        let out = warnings_for("ex-ray", Some("tls;host=cdn.example;ech-doh="), None);
        assert!(
            !out.contains("stands"),
            "an empty ech-doh= must not be reported as a live/standing value; got:\n{out}"
        );
        assert!(
            out.contains("ECH is off"),
            "expected the same disposition as no ech-doh from any source; got:\n{out}"
        );
    }

    // A fatal config-build error must get ITS OWN warning — distinct from
    // the plain "ECH is off" inert case above — naming the rejecting key,
    // AND `inject_plugin_directives` must still return `Ok` (ex-ray, not
    // Hole, is what refuses this config; Hole still spawns it and lets
    // ex-ray exit 23, same as any other config-class ex-ray rejects today).
    #[skuld::test]
    fn a_fatal_config_reports_its_own_warning_and_still_starts() {
        let out = warnings_for(
            "ex-ray",
            Some("tls;host=cdn.example;localPort=0"),
            Some(&pinned("https://9.9.9.9/dns-query")),
        );
        assert!(
            out.contains("ex-ray will refuse to start") && out.contains("localPort"),
            "expected the fatal-config warning naming `localPort`; got:\n{out}"
        );
        assert!(
            !out.contains("ECH is off") && !out.contains("ex-ray will never attempt"),
            "the fatal-config warning must not also emit an ECH-posture line; got:\n{out}"
        );
        assert!(
            merged(
                "ex-ray",
                Some("tls;host=cdn.example;localPort=0"),
                Some(&pinned("https://9.9.9.9/dns-query"))
            )
            .is_some(),
            "a semantically (not syntactically) invalid config must still be forwarded — ex-ray, \
             not Hole, is what refuses to start"
        );
    }

    // The checks inside `ex_ray_fatal_config_error` run in ex-ray's OWN
    // evaluation order, not textual/declaration order — with TWO distinct
    // keys simultaneously invalid, the EARLIER-evaluated one must win, not
    // merely the first one this function happens to check.
    #[skuld::test]
    fn two_distinct_fatal_keys_report_ex_rays_earlier_one() {
        let segments = garter::split_plugin_options("tls;host=cdn.example;localPort=0;tcp-keepalive=99999").unwrap();
        assert_eq!(
            ex_ray_fatal_config_error(&segments, None),
            Some("tcp-keepalive"),
            "tcp-keepalive (registerTCPKeepAlive) runs before the localPort=0 check in ex-ray's own main()"
        );
        let segments = garter::split_plugin_options("tls;host=cdn.example;remotePort=bogus;mux=-1").unwrap();
        assert_eq!(
            ex_ray_fatal_config_error(&segments, None),
            Some("remotePort"),
            "remotePort is parsed inside generateConfig before mux/fwmark's uint32Opt calls"
        );
        let segments = garter::split_plugin_options("tls;host=cdn.example;mode=grpc;ech=bogus").unwrap();
        assert_eq!(
            ex_ray_fatal_config_error(&segments, None),
            Some("mode"),
            "mode's switch is unconditional and runs before ech's, which is gated on tlsEnabled"
        );
    }

    // ex-ray reads the FIRST `ech`, so a later `always` it will never apply must
    // not be reported as a fail-closed posture.
    #[skuld::test]
    fn fail_closed_reads_the_first_ech_not_any_of_them() {
        let out = warnings_for("ex-ray", Some("ech=never;ech=always"), None);
        assert!(
            out.contains("fail_closed=false"),
            "the first `ech` is `never`; got:
{out}"
        );
        let out = warnings_for("ex-ray", Some("ech=always;ech=never"), None);
        assert!(
            out.contains("fail_closed=true"),
            "the first `ech` is `always`; got:
{out}"
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

    // effective_ech_doh / ech_doh_will_reach_ex_ray ===================================================================

    // A regression that made this return `true` whenever `ech_doh.is_some()`
    // would pass this test if the plugin-family gate were dropped: a
    // non-ECH-capable plugin name
    // must never be told it will fetch Hole's ech_doh, even with a pinned
    // candidate in hand.
    #[skuld::test]
    fn non_family_plugin_never_reaches_ex_ray() {
        assert!(!ech_doh_will_reach_ex_ray(
            "obfs-local",
            None,
            Some(&pinned("https://9.9.9.9/dns-query"))
        ));
        assert_eq!(
            effective_ech_doh("obfs-local", None, Some(&pinned("https://9.9.9.9/dns-query"))),
            EffectiveEchDoh::None
        );
    }

    #[skuld::test]
    fn family_plugin_with_no_ech_doh_from_any_source_is_not_applicable() {
        assert_eq!(effective_ech_doh("ex-ray", None, None), EffectiveEchDoh::None);
    }

    #[skuld::test]
    fn family_plugin_with_no_operator_override_reaches_ex_ray_as_holes() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert!(ech_doh_will_reach_ex_ray(
            "ex-ray",
            Some("tls;host=cdn.example"),
            Some(&e)
        ));
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example"), Some(&e)),
            EffectiveEchDoh::Holes
        );
    }

    // An unpinned Hole guess against an operator's own IP-literal `ech-doh` —
    // the operator's choice stands, so ex-ray fetches THEIRS, not Hole's.
    #[skuld::test]
    fn family_plugin_with_a_winning_operator_override_reaches_ex_ray_as_operators() {
        let e = unpinned("https://1.1.1.1/dns-query");
        assert!(!ech_doh_will_reach_ex_ray(
            "ex-ray",
            Some("tls;host=cdn.example;ech-doh=https://8.8.8.8/dns-query"),
            Some(&e)
        ));
        assert_eq!(
            effective_ech_doh(
                "ex-ray",
                Some("tls;host=cdn.example;ech-doh=https://8.8.8.8/dns-query"),
                Some(&e)
            ),
            EffectiveEchDoh::Operators("https://8.8.8.8/dns-query".to_string())
        );
    }

    // An explicit empty `ech-doh=` never dials (see `classify_ech_doh`'s
    // comment), so it must not be reported as a live operator fetch
    // (`EffectiveEchDoh::Operators`), which would falsely widen the
    // residual-stall warning and (were Operators ever permitted) the cover
    // itself.
    #[skuld::test]
    fn empty_operator_ech_doh_never_reaches_ex_ray() {
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;ech-doh="), None),
            EffectiveEchDoh::None
        );
    }

    // A bare `ech-doh` (no `=`) reads as ex-ray's own `"1"` — non-empty, so
    // ex-ray DOES arm `Ech_DOHserver = "1"` (config.go:213) and attempt to
    // use it as a DoH URL, even though "1" itself is not a usable URL. The
    // operator's value is reported as exactly what ex-ray will try, "1".
    #[skuld::test]
    fn bare_operator_ech_doh_reaches_ex_ray_as_ex_rays_own_placeholder() {
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;ech-doh"), None),
            EffectiveEchDoh::Operators("1".to_string())
        );
    }

    // `switch *echMode` lives INSIDE `buildTLSConfig`, called only `if
    // *tlsEnabled` (config.go:209-223,290-294,334) — an invalid `ech` value
    // with no `tls` flag and no `mode=quic` is never looked at, so ex-ray
    // starts fine and dials the plaintext upstream normally. Must NOT be
    // reported as a fatal config-build error (nor, since there's no `tls`,
    // as reachable — `no_tls_and_not_quic_never_reaches_ex_ray` already
    // covers that half).
    #[skuld::test]
    fn an_invalid_ech_value_without_tls_is_inert_not_fatal() {
        let segments = garter::split_plugin_options("host=cdn.example;ech=bogus").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), None);
    }

    // As above, but `mode=quic` force-enables TLS with no explicit `tls`
    // flag — `buildTLSConfig` DOES run, so an invalid `ech` value here IS
    // fatal.
    #[skuld::test]
    fn an_invalid_ech_value_with_mode_quic_is_fatal() {
        let segments = garter::split_plugin_options("host=cdn.example;mode=quic;ech=bogus").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("ech"));
    }

    // Go's `ParseUint` rejects a leading `+` that Rust's parser accepts —
    // see `ex_ray_parses_as_uint32`'s doc.
    #[skuld::test]
    fn a_signed_local_port_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;localPort=+8080"), Some(&e)),
            EffectiveEchDoh::None
        );
    }

    #[skuld::test]
    fn a_signed_remote_port_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;remotePort=+1080"), Some(&e)),
            EffectiveEchDoh::None
        );
    }

    // `remotePort` has NO upper bound of its own (config.go routes it
    // through raw `strconv.ParseUint`, not `net.Port`) — its only ceiling is
    // u32::MAX from the parse itself. A value that overflows it is the one
    // thing standing between a legal and a rejected remotePort, so it must
    // be exercised, not just the non-digit / negative cases above.
    #[skuld::test]
    fn a_remote_port_above_u32_max_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;remotePort=4294967296"), Some(&e)),
            EffectiveEchDoh::None
        );
    }

    // As above, for `localPort` (whose ceiling is the tighter 65535, but the
    // u32::MAX parse overflow is a distinct failure mode from that range
    // check and must independently be caught by `ex_ray_parses_as_uint32`).
    #[skuld::test]
    fn a_local_port_above_u32_max_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;localPort=4294967296"), Some(&e)),
            EffectiveEchDoh::None
        );
    }

    // `ech=always` with an empty RESOLVED `ech-doh` is itself a
    // config-build error (config.go:218-220) distinct from a plain invalid
    // `ech` value — ex-ray refuses to start rather than merely skipping
    // ECH. Reachable whenever Hole has no candidate of its own (no pinned
    // resolver) and the operator's own config supplies none either.
    #[skuld::test]
    fn ech_always_with_no_ech_doh_from_any_source_never_reaches_ex_ray() {
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;ech=always"), None),
            EffectiveEchDoh::None
        );
        let segments = garter::split_plugin_options("tls;host=cdn.example;ech=always").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("ech-doh"));
    }

    // As above, but the operator's OWN `ech-doh=` is explicitly empty
    // rather than absent — same config.go:218-220 fatal, same expectation.
    #[skuld::test]
    fn ech_always_with_an_explicitly_empty_operator_ech_doh_never_reaches_ex_ray() {
        let segments = garter::split_plugin_options("tls;host=cdn.example;ech=always;ech-doh=").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("ech-doh"));
    }

    // Hole's own (non-empty, by construction) `ech_doh` always satisfies
    // `ech=always`'s requirement, regardless of what the operator's own
    // config carries — this must NOT be reported as fatal.
    #[skuld::test]
    fn ech_always_with_holes_own_ech_doh_is_not_fatal() {
        let e = pinned("https://9.9.9.9/dns-query");
        let segments = garter::split_plugin_options("tls;host=cdn.example;ech=always").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, Some(&e)), None);
    }

    // The nested `ech=always` + empty-resolved-`ech-doh` check lives INSIDE
    // the `tls_enabled` gate, same as the enum check — with no `tls` and no
    // `mode=quic`, `buildTLSConfig` (and the whole `ech` switch within it)
    // never runs, so `ech=always` with no `ech-doh` from any source is
    // inert, not fatal. A regression that moved this check outside the
    // `tls_enabled` guard would pass every OTHER `ech=always` test (all of
    // which include `tls`) but not this one.
    #[skuld::test]
    fn ech_always_without_tls_is_inert_not_fatal() {
        let segments = garter::split_plugin_options("host=cdn.example;ech=always").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), None);
    }

    // Every new `ex_ray_fatal_config_error` check reads its key via `find`
    // (first match), matching ex-ray's own `Args.Get` — a corrective SECOND
    // occurrence of the same key must not un-set a first occurrence's
    // fatal verdict, matching the first-wins coverage every pre-existing
    // check in this file already has (`ech_never_is_first_wins`,
    // `domain_host_is_first_wins`, the `mode=quic` force-enable test).
    #[skuld::test]
    fn the_new_fatal_checks_are_first_wins() {
        let cases: &[(&str, &str)] = &[
            ("tls;host=cdn.example;mode=grpc;mode=quic", "mode"),
            ("tls;host=cdn.example;ech=bogus;ech=auto", "ech"),
            ("tls;host=cdn.example;mux=-1;mux=1", "mux"),
            ("tls;host=cdn.example;fwmark=-1;fwmark=1", "fwmark"),
            (
                "tls;host=cdn.example;tcp-keepalive=99999;tcp-keepalive=15",
                "tcp-keepalive",
            ),
            ("tls;host=cdn.example;localPort=0;localPort=1984", "localPort"),
            ("tls;host=cdn.example;remotePort=bogus;remotePort=1080", "remotePort"),
        ];
        for (opts, expected_key) in cases {
            let segments = garter::split_plugin_options(opts).unwrap();
            assert_eq!(
                ex_ray_fatal_config_error(&segments, None),
                Some(*expected_key),
                "opts={opts:?}: the FIRST occurrence of the key must decide, matching ex-ray's own \
                 first-wins `Args.Get` — a corrective second occurrence must not un-set it"
            );
        }
    }

    // `ex_ray_fatal_config_error`'s enum checks (`ech`/`mode`) must not
    // widen the permit or the residual warning for a config ex-ray never
    // even starts for — see `mux`/`fwmark`/`tcp-keepalive`/`localPort`/
    // `remotePort` below for the same principle applied to ex-ray's other
    // exit(23) classes.
    #[skuld::test]
    fn a_fatal_mux_value_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;mux=-1"), Some(&e)),
            EffectiveEchDoh::None,
            "mux=-1 parses but is out of uint32Opt's 0..=u32::MAX range — config.go rejects it"
        );
    }

    // A `mux` that fails to parse at all is NOT a config-build error —
    // ex-ray's own opts-to-flags step (main.go) logs a warning and silently
    // keeps the flag's default, so the fetch is still reachable.
    #[skuld::test]
    fn an_unparseable_mux_value_keeps_ex_ray_default_and_still_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;mux=not-a-number"), Some(&e)),
            EffectiveEchDoh::Holes
        );
    }

    #[skuld::test]
    fn a_fatal_fwmark_value_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;fwmark=4294967296"), Some(&e)),
            EffectiveEchDoh::None,
            "fwmark above u32::MAX is out of uint32Opt's range — config.go rejects it"
        );
    }

    // `core.New` rejects a non-zero websocket `mux` `Concurrency` outside
    // `1..=1024` — DIFFERENT from `uint32Opt`'s own `0..=u32::MAX` range
    // check above (a later, separate exit(23) site).
    #[skuld::test]
    fn a_fatal_mux_concurrency_value_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;mux=1025"), Some(&e)),
            EffectiveEchDoh::None,
            "mux=1025 is within uint32Opt's range but outside core.New's 1..=1024 concurrency bound"
        );
    }

    // The boundary itself must still be reachable — `1024` is valid, only
    // `1025` and above are not.
    #[skuld::test]
    fn a_mux_concurrency_value_at_the_boundary_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;mux=1024"), Some(&e)),
            EffectiveEchDoh::Holes
        );
    }

    // `mux=0` disables multiplexing outright — `connectionReuse` stays
    // false, so `MultiplexingConfig` (and its 1..=1024 bound) never attaches
    // at all, regardless of how large a LATER duplicate `mux` looks.
    #[skuld::test]
    fn a_zero_mux_never_hits_the_concurrency_bound() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;mux=0"), Some(&e)),
            EffectiveEchDoh::Holes
        );
    }

    // `quic`'s mux is never read (`connectionReuse` only sets under
    // `case "websocket"`) — an out-of-bound `mux` alongside `mode=quic`
    // must not be reported as fatal.
    #[skuld::test]
    fn a_large_mux_with_mode_quic_never_hits_the_concurrency_bound() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("host=cdn.example;mode=quic;mux=99999"), Some(&e)),
            EffectiveEchDoh::Holes
        );
    }

    #[skuld::test]
    fn a_fatal_tcp_keepalive_value_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;tcp-keepalive=32768"), Some(&e)),
            EffectiveEchDoh::None,
            "tcp-keepalive above tcpKeepAliveParams' 32767 max — config.go rejects it"
        );
    }

    // As above, the LOWER edge — `tcpKeepAliveParams` rejects `v < 0` too,
    // a distinct branch from the overflow case.
    #[skuld::test]
    fn a_negative_tcp_keepalive_value_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;tcp-keepalive=-1"), Some(&e)),
            EffectiveEchDoh::None,
            "tcp-keepalive below tcpKeepAliveParams' 0 minimum — config.go rejects it"
        );
    }

    #[skuld::test]
    fn a_zero_or_empty_local_port_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        for opts in ["tls;host=cdn.example;localPort=0", "tls;host=cdn.example;localPort="] {
            assert_eq!(
                effective_ech_doh("ex-ray", Some(opts), Some(&e)),
                EffectiveEchDoh::None,
                "opts={opts:?}: ex-ray cannot honor port-0/empty OS-assignment (main.go) — exits before dialing"
            );
        }
    }

    #[skuld::test]
    fn an_out_of_range_local_port_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;localPort=65536"), Some(&e)),
            EffectiveEchDoh::None,
            "localPort above net.PortFromString's 65535 max — config.go rejects it"
        );
    }

    #[skuld::test]
    fn an_unparseable_remote_port_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;remotePort=not-a-port"), Some(&e)),
            EffectiveEchDoh::None,
            "remotePort must be strconv.ParseUint(_, 10, 32)-parseable (config.go) — else it rejects it"
        );
    }

    // `classify_ech_doh` must read whether ex-ray will even ATTEMPT ECH, not
    // just plugin family + ech-doh presence — `ech=never` short-circuits it
    // (config.go:209-211) regardless of `tls`/`host`/`ech-doh`.
    #[skuld::test]
    fn ech_never_never_reaches_ex_ray_even_with_tls_and_ech_doh() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;ech=never"), Some(&e)),
            EffectiveEchDoh::None
        );
    }

    // `ech=never` uses first-wins (matching ex-ray's own `Args.Get`), same as
    // `fail_closed` elsewhere in this module — a later `ech=auto` must not
    // resurrect it.
    #[skuld::test]
    fn ech_never_is_first_wins() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;ech=never;ech=auto"), Some(&e)),
            EffectiveEchDoh::None
        );
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;ech=auto;ech=never"), Some(&e)),
            EffectiveEchDoh::Holes,
            "the FIRST ech= wins — auto here, so never (second) is ignored"
        );
    }

    // An ABSENT `host` is NOT "no SNI" — ex-ray defaults it to
    // `EX_RAY_DEFAULT_HOST` (a real domain), so the fetch IS reachable.
    #[skuld::test]
    fn absent_host_falls_back_to_ex_rays_own_domain_default_and_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls"), Some(&e)),
            EffectiveEchDoh::Holes
        );
    }

    // But an EXPLICIT `host` must still be a DOMAIN for `ApplyECH` to ever
    // dial DoH at all (`echCacheDomain` returns "" and `ApplyECH` bails
    // otherwise) — explicitly empty or IP-literal both mean "no SNI to key
    // the lookup on", matching v2ray-core's `net.ParseAddress` exactly:
    // only a MATCHED `[...]` pair strips, and only a non-alphanumeric edge
    // trims whitespace.
    #[skuld::test]
    fn no_domain_host_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        for opts in [
            "tls;host=",
            "tls;host=203.0.113.5",
            "tls;host=[2001:db8::1]",
            "tls;host= 203.0.113.5", // ParseAddress TrimSpaces a non-alnum edge, still an IP
            "tls;host=203.0.113.5 ", // same, trailing
        ] {
            assert_eq!(
                effective_ech_doh("ex-ray", Some(opts), Some(&e)),
                EffectiveEchDoh::None,
                "opts={opts:?} must not reach ex-ray: no domain SNI to key the DoH lookup on"
            );
        }
    }

    // An EXPLICIT empty `host=` is NOT "no SNI" — `Config.ServerName`
    // (empty) falls back to the dial destination (`tls.WithDestination`),
    // and that destination is `remoteAddr`, itself a `plugin_opts` option
    // that can name a domain.
    #[skuld::test]
    fn empty_host_falls_back_to_a_domain_remote_addr_and_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=;remoteAddr=cdn.example"), Some(&e)),
            EffectiveEchDoh::Holes
        );
    }

    // As above, but the destination fallback is itself an IP — no domain
    // SNI either way, so still unreachable (same outcome as no `remoteAddr`
    // at all, just via the explicit-IP branch instead of the absent one).
    #[skuld::test]
    fn empty_host_with_an_ip_remote_addr_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=;remoteAddr=203.0.113.5"), Some(&e)),
            EffectiveEchDoh::None
        );
    }

    // `remoteAddr` uses first-wins too, matching every other flag here.
    #[skuld::test]
    fn empty_host_remote_addr_fallback_is_first_wins() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh(
                "ex-ray",
                Some("tls;host=;remoteAddr=203.0.113.5;remoteAddr=cdn.example"),
                Some(&e)
            ),
            EffectiveEchDoh::None,
            "the FIRST remoteAddr= wins — an IP literal here, so the later domain is ignored"
        );
        assert_eq!(
            effective_ech_doh(
                "ex-ray",
                Some("tls;host=;remoteAddr=cdn.example;remoteAddr=203.0.113.5"),
                Some(&e)
            ),
            EffectiveEchDoh::Holes,
            "the FIRST remoteAddr= wins — a domain here, so the later IP literal is ignored"
        );
    }

    // A bare `host` (no `=`) is `""` in `OptionSegment::value`, but ex-ray's
    // own parser reads it as `"1"` (`crates/ex-ray/args.go`) — a DOMAIN, not
    // an empty SNI. Misreading it as `""` would omit the cover's resolver
    // permit while ex-ray still dials the pinned resolver, stalling under
    // the very cover meant to prevent that.
    #[skuld::test]
    fn bare_host_reads_as_ex_rays_own_domain_default_and_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host"), Some(&e)),
            EffectiveEchDoh::Holes
        );
    }

    // `ech` and `mode` are CLOSED enums to ex-ray (`switch *echMode` /
    // `switch *mode`, config.go:209,281) — a value outside the known set is
    // a config-build error and `main.go` exits (23) before the server ever
    // starts, so no dial of any kind happens. A bare `ech` (no `=`) reads as
    // `"1"` to ex-ray, which is exactly such an invalid value — NOT
    // `"never"` (a different reason to be unreachable) and NOT a value that
    // reaches ex-ray either.
    #[skuld::test]
    fn bare_ech_is_an_invalid_enum_value_and_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;ech"), Some(&e)),
            EffectiveEchDoh::None
        );
    }

    // An explicit, misspelled `ech` value is the same invalid-enum case as
    // the bare-key one above, exercised without relying on `has_value` at
    // all — the enum check must reject any value outside
    // `never`/`auto`/`always`, not just the ones this module happens to name.
    #[skuld::test]
    fn an_unrecognized_ech_value_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;ech=Always"), Some(&e)),
            EffectiveEchDoh::None,
            "ex-ray's echMode switch is case-sensitive; a value ex-ray itself would reject as \
             \"invalid ech mode\" must not be read as reachable"
        );
    }

    // Same closed-enum reasoning as `ech`, for `mode` (config.go's `switch
    // *mode`, `websocket`/`quic` only): a bare `mode` reads as `"1"`, an
    // invalid value on its own. `tls` is present here so the ONLY thing
    // keeping this unreachable is the mode-enum check — without it, `tls`
    // alone would already make this reachable.
    #[skuld::test]
    fn bare_mode_is_an_invalid_transport_and_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;mode"), Some(&e)),
            EffectiveEchDoh::None
        );
    }

    // As `an_unrecognized_ech_value_never_reaches_ex_ray`, for `mode`.
    #[skuld::test]
    fn an_unrecognized_mode_value_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;mode=grpc"), Some(&e)),
            EffectiveEchDoh::None,
            "ex-ray's mode switch accepts only websocket/quic; \"unsupported mode\" is a \
             config-build error, not a fetch that happens"
        );
    }

    // `ParseAddress` strips only a MATCHED `[...]` pair — an unmatched
    // bracket is left as part of the (non-IP, therefore domain) string, so
    // ex-ray treats it as a real SNI and DOES dial DoH.
    #[skuld::test]
    fn unmatched_brackets_are_not_stripped_and_reach_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        for opts in ["tls;host=[2001:db8::1", "tls;host=2001:db8::1]"] {
            assert_eq!(
                effective_ech_doh("ex-ray", Some(opts), Some(&e)),
                EffectiveEchDoh::Holes,
                "opts={opts:?}: an unmatched bracket is not IPv6-literal stripping, so this is a \
                 (nonsensical but real) domain string ex-ray will dial DoH for"
            );
        }
    }

    // The Go source cited by `EX_RAY_DEFAULT_HOST`'s doc, pinned at the text
    // level: this crate can't execute ex-ray's Go code, but a literal-string
    // check still fails loudly if the vendored default ever changes without
    // a matching edit here — the same spirit as `resolver_permit_port_matches_doh_port`
    // pinning a value across the tun-engine/hole-bridge crate boundary,
    // applied across the Rust/Go boundary instead.
    #[skuld::test]
    fn ex_ray_default_host_matches_vendored_config_go() {
        let source = include_str!("../../../ex-ray/config.go");
        let expected = format!("flag.String(\"host\", \"{EX_RAY_DEFAULT_HOST}\", \"Hostname for server.\")");
        assert!(
            source.contains(&expected),
            "EX_RAY_DEFAULT_HOST ({EX_RAY_DEFAULT_HOST:?}) no longer matches config.go's `host` flag \
             default — update the constant to match the vendored source"
        );
    }

    // As `ex_ray_default_host_matches_vendored_config_go`, for the closed
    // enum sets `ex_ray_fatal_config_error` hardcodes: a vendored source
    // change that adds/renames an `ech`/`mode` value must fail this test
    // loudly rather than silently change which configs are treated as a
    // fatal ex-ray config-build error.
    #[skuld::test]
    fn ech_and_mode_enums_match_vendored_config_go() {
        let source = include_str!("../../../ex-ray/config.go");

        let ech_arms = go_switch_arms(source, "switch *echMode {");
        for value in ["\"never\"", "\"auto\", \"always\""] {
            assert!(
                ech_arms.contains(value),
                "config.go's `echMode` switch no longer has the arm {value} \u{2014} update \
                 ex_ray_fatal_config_error's `ech` match to the vendored source. Arms:\n{ech_arms}"
            );
        }
        assert_eq!(
            ech_arms.matches("\n\tcase ").count(),
            2,
            "config.go's `echMode` switch gained or lost a case arm beyond never/auto/always \u{2014} \
             update ex_ray_fatal_config_error's `ech` match to the vendored source. Arms:\n{ech_arms}"
        );

        let mode_arms = go_switch_arms(source, "switch *mode {");
        for value in ["\"websocket\"", "\"quic\""] {
            assert!(
                mode_arms.contains(value),
                "config.go's `mode` switch no longer has the arm {value} \u{2014} update \
                 ex_ray_fatal_config_error's `mode` match to the vendored source. Arms:\n{mode_arms}"
            );
        }
        assert_eq!(
            mode_arms.matches("\n\tcase ").count(),
            2,
            "config.go's `mode` switch gained or lost a case arm beyond websocket/quic \u{2014} \
             update ex_ray_fatal_config_error's `mode` match to the vendored source. Arms:\n{mode_arms}"
        );

        // The numeric bounds `ex_ray_fatal_config_error` hardcodes for
        // mux/fwmark (`uint32Opt`), tcp-keepalive (`keepAliveMaxSeconds`),
        // and localPort (`net.PortFromString`) — same drift risk, same pin.
        assert!(
            source.contains("(expected 0..4294967295), got:"),
            "ex_ray_fatal_config_error's mux/fwmark range (0..=u32::MAX) no longer matches \
             config.go's `uint32Opt` — update the range to the vendored source"
        );
        assert!(
            source.contains("keepAliveMaxSeconds = 32767"),
            "ex_ray_fatal_config_error's tcp-keepalive range (0..=32767) no longer matches \
             config.go's `keepAliveMaxSeconds` — update the range to the vendored source"
        );
        let port_source = include_str!("../../../ex-ray/third_party/v2ray-core/common/net/port.go");
        assert!(
            port_source.contains("if val > 65535 {"),
            "ex_ray_fatal_config_error's localPort ceiling (65535) no longer matches \
             port.go's `PortFromInt` — update the bound to the vendored source"
        );
        let handler_source = include_str!("../../../ex-ray/third_party/v2ray-core/app/proxyman/outbound/handler.go");
        assert!(
            handler_source.contains("config.Concurrency < 1 || config.Concurrency > 1024"),
            "ex_ray_fatal_config_error's mux-concurrency range (1..=1024) no longer matches \
             handler.go's own bound — update the range to the vendored source"
        );
    }

    /// The text of a Go `switch` statement's case arms — between
    /// `switch_header` (exclusive) and the following `default:` (exclusive)
    /// — so a test can assert on exactly the case VALUES present, and fail
    /// loudly if the vendored source gains or loses one, not just if a known
    /// value's text happens to disappear.
    fn go_switch_arms<'a>(source: &'a str, switch_header: &str) -> &'a str {
        let start = source
            .find(switch_header)
            .unwrap_or_else(|| panic!("{switch_header:?} not found in vendored config.go"))
            + switch_header.len();
        let rest = &source[start..];
        let end = rest
            .find("\n\tdefault:")
            .unwrap_or_else(|| panic!("no `default:` arm found after {switch_header:?} in vendored config.go"));
        &rest[..end]
    }

    // `host` uses first-wins too, matching every other flag here.
    #[skuld::test]
    fn domain_host_is_first_wins() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=203.0.113.5;host=cdn.example"), Some(&e)),
            EffectiveEchDoh::None,
            "the FIRST host= wins — an IP literal here, so the later domain is ignored"
        );
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;host=203.0.113.5"), Some(&e)),
            EffectiveEchDoh::Holes,
            "the FIRST host= wins — a domain here, so the later IP literal is ignored"
        );
    }

    // ex-ray's `buildTLSConfig` (and therefore its whole `ech` switch) is
    // only called when `tlsEnabled` — never for a plain, non-quic transport
    // with no `tls` flag (config.go:290-294,334). A permit or warning for
    // this config would be for a fetch that provably cannot happen.
    #[skuld::test]
    fn no_tls_and_not_quic_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("host=cdn.example;mode=websocket"), Some(&e)),
            EffectiveEchDoh::None
        );
        assert_eq!(effective_ech_doh("ex-ray", None, Some(&e)), EffectiveEchDoh::None);
    }

    // `mode=quic` force-enables TLS even with no explicit `tls` flag
    // (config.go:290-294) — first-wins, matching every other flag here.
    #[skuld::test]
    fn quic_mode_reaches_ex_ray_without_an_explicit_tls_flag() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("host=cdn.example;mode=quic"), Some(&e)),
            EffectiveEchDoh::Holes
        );
        assert_eq!(
            effective_ech_doh("ex-ray", Some("host=cdn.example;mode=quic;mode=websocket"), Some(&e)),
            EffectiveEchDoh::Holes,
            "first-wins: the second mode= does not un-set the quic TLS force-enable"
        );
    }

    // A malformed `opts` string makes `inject_plugin_directives` return `Err`
    // and the plugin chain never starts — neither accessor may panic, and
    // both must read this as "nothing reaches ex-ray".
    #[skuld::test]
    fn malformed_opts_reaches_ex_ray_as_nothing_not_a_panic() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert!(!ech_doh_will_reach_ex_ray("ex-ray", Some(r"path=/a\"), Some(&e)));
        assert_eq!(
            effective_ech_doh("ex-ray", Some(r"path=/a\"), Some(&e)),
            EffectiveEchDoh::None
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
