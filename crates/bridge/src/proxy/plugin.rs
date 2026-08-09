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
/// (`crates/ex-ray/config.go:65`: `flag.String("host", "cloudfront.com", ...)`)
/// — a real DOMAIN, not "no SNI". An absent `host` segment is NOT the same
/// as an unreachable config; see `ex_ray_default_host_matches_vendored_config_go`
/// for the executable pin against the vendored Go source (can't run the Go
/// code itself, but a text-level assertion still fails loudly if the
/// literal ever changes there without a matching edit here).
const EX_RAY_DEFAULT_HOST: &str = "cloudfront.com";

/// Whether ex-ray's own config-build step — `parseOptsIntoFlags`
/// (options.go, main.go), `registerTCPKeepAlive` + `generateConfig`
/// (config.go), run before `server.Start()` — would REJECT this segment set
/// outright, in which case the whole plugin process exits (23) before it
/// dials anything at all, ECH-config fetch included. Returns the rejecting
/// key, first-wins (matching `Args.Get`) among segments sharing a key,
/// checked in ex-ray's OWN evaluation order below so the diagnostic names
/// the key ex-ray itself would report first — the cover-permit /
/// reachability side only needs `.is_some()`, order-independent.
///
/// `parseOptsIntoFlags` shares one rule across every option it validates: an
/// ABSENT key is a no-op (the flag keeps its default); any PRESENT value —
/// an explicitly empty one included — must be well-formed or the option is
/// fatal. Checked in `parseOptsIntoFlags`'s own order:
/// - `mux` (`parseIntOption`): a present value `strconv.Atoi` can't parse
///   (non-numeric, or explicitly empty) is fatal — galoshes appends `mux=0`
///   and ex-ray is first-wins, so an operator's own unparseable `mux=` must
///   not silently win over it and leave Mux.Cool on.
/// - `tcp-keepalive` (`parseIntOption`): same parse rule as `mux`.
/// - `tls` (`parseBoolOption`): a present value other than `"1"` is fatal —
///   a presence-only flag with no wider "truthy" vocabulary.
/// - `host`/`path` (`parseStringOption`, `emptyOK=false`): a present but
///   EXPLICITLY EMPTY value is fatal — unlike `cert`/`certRaw`/`key`
///   (`emptyOK=true`, disclosed below), empty has no documented meaning for
///   these two. [`ech_fetch_is_reachable`] relies on this rather than
///   modeling its own fallback for an empty `host=` — see that function's
///   doc.
/// - `server`/`fastOpen`/`__android_vpn` (`parseBoolOption`): same
///   present-value rule as `tls`.
/// - `fwmark` (`parseIntOption`): same parse rule as `mux`.
/// - `ech` is a CLOSED enum (`parseEnumOption`) — validated
///   UNCONDITIONALLY here, not only when TLS is enabled: `generateConfig`
///   separately rejects `ech=always` with TLS not enabled (below), the
///   TLS-dependent half of `ech`'s validation.
/// - `ech-doh` (`parseURLOption`): empty is a documented no-op ("disables
///   ECH"), but a present, non-empty value that isn't a well-formed
///   `https://` URL with a host is fatal. Checked only when the CONFIG's
///   own value is what ex-ray will actually read: Hole's own injection
///   (always well-formed by construction) strips it whenever
///   [`ech_doh_displaces`] is true.
///
/// Then `registerTCPKeepAlive` and main()'s own pre-`generateConfig` guards:
/// - `tcp-keepalive`, again: a value that parsed above is now range-checked
///   against `tcpKeepAliveParams`' `0..=32767` — EXCEPT under a `server`
///   segment: `registerTCPKeepAlive` returns early for `*server`, without
///   range-checking; server mode's own range check is unconditional inside
///   `generateConfig` instead, much later (below).
/// - `localPort` (main.go's cross-assign + `validPort` ==
///   `net.PortFromString`): must be an unsigned base-10 literal `<=65535`
///   and not `0` — `0` is otherwise valid syntax
///   (`net.PortFromString("0")` succeeds) but ex-ray cannot honor
///   OS-assigned-port semantics. Under a `server` segment, main.go
///   cross-assigns the `remotePort` KEY here instead of `localPort` — but
///   both keys share this exact rule, so which one is checked never
///   changes the verdict, only (irrelevantly) which literal key name a
///   hypothetical diagnostic would cite; not worth branching on.
/// - `localAddr` (main.go's cross-assign + `canonicalLocalAddr`): must be a
///   single (`|`-free) IP literal — a domain or a `|`-joined multi-address
///   list is fatal, since the sitrep's `ready` event can report only one
///   `listen` address. Under a `server` segment, main.go cross-assigns the
///   `remoteAddr` KEY to `*localAddr` — UNLIKE the port pair above, this
///   rule genuinely differs from `remoteAddr`'s own (below), so which key
///   is checked against which rule swaps under `server`.
///
/// Then `generateConfig`:
/// - `remotePort`, same rule and same server-mode key-swap non-issue as
///   `localPort` above, checked here instead.
/// - `remoteAddr`: must not normalize to an empty domain or the unspecified
///   IP (`0.0.0.0`/`::`) — freedom's destination override would otherwise
///   dial nowhere honestly. Under a `server` segment, checked against the
///   `localAddr` KEY instead (swapped with the bullet above, same
///   cross-assign).
/// - `mux`, again: a value that parsed above is now range-checked against
///   `uint32Opt`'s `0..=u32::MAX`.
/// - `fwmark`, same range check as `mux`.
/// - `mode` is a CLOSED enum (`switch *mode`): outside `websocket`/`quic`
///   is fatal.
/// - `ech=always` with TLS not enabled is fatal — the TLS-dependent half of
///   `ech`'s validation (above): a valid-vocabulary `ech=always` with no
///   `tls` and no `mode=quic` promises fail-closed ECH it cannot deliver.
/// - `cert`/`certRaw`/`key` present (non-empty) with TLS not enabled is
///   fatal too — the material would otherwise be silently never read.
/// - `tcp-keepalive`, again, under a `server` segment ONLY (the
///   `registerTCPKeepAlive`-position check above skips it there): the same
///   `0..=32767` range check `generateConfig` itself runs unconditionally,
///   regardless of `*server`.
/// - `ech=always` additionally requires a non-empty RESOLVED `ech-doh`
///   (`buildTLSConfig`, reached only `if *tlsEnabled`) — the value ex-ray
///   actually receives once Hole's own injection wins or loses against the
///   operator's; see [`resolved_ech_doh_is_empty`] for why that is
///   recomputed rather than shared with [`classify_ech_doh`].
///
/// Then `core.New`, once `generateConfig` has fully succeeded:
/// - `mux`, a THIRD time: a non-zero `Concurrency` outside `1..=1024` on
///   the websocket transport only (`quic`'s mux is never read).
///
/// `mux`/`fwmark` are each checked TWICE (parse, then range) at their own
/// two real positions above — no order fidelity is relaxed for these two.
/// `tcp-keepalive` is checked twice too, but at ONE OF TWO MUTUALLY
/// EXCLUSIVE positions depending on `server` (never both), not the same
/// position regardless of mode.
///
/// **Not modeled, and why it's safe not to:** `loglevel` is ALSO fatal when
/// explicitly empty (`parseStringOption`) or unrecognized (`logConfig`) —
/// but `inject_plugin_directives` ALWAYS strips the operator's own
/// `loglevel` and appends `loglevel=debug`, unconditionally, whether or not
/// Hole's `ech-doh` wins. No value from `segments` (read pre-injection
/// here) ever reaches ex-ray unmodified, so modeling it would produce a
/// FALSE fatal for a config that starts fine in practice — the opposite of
/// the over-permit risk this gate exists to close.
///
/// **Disclosed, deliberately unmodeled:** `cert`/`certRaw`/`key`'s CONTENT
/// (a readable, well-formed X509 pair) requires filesystem I/O this
/// otherwise-pure gate doesn't perform — only their presence-without-TLS is
/// checked above. `server`'s `localAddr`/`remoteAddr` cross-assign IS
/// modeled (the two bullets above); its `mux`-concurrency exemption is
/// modeled too (`core.New` bullet below). What stays unmodeled: whether
/// ex-ray's OWN v2ray-core dependency even performs the DoH fetch this gate
/// reasons about for a server listener at all — `GetTLSConfig` is called
/// directly for server listeners too (their own doc: "only server
/// listeners... call this directly"), and `ApplyECH` doesn't itself branch
/// on `*server`, but `ech_fetch_is_reachable`'s empty-stripped-SNI fallback
/// specifically models `tls.WithDestination`, a CLIENT-DIAL option
/// (`websocket/dialer.go`) with no evident server-listener equivalent in
/// this vendored source — modeling that with confidence needs tracing
/// v2ray-core's server-listener construction path, not attempted here.
/// Hole never spawns ex-ray as a server regardless, so an operator would
/// have to hand-author `server` into their own `plugin_opts` to reach any
/// of this. See CONTRIBUTING.md's "ECH-config-fetch reachability gate"
/// section for why.
fn ex_ray_fatal_config_error(
    segments: &[garter::OptionSegment<'_>],
    ech_doh: Option<&crate::dns::ech::EchDoh>,
) -> Option<&'static str> {
    // parseOptsIntoFlags, in its own internal order.
    for key in ["mux", "tcp-keepalive"] {
        if segments
            .iter()
            .find(|s| s.key == key)
            .is_some_and(|s| ex_ray_flag_value(s).parse::<i64>().is_err())
        {
            return Some(key);
        }
    }
    if segments
        .iter()
        .find(|s| s.key == "tls")
        .is_some_and(|s| ex_ray_flag_value(s) != "1")
    {
        return Some("tls");
    }
    for key in ["host", "path"] {
        if segments
            .iter()
            .find(|s| s.key == key)
            .is_some_and(|s| ex_ray_flag_value(s).is_empty())
        {
            return Some(key);
        }
    }
    for key in ["server", "fastOpen", "__android_vpn"] {
        if segments
            .iter()
            .find(|s| s.key == key)
            .is_some_and(|s| ex_ray_flag_value(s) != "1")
        {
            return Some(key);
        }
    }
    if segments
        .iter()
        .find(|s| s.key == "fwmark")
        .is_some_and(|s| ex_ray_flag_value(s).parse::<i64>().is_err())
    {
        return Some("fwmark");
    }
    let ech = segments.iter().find(|s| s.key == "ech").map(ex_ray_flag_value);
    if let Some(v) = ech {
        if !matches!(v, "never" | "auto" | "always") {
            return Some("ech");
        }
    }
    if let Some(s) = segments.iter().find(|s| s.key == "ech-doh") {
        let v = ex_ray_flag_value(s);
        if !v.is_empty() && !ech_doh_displaces(segments, ech_doh) && !ex_ray_value_is_https_url(v) {
            return Some("ech-doh");
        }
    }

    // registerTCPKeepAlive + main()'s own pre-generateConfig guards.
    // registerTCPKeepAlive returns early under `*server` WITHOUT
    // range-checking — server mode's own tcp-keepalive range check is
    // unconditional inside generateConfig instead, much later (see below),
    // so it must not fire here too.
    let server_present = segments.iter().any(|s| s.key == "server");
    if !server_present
        && segments.iter().find(|s| s.key == "tcp-keepalive").is_some_and(|s| {
            !ex_ray_flag_value(s)
                .parse::<i64>()
                .is_ok_and(|v| (0..=32767).contains(&v))
        })
    {
        return Some("tcp-keepalive");
    }
    if segments
        .iter()
        .find(|s| s.key == "localPort")
        .is_some_and(|s| !matches!(ex_ray_parses_as_uint32(ex_ray_flag_value(s)), Some(p) if p != 0 && p <= 65535))
    {
        return Some("localPort");
    }
    // main.go's cross-assign sends a `localAddr` OPTION to `*remoteAddr`
    // under `*server` — so the KEY validated against `*localAddr`'s own
    // rule (a single IP literal) is `remoteAddr`, not `localAddr`, in that
    // mode. The two rules genuinely differ (unlike the port pair below,
    // where both directions share one rule), so the swap changes the
    // verdict.
    let (local_addr_key, remote_addr_key) = if server_present {
        ("remoteAddr", "localAddr")
    } else {
        ("localAddr", "remoteAddr")
    };
    if segments
        .iter()
        .find(|s| s.key == local_addr_key)
        .is_some_and(|s| ex_ray_local_addr_is_invalid(ex_ray_flag_value(s)))
    {
        return Some(local_addr_key);
    }

    // generateConfig.
    if segments
        .iter()
        .find(|s| s.key == "remotePort")
        .is_some_and(|s| !matches!(ex_ray_parses_as_uint32(ex_ray_flag_value(s)), Some(p) if p != 0 && p <= 65535))
    {
        return Some("remotePort");
    }
    if segments
        .iter()
        .find(|s| s.key == remote_addr_key)
        .is_some_and(|s| ex_ray_remote_addr_is_invalid(ex_ray_flag_value(s)))
    {
        return Some(remote_addr_key);
    }
    for key in ["mux", "fwmark"] {
        if segments.iter().find(|s| s.key == key).is_some_and(|s| {
            !ex_ray_flag_value(s)
                .parse::<i64>()
                .is_ok_and(|v| (0..=i64::from(u32::MAX)).contains(&v))
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
    if ech == Some("always") && !tls_enabled {
        return Some("ech");
    }
    let cert_material_present = ["cert", "certRaw", "key"].iter().any(|key| {
        segments
            .iter()
            .find(|s| s.key == *key)
            .is_some_and(|s| !ex_ray_flag_value(s).is_empty())
    });
    if !tls_enabled && cert_material_present {
        return Some("cert");
    }
    // Server mode's own tcp-keepalive range check — unconditional inside
    // generateConfig, unlike registerTCPKeepAlive above, which never runs
    // it for `*server`.
    if server_present
        && segments.iter().find(|s| s.key == "tcp-keepalive").is_some_and(|s| {
            !ex_ray_flag_value(s)
                .parse::<i64>()
                .is_ok_and(|v| (0..=32767).contains(&v))
        })
    {
        return Some("tcp-keepalive");
    }
    if ech == Some("always") && tls_enabled && resolved_ech_doh_is_empty(segments, ech_doh) {
        return Some("ech-doh");
    }

    // core.New, once generateConfig has fully succeeded (doc: mux, a third
    // time; skipped alongside the server residual).
    if mode != Some("quic") && !server_present {
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
/// that will — three independent conditions, each first-wins (matching
/// `Args.Get`):
/// - [`ex_ray_fatal_config_error`] is `Some` — the whole plugin process
///   exits before it ever starts, so no dial of any kind happens. This also
///   covers an EXPLICITLY EMPTY `host=`: `parseStringOption(..., "host",
///   ..., emptyOK: false)` rejects it at parse time, so `*host` can never
///   actually BE `""` this way when `buildTLSConfig` runs.
/// - `ech=never` short-circuits ECH entirely before it ever looks at
///   `ech-doh` (config.go).
/// - TLS must be enabled at all — an explicit `tls` flag, or `mode=quic`
///   forcing it on — since `buildTLSConfig` (which contains the whole `ech`
///   switch) is called only when `tlsEnabled`; a plain non-quic transport
///   (e.g. `mode=websocket` with no `tls`) never calls it.
/// - `ApplyECH` bails before dialing DoH unless the TLS `ServerName` is a
///   DOMAIN: ex-ray sets `tlsConfig.ServerName = *host` directly, and an
///   ABSENT `host` falls back to ex-ray's own [`EX_RAY_DEFAULT_HOST`], a
///   real domain, so it's reachable. An EXPLICIT `host=<value>` wins
///   outright, domain or not — EXCEPT that `GetTLSConfig` resolves
///   `config.ServerName` via `parseServerName` before `ApplyECH` ever reads
///   it, which strips a literal [`V2RAY_CORE_EXP_8357_PREFIX`] prefix
///   first. If THAT strip leaves `*host` empty (only when `*host` is
///   EXACTLY the bare prefix — an explicit `host=` alone is already fatal,
///   above), `config.ServerName` is NOT `""`: `GetTLSConfig` applies
///   `WithDestination` (an `Option` in its `opts...` — the websocket client
///   dialer always passes one) BEFORE the `parseServerName` assignment,
///   and `WithDestination` only ever fills an ALREADY-`""` `ServerName`
///   from the dial destination — so the empty-after-strip case reaches
///   `ApplyECH` with `remoteAddr` as its SNI, same first-wins rule as every
///   other key here (third_party/v2ray-core/transport/internet/tls/
///   config.go:20,173-183,262-264,296-301,371-381; `ech.go:26-51,37-51`;
///   `websocket/dialer.go:67`).
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
    let sni = segments
        .iter()
        .find(|s| s.key == "host")
        .map_or(EX_RAY_DEFAULT_HOST, ex_ray_flag_value);
    // `parseServerName` strips this prefix before `ApplyECH` ever sees the
    // SNI — an unstripped `sni` here can read as a domain (e.g.
    // "experiment:8357203.0.113.5") while the stripped value ex-ray
    // actually uses ("203.0.113.5") is an IP, unreachable.
    let sni = sni.strip_prefix(V2RAY_CORE_EXP_8357_PREFIX).unwrap_or(sni);
    // An absent `remoteAddr` falls back to Hole's own `SS_REMOTE_HOST` (env,
    // invisible here) — but is ALWAYS an IP literal in Hole's own spawn path
    // (`garter::binary::sip003_env` passes an already-resolved `SocketAddr`),
    // so treating an absent value as `""` here is safe.
    let sni = if sni.is_empty() {
        segments
            .iter()
            .find(|s| s.key == "remoteAddr")
            .map_or("", ex_ray_flag_value)
    } else {
        sni
    };
    tls_enabled && v2ray_core_parses_as_a_domain(sni)
}

/// v2ray-core's `Config.parseServerName` strips this literal prefix from the
/// TLS `ServerName` before `ApplyECH` (and `GetTLSConfig` generally) ever
/// reads it (third_party/v2ray-core/transport/internet/tls/config.go:20).
/// Pinned against the vendored source by
/// `ech_and_mode_enums_match_vendored_config_go`.
const V2RAY_CORE_EXP_8357_PREFIX: &str = "experiment:8357";

/// A segment's value the way ex-ray's own parser reads it (see
/// [`garter::OptionSegment::has_value`]), not the raw `garter` decode.
fn ex_ray_flag_value<'a>(s: &'a garter::OptionSegment<'_>) -> &'a str {
    if s.has_value {
        &s.value
    } else {
        "1"
    }
}

/// Mirrors v2ray-core's `net.ParseAddress` normalization
/// (third_party/v2ray-core/common/net/address.go:78-95): strips ONE matched
/// `[...]` bracket pair, then trims surrounding whitespace ONLY when the
/// first or last byte isn't alphanumeric.
fn v2ray_core_normalize(value: &str) -> &str {
    let bytes = value.as_bytes();
    let unbracketed = if !bytes.is_empty() && bytes[0] == b'[' && bytes[bytes.len() - 1] == b']' {
        &value[1..value.len() - 1]
    } else {
        value
    };
    let ub = unbracketed.as_bytes();
    let needs_trim = !ub.is_empty() && (!ub[0].is_ascii_alphanumeric() || !ub[ub.len() - 1].is_ascii_alphanumeric());
    if needs_trim {
        unbracketed.trim()
    } else {
        unbracketed
    }
}

/// Whether `value` parses as a v2ray-core DOMAIN address (non-empty, not an
/// IP) once normalized as [`v2ray_core_normalize`]. An empty result
/// (whether from the input or after normalization) is never a domain —
/// `echCacheDomain`'s own caller excludes it explicitly.
fn v2ray_core_parses_as_a_domain(value: &str) -> bool {
    let normalized = v2ray_core_normalize(value);
    !normalized.is_empty() && normalized.parse::<std::net::IpAddr>().is_err()
}

/// Whether `value` parses as a v2ray-core IP-family address once normalized
/// as [`v2ray_core_normalize`] — used by [`ex_ray_fatal_config_error`] for
/// `localAddr`'s `canonicalLocalAddr` check, which requires an IP literal.
fn v2ray_core_parses_as_an_ip(value: &str) -> bool {
    v2ray_core_normalize(value).parse::<std::net::IpAddr>().is_ok()
}

/// Whether ex-ray's `canonicalLocalAddr` (config.go, reachable from main()'s
/// pre-bind guard) would reject `value` for `localAddr`: not exactly one
/// (`|`-free) address, or not an IP literal once normalized.
fn ex_ray_local_addr_is_invalid(value: &str) -> bool {
    value.contains('|') || !v2ray_core_parses_as_an_ip(value)
}

/// Whether ex-ray's `generateConfig` (config.go) would reject `value` for
/// `remoteAddr`: an empty domain (normalizes to `""`, `ParseAddress`'s own
/// domain fallback), or the unspecified IP (`0.0.0.0`/`::`) — freedom's
/// destination override would otherwise dial nowhere honestly.
///
/// `IpAddr::to_canonical()` folds an IPv4-mapped IPv6 literal
/// (`::ffff:0.0.0.0`) to plain IPv4 BEFORE the unspecified test, mirroring
/// v2ray-core's own `IPAddress()` constructor (third_party/v2ray-core/
/// common/net/address.go:99-101, `bytes[:10]==0 && [10]==[11]==0xff`) —
/// without the fold, `Ipv6Addr::is_unspecified()` (`octets() == [0; 16]`)
/// misses it: `::ffff:0.0.0.0`'s last four octets are `0.0.0.0`, but its
/// 11th/12th are `0xff`, so the raw 16-byte check reads it as specified.
fn ex_ray_remote_addr_is_invalid(value: &str) -> bool {
    let normalized = v2ray_core_normalize(value);
    match normalized.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.to_canonical().is_unspecified(),
        Err(_) => normalized.is_empty(),
    }
}

/// Whether ex-ray's `parseURLOption(opts, "ech-doh", ...)` (options.go)
/// would accept `v` as a well-formed DoH URL: `url.Parse` succeeding, an
/// `https` scheme, and a non-empty host. Only checked for the CONFIG's own
/// `ech-doh` value, and only when it is NOT displaced by Hole's own — see
/// [`ex_ray_fatal_config_error`]'s `ech-doh` bullet, which means a FALSE
/// negative here (this function says "well-formed" for something Go's
/// `net/url` would reject) can only ever suppress the never-permitted
/// `EffectiveEchDoh::Operators` residual-stall diagnostic — the fail-closed
/// cover never permits an operator-chosen address regardless, so it cannot
/// widen the permit. A FALSE positive (rejecting something Go accepts)
/// WOULD be unsafe here (an under-permit masquerading as an over-cautious
/// fatal), so this is deliberately a lenient superset check — a
/// case-insensitive `https://` prefix plus a non-empty authority segment up
/// to the first `/`, `?`, or `#` — rather than a byte-exact port of Go's
/// `net/url.Parse`: the `url` crate's stricter WHATWG parser rejects
/// syntax Go accepts (verified: Go accepts `https://999.1.1.1/` and
/// `https://1.2.3.4.5/dns-query`, the `url` crate errors on both with
/// `InvalidIpv4Address`), which would have been the unsafe direction.
fn ex_ray_value_is_https_url(v: &str) -> bool {
    let Some(rest) = v
        .get(..8)
        .filter(|p| p.eq_ignore_ascii_case("https://"))
        .map(|_| &v[8..])
    else {
        return false;
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    !rest[..authority_end].is_empty()
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
    // (config.go:360-361: `if *echDoh != "" { tlsConfig.Ech_DOHserver =
    // *echDoh }`) — an EMPTY operator value is inert, same as no `ech-doh`
    // at all. A BARE `ech-doh` (no `=`) is different: it reads as ex-ray's
    // own literal `"1"` (args.go), not an empty string, and `parseURLOption`
    // (options.go) rejects any non-empty value that isn't a well-formed
    // `https://` URL — so a bare `ech-doh` is FATAL, not inert;
    // `ech_fetch_is_reachable`'s check above (which reads
    // `ex_ray_fatal_config_error`) already routes it to `None` before this
    // line is ever reached.
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
            // arms `Ech_DOHserver` for a NON-empty value (same rule
            // `classify_ech_doh` already applies to its `Operators` arm) —
            // an explicitly empty `ech-doh=` must read as "no config
            // value", not as one standing.
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
                // ECH is armed only by `ech-doh`, so there is none. `ech=always`
                // can't reach here — `ex_ray_fatal_config_error` already routes
                // it through the fatal-config warning above (see that fn's
                // doc). No `fail_closed` field to report.
                (None, None) => tracing::warn!(plugin = %plugin_name, "no ech-doh from any source; ECH is off"),
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
            Some("ech"),
            "ech's enum check runs unconditionally in parseOptsIntoFlags, structurally before \
             generateConfig's mode switch even starts"
        );
        let segments = garter::split_plugin_options("tls=99;host=cdn.example;localAddr=bad-addr").unwrap();
        assert_eq!(
            ex_ray_fatal_config_error(&segments, None),
            Some("tls"),
            "tls (parseOptsIntoFlags) runs before localAddr (main(), after parseOptsIntoFlags \
             returns) — a key checked in generateConfig/main()'s own pre-generateConfig guards must \
             never win over one checked earlier, inside parseOptsIntoFlags itself"
        );
        // Under `server`, tcp-keepalive's range check moves from the early
        // registerTCPKeepAlive position all the way to generateConfig's own
        // unconditional call, well after `mode` — so `mode` must now win.
        let segments = garter::split_plugin_options("server;host=cdn.example;mode=bogus;tcp-keepalive=99999").unwrap();
        assert_eq!(
            ex_ray_fatal_config_error(&segments, None),
            Some("mode"),
            "registerTCPKeepAlive skips the range check under *server; generateConfig's own mode \
             switch runs long before its own (also unconditional) tcp-keepalive range check"
        );
    }

    // As `two_distinct_fatal_keys_report_ex_rays_earlier_one`'s server-mode
    // case, exercised end to end: `registerTCPKeepAlive` skips
    // `tcp-keepalive`'s range check under `*server`, but `generateConfig`
    // still range-checks it unconditionally, later — this must still be
    // fatal, just at the later position.
    #[skuld::test]
    fn a_fatal_tcp_keepalive_value_under_server_still_reaches_the_late_check() {
        let segments = garter::split_plugin_options("server;host=cdn.example;tcp-keepalive=99999").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("tcp-keepalive"));
    }

    // ex-ray reads the FIRST `ech`, so a later `always` it will never apply must
    // not be reported as a fail-closed posture. `tls` and a pinned candidate are
    // required on both inputs so neither trips the (unrelated) ech=always-requires-
    // tls / ech=always-requires-resolved-ech-doh fatal checks.
    #[skuld::test]
    fn fail_closed_reads_the_first_ech_not_any_of_them() {
        // Unpinned, not pinned: a pinned candidate reaches the silent
        // `(Some(_), _) => {}` warning arm (nothing to report), which would
        // never contain "fail_closed" at all.
        let e = unpinned("https://9.9.9.9/dns-query");
        let out = warnings_for("ex-ray", Some("tls;ech=never;ech=always"), Some(&e));
        assert!(
            out.contains("fail_closed=false"),
            "the first `ech` is `never`; got:
{out}"
        );
        let out = warnings_for("ex-ray", Some("tls;ech=always;ech=never"), Some(&e));
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

    // A bare `ech-doh` (no `=`) reads as ex-ray's own `"1"` — non-empty, but
    // not a well-formed `https://` URL (`parseURLOption`), so it is a fatal
    // config error (`parseOptsIntoFlags`) rather than a value ex-ray tries
    // and fails on later; the whole process exits before dialing anything.
    #[skuld::test]
    fn bare_operator_ech_doh_never_reaches_ex_ray() {
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;ech-doh"), None),
            EffectiveEchDoh::None
        );
        let segments = garter::split_plugin_options("tls;host=cdn.example;ech-doh").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("ech-doh"));
    }

    // A malformed operator `ech-doh` that Hole's OWN value DISPLACES is
    // stripped before ex-ray ever sees it (`inject_plugin_directives`), so
    // it must NOT be reported as fatal — the malformed string never reaches
    // the plugin at all.
    #[skuld::test]
    fn a_malformed_operator_ech_doh_displaced_by_holes_own_is_not_fatal() {
        let e = pinned("https://9.9.9.9/dns-query");
        let segments = garter::split_plugin_options("tls;host=cdn.example;ech-doh=not-a-url").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, Some(&e)), None);
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;ech-doh=not-a-url"), Some(&e)),
            EffectiveEchDoh::Holes
        );
    }

    // `ech`'s enum check (`parseEnumOption`, `parseOptsIntoFlags`) is
    // UNCONDITIONAL — it does not live only inside `buildTLSConfig` (`if
    // *tlsEnabled`). An invalid `ech` value with no `tls` flag and no
    // `mode=quic` is fatal too, even though the fetch itself is
    // (separately) unreachable either way — see
    // `no_tls_and_not_quic_never_reaches_ex_ray` for that half.
    #[skuld::test]
    fn an_invalid_ech_value_without_tls_is_fatal() {
        let segments = garter::split_plugin_options("host=cdn.example;ech=bogus").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("ech"));
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

    // A value that overflows the parse itself (u32::MAX) is a distinct
    // failure mode from the range check below and must independently be
    // caught by `ex_ray_parses_as_uint32`.
    #[skuld::test]
    fn a_remote_port_above_u32_max_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;remotePort=4294967296"), Some(&e)),
            EffectiveEchDoh::None
        );
    }

    // As above, for `localPort`.
    #[skuld::test]
    fn a_local_port_above_u32_max_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;localPort=4294967296"), Some(&e)),
            EffectiveEchDoh::None
        );
    }

    // `remotePort` routes through the SAME `validPort` as `localPort`
    // (config.go), so it shares localPort's tighter 65535 ceiling and its
    // `0` rejection, not a bare `strconv.ParseUint(_, 10, 32)` with no
    // upper bound beyond u32::MAX and no zero check.
    #[skuld::test]
    fn a_remote_port_shares_local_ports_ceiling_and_zero_rejection() {
        let e = pinned("https://9.9.9.9/dns-query");
        for opts in [
            "tls;host=cdn.example;remotePort=65536", // within u32::MAX, above the 65535 ceiling
            "tls;host=cdn.example;remotePort=0",
            "tls;host=cdn.example;remotePort=",
        ] {
            assert_eq!(
                effective_ech_doh("ex-ray", Some(opts), Some(&e)),
                EffectiveEchDoh::None,
                "opts={opts:?}"
            );
        }
    }

    // Non-canonical-zero coverage: `"00"` is valid `strconv.ParseUint`
    // syntax (parses to `0`), so it is caught by `validPort`'s `== 0`
    // rejection, not by a parse failure — a check that only compared
    // against the LITERAL string `"0"` would miss it.
    #[skuld::test]
    fn a_non_canonical_zero_local_port_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;localPort=00"), Some(&e)),
            EffectiveEchDoh::None
        );
        let segments = garter::split_plugin_options("tls;host=cdn.example;localPort=00").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("localPort"));
    }

    // `tls`/`server`/`fastOpen`/`__android_vpn` (`parseBoolOption`) accept
    // ONLY a present `"1"` (or a bare key, which `Args` maps to `"1"`) —
    // any other present value is fatal.
    #[skuld::test]
    fn a_bool_option_with_a_value_other_than_1_is_fatal() {
        for (key, opts) in [
            ("tls", "tls=0;host=cdn.example"),
            ("tls", "tls=true;host=cdn.example"),
            ("server", "tls;host=cdn.example;server=0"),
            ("fastOpen", "tls;host=cdn.example;fastOpen=0"),
            ("__android_vpn", "tls;host=cdn.example;__android_vpn=0"),
        ] {
            let segments = garter::split_plugin_options(opts).unwrap();
            assert_eq!(ex_ray_fatal_config_error(&segments, None), Some(key), "opts={opts:?}");
        }
    }

    // `path` (`parseStringOption`, `emptyOK=false`) is fatal when
    // EXPLICITLY empty, same rule as `host`.
    #[skuld::test]
    fn an_explicitly_empty_path_is_fatal() {
        let segments = garter::split_plugin_options("tls;host=cdn.example;path=").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("path"));
    }

    // `localAddr` (main.go's cross-assign + `canonicalLocalAddr`) must be a
    // single IP literal — a domain or a `|`-joined multi-address list is
    // fatal.
    #[skuld::test]
    fn an_invalid_local_addr_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        for opts in [
            "tls;host=cdn.example;localAddr=cdn.example",   // domain, not an IP
            "tls;host=cdn.example;localAddr=127.0.0.1|::1", // multi-address
        ] {
            assert_eq!(
                effective_ech_doh("ex-ray", Some(opts), Some(&e)),
                EffectiveEchDoh::None,
                "opts={opts:?}"
            );
        }
        let segments = garter::split_plugin_options("tls;host=cdn.example;localAddr=cdn.example").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("localAddr"));
    }

    // Under `server`, main.go cross-assigns a `localAddr` OPTION to
    // `*remoteAddr` and a `remoteAddr` OPTION to `*localAddr` — so the
    // single-IP-literal rule (`localAddr`'s own) must be checked against the
    // `remoteAddr` KEY, and vice versa, or this either over-permits (a
    // config that is actually fatal reads as reachable) or under-permits (a
    // config that actually starts fine reads as unreachable, reintroducing
    // the ECH-fetch stall this PR closes).
    #[skuld::test]
    fn server_mode_swaps_which_key_the_address_rules_apply_to() {
        let e = pinned("https://9.9.9.9/dns-query");
        // Over-permit repro: under `server`, the `remoteAddr` OPTION lands
        // in `*localAddr`, so this domain value fails `canonicalLocalAddr`
        // and the whole process exits 23 — never reachable.
        let segments = garter::split_plugin_options("server;tls;host=cdn.example;remoteAddr=cdn.example").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("remoteAddr"));
        assert_eq!(
            effective_ech_doh(
                "ex-ray",
                Some("server;tls;host=cdn.example;remoteAddr=cdn.example"),
                Some(&e)
            ),
            EffectiveEchDoh::None
        );
        // Under-permit repro: under `server`, the `localAddr` OPTION lands
        // in `*remoteAddr`, which accepts a domain fine — ex-ray starts and
        // (per the file's own residual disclosure on server-mode DoH
        // reachability) may fetch.
        let segments = garter::split_plugin_options("server;tls;host=cdn.example;localAddr=cdn.example").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), None);
    }

    // `remoteAddr` (`generateConfig`) must not be an empty domain or the
    // unspecified IP (`0.0.0.0`/`::`) — a wrong destination that binds fine
    // and reports ready, then fails (or silently misroutes) every dial.
    #[skuld::test]
    fn an_unspecified_or_empty_remote_addr_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        for opts in [
            "tls;host=cdn.example;remoteAddr=0.0.0.0",
            "tls;host=cdn.example;remoteAddr=::",
            "tls;host=cdn.example;remoteAddr= ", // whitespace-only normalizes to empty
            // IPv4-mapped IPv6 spellings of the unspecified address — must be
            // folded to plain IPv4 (`to_canonical`) before the unspecified
            // test, matching v2ray-core's own `IPAddress()` constructor.
            "tls;host=cdn.example;remoteAddr=::ffff:0.0.0.0",
            "tls;host=cdn.example;remoteAddr=::ffff:0:0",
            "tls;host=cdn.example;remoteAddr=[::ffff:0.0.0.0]",
        ] {
            assert_eq!(
                effective_ech_doh("ex-ray", Some(opts), Some(&e)),
                EffectiveEchDoh::None,
                "opts={opts:?}"
            );
        }
        let segments = garter::split_plugin_options("tls;host=cdn.example;remoteAddr=0.0.0.0").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("remoteAddr"));
        let segments = garter::split_plugin_options("tls;host=cdn.example;remoteAddr=::ffff:0.0.0.0").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("remoteAddr"));
    }

    // `parseServerName` strips a literal `experiment:8357` prefix from the
    // TLS `ServerName` before `ApplyECH` ever reads it (v2ray-core's
    // config.go) — an unstripped `host` value can read as a domain to this
    // gate while ex-ray itself, after stripping, sees an IP and never dials.
    #[skuld::test]
    fn exp_8357_prefixed_host_is_evaluated_after_stripping() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=experiment:8357203.0.113.5"), Some(&e)),
            EffectiveEchDoh::None,
            "stripped SNI is the IP literal 203.0.113.5 — no domain to key the DoH lookup on"
        );
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=experiment:8357cdn.example"), Some(&e)),
            EffectiveEchDoh::Holes,
            "stripped SNI is the domain cdn.example — reachable"
        );
    }

    // `host` EXACTLY the bare prefix strips to an EMPTY `ServerName` —
    // `WithDestination` then fills it from `remoteAddr` instead (see
    // `ech_fetch_is_reachable`'s doc), so the fetch is reachable or not
    // based on `remoteAddr`, not on the (now-empty) stripped host.
    #[skuld::test]
    fn exp_8357_with_nothing_after_it_falls_back_to_remote_addr() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh(
                "ex-ray",
                Some("tls;host=experiment:8357;remoteAddr=cdn.example"),
                Some(&e)
            ),
            EffectiveEchDoh::Holes,
            "remoteAddr is a domain — reachable"
        );
        assert_eq!(
            effective_ech_doh(
                "ex-ray",
                Some("tls;host=experiment:8357;remoteAddr=203.0.113.5"),
                Some(&e)
            ),
            EffectiveEchDoh::None,
            "remoteAddr is an IP — unreachable"
        );
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=experiment:8357"), Some(&e)),
            EffectiveEchDoh::None,
            "no remoteAddr — falls back to Hole's own SS_REMOTE_HOST, always an IP literal"
        );
    }

    // `ex_ray_value_is_https_url` is a deliberately lenient superset of Go's
    // `net/url.Parse` (see its doc): a syntax the `url` crate's stricter
    // WHATWG parser rejects but Go accepts must still read as well-formed
    // here, or the operator's own (never-permitted, but still diagnosed)
    // `ech-doh` residual-stall warning would be wrongly suppressed.
    #[skuld::test]
    fn a_go_valid_but_whatwg_invalid_ech_doh_is_not_fatal() {
        for opts in [
            "tls;host=cdn.example;ech-doh=https://999.1.1.1/",
            "tls;host=cdn.example;ech-doh=https://1.2.3.4.5/dns-query",
            "tls;host=cdn.example;ech-doh=HTTPS://cdn.example/dns-query", // case-insensitive scheme
        ] {
            let segments = garter::split_plugin_options(opts).unwrap();
            assert_eq!(ex_ray_fatal_config_error(&segments, None), None, "opts={opts:?}");
        }
    }

    // A non-empty `cert`/`certRaw`/`key` with TLS not enabled is fatal —
    // the material would otherwise be silently never read.
    #[skuld::test]
    fn cert_material_without_tls_is_fatal() {
        for opts in [
            "host=cdn.example;cert=/tmp/cert.pem",
            "host=cdn.example;certRaw=deadbeef",
            "host=cdn.example;key=/tmp/key.pem",
        ] {
            let segments = garter::split_plugin_options(opts).unwrap();
            assert_eq!(
                ex_ray_fatal_config_error(&segments, None),
                Some("cert"),
                "opts={opts:?}"
            );
        }
    }

    // `loglevel` is NOT modeled: `inject_plugin_directives` always strips
    // the operator's own `loglevel` and appends `loglevel=debug`, so no
    // value from the pre-injection `segments` this gate reads ever reaches
    // ex-ray — an explicitly empty or unrecognized `loglevel` here must NOT
    // be reported as fatal, even though ex-ray itself would reject either
    // one directly.
    #[skuld::test]
    fn loglevel_is_never_modeled_as_fatal() {
        let e = pinned("https://9.9.9.9/dns-query");
        for opts in [
            "tls;host=cdn.example;loglevel=",
            "tls;host=cdn.example;loglevel=verbose",
        ] {
            assert_eq!(
                effective_ech_doh("ex-ray", Some(opts), Some(&e)),
                EffectiveEchDoh::Holes,
                "opts={opts:?}: loglevel is always overridden by Hole's own injection"
            );
        }
    }

    // `ech=always` with an empty RESOLVED `ech-doh` is itself a config-build
    // error (config.go's `buildTLSConfig`, `"ech=always requires ech-doh to
    // be set"`) distinct from a plain invalid `ech` value — ex-ray refuses
    // to start rather than merely skipping ECH. Reachable whenever Hole has
    // no candidate of its own (no pinned resolver) and the operator's own
    // config supplies none either.
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
    // rather than absent — same fatal check, same expectation.
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

    // `generateConfig` rejects `ech=always` outright when TLS isn't enabled
    // (`if *echMode == "always" && !*tlsEnabled`) — a valid-vocabulary
    // `ech=always` with no `tls` and no `mode=quic` promises fail-closed
    // ECH it cannot deliver. This is a DIFFERENT fatal reason than the
    // nested `ech=always` + empty-resolved-`ech-doh` check (which stays
    // gated inside `tls_enabled`, since `buildTLSConfig` itself is) — this
    // one is fatal precisely BECAUSE tls is off, regardless of whether an
    // `ech-doh` is configured at all.
    #[skuld::test]
    fn ech_always_without_tls_is_fatal() {
        let segments = garter::split_plugin_options("host=cdn.example;ech=always").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("ech"));
    }

    // `ech=always` can never reach `inject_plugin_directives`'s `(None,
    // None)` "no ech-doh from any source" warning arm: with no `ech_doh`
    // and no config-side `ech-doh`, `resolved_ech_doh_is_empty` is
    // unconditionally true, so `ex_ray_fatal_config_error` already routes
    // it through the fatal-config warning first — regardless of `tls`.
    #[skuld::test]
    fn ech_always_with_no_ech_doh_never_reaches_the_ech_is_off_warning() {
        for opts in ["ech=always", "tls;ech=always"] {
            let out = warnings_for("ex-ray", Some(opts), None);
            assert!(
                out.contains("ex-ray will refuse to start") && !out.contains("ECH is off"),
                "opts={opts:?}: expected the fatal-config warning, not the ECH-is-off one; got:\n{out}"
            );
        }
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

    // A `mux` that fails to parse at all is a config-build error too —
    // `parseIntOption`'s doc: an operator's own unparseable `mux=` must not
    // silently outrank galoshes' appended `mux=0` and leave Mux.Cool on.
    #[skuld::test]
    fn an_unparseable_mux_value_is_fatal() {
        let e = pinned("https://9.9.9.9/dns-query");
        assert_eq!(
            effective_ech_doh("ex-ray", Some("tls;host=cdn.example;mux=not-a-number"), Some(&e)),
            EffectiveEchDoh::None
        );
        let segments = garter::split_plugin_options("tls;host=cdn.example;mux=not-a-number").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("mux"));
    }

    // As above, for an explicitly EMPTY `mux=` specifically: galoshes
    // appends `mux=0`, ex-ray is first-wins, so a bare `mux=` an operator
    // left behind must not silently win over galoshes' append and leave
    // Mux.Cool on.
    #[skuld::test]
    fn an_explicitly_empty_mux_value_is_fatal() {
        let segments = garter::split_plugin_options("tls;host=cdn.example;mux=").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("mux"));
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

    // As `an_unparseable_mux_value_is_fatal`, for `fwmark` and
    // `tcp-keepalive` — `parseIntOption` is shared across all three.
    #[skuld::test]
    fn an_unparseable_fwmark_or_tcp_keepalive_value_is_fatal() {
        for (key, opts) in [
            ("fwmark", "tls;host=cdn.example;fwmark=not-a-number"),
            ("tcp-keepalive", "tls;host=cdn.example;tcp-keepalive=not-a-number"),
        ] {
            let segments = garter::split_plugin_options(opts).unwrap();
            assert_eq!(ex_ray_fatal_config_error(&segments, None), Some(key), "opts={opts:?}");
        }
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
    // (config.go's `buildTLSConfig`, `case "never":`) regardless of
    // `tls`/`host`/`ech-doh`.
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
    // otherwise) — an IP-literal `host` means "no SNI to key the lookup
    // on", matching v2ray-core's `net.ParseAddress` exactly: only a MATCHED
    // `[...]` pair strips, and only a non-alphanumeric edge trims
    // whitespace. (An explicitly EMPTY `host=` is a DIFFERENT, fatal case —
    // see `explicitly_empty_host_is_fatal` below, not this one.)
    #[skuld::test]
    fn no_domain_host_never_reaches_ex_ray() {
        let e = pinned("https://9.9.9.9/dns-query");
        for opts in [
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

    // `parseStringOption(opts, "host", host, false)` rejects a present,
    // explicitly EMPTY `host=` at parse time — the whole plugin process
    // exits before it ever dials anything, regardless of what `remoteAddr`
    // says (v2ray-core's own `tls.WithDestination` empty-`ServerName`
    // fallback to the dial destination still exists but is unreachable via
    // `plugin_opts` — see `ech_fetch_is_reachable`'s doc).
    #[skuld::test]
    fn explicitly_empty_host_is_fatal() {
        let e = pinned("https://9.9.9.9/dns-query");
        for opts in [
            "tls;host=",
            "tls;host=;remoteAddr=cdn.example",
            "tls;host=;remoteAddr=203.0.113.5",
        ] {
            assert_eq!(
                effective_ech_doh("ex-ray", Some(opts), Some(&e)),
                EffectiveEchDoh::None,
                "opts={opts:?}: host= is fatal regardless of remoteAddr"
            );
        }
        let segments = garter::split_plugin_options("tls;host=").unwrap();
        assert_eq!(ex_ray_fatal_config_error(&segments, None), Some("host"));
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
    // `switch *mode`, config.go) — a value outside the known set is
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
        // and localPort/remotePort (`validPort`) — same drift risk, same
        // pin. Pinned on the COMPARISON itself, not `uint32Opt`'s error
        // message: the message is free to change for reasons that have
        // nothing to do with the bound it protects (e.g. to stop a
        // mux=abc\;certRaw=SECRET-shaped escape from leaking a later
        // segment's value through it) — a message-text pin would go stale
        // for that unrelated reason, and did.
        assert!(
            source.contains("v >= 0 && v <= math.MaxUint32"),
            "ex_ray_fatal_config_error's mux/fwmark range (0..=u32::MAX) no longer matches \
             config.go's `uint32Opt` — update the range to the vendored source"
        );
        assert!(
            source.contains("keepAliveMaxSeconds = 32767"),
            "ex_ray_fatal_config_error's tcp-keepalive range (0..=32767) no longer matches \
             config.go's `keepAliveMaxSeconds` — update the range to the vendored source"
        );
        assert!(
            source.contains("rport, err := validPort(*remotePort)"),
            "ex_ray_fatal_config_error's remotePort ceiling (65535, shared with localPort) no \
             longer matches config.go — remotePort must still route through the same `validPort` \
             as localPort, not a bare `strconv.ParseUint`"
        );
        assert!(
            source.contains("family.IsIP() && remoteAddress.IP().IsUnspecified()"),
            "ex_ray_fatal_config_error's remoteAddr unspecified-IP check no longer matches \
             config.go — update ex_ray_remote_addr_is_invalid to the vendored source"
        );
        assert!(
            source.contains("func canonicalLocalAddr"),
            "ex_ray_fatal_config_error's localAddr IP-literal check no longer matches config.go's \
             `canonicalLocalAddr` — update ex_ray_local_addr_is_invalid to the vendored source"
        );
        assert!(
            source.contains("if *echMode == \"always\" && !*tlsEnabled {"),
            "ex_ray_fatal_config_error's ech=always-requires-tls check no longer matches \
             config.go — update the vendored source reference"
        );
        assert!(
            source.contains("if !*tlsEnabled && (*cert != \"\" || *certRaw != \"\" || *key != \"\") {"),
            "ex_ray_fatal_config_error's cert/certRaw/key-requires-tls check no longer matches \
             config.go — update the vendored source reference"
        );
        let port_source = include_str!("../../../ex-ray/third_party/v2ray-core/common/net/port.go");
        assert!(
            port_source.contains("if val > 65535 {"),
            "ex_ray_fatal_config_error's localPort/remotePort ceiling (65535) no longer matches \
             port.go's `PortFromInt` — update the bound to the vendored source"
        );
        let handler_source = include_str!("../../../ex-ray/third_party/v2ray-core/app/proxyman/outbound/handler.go");
        assert!(
            handler_source.contains("config.Concurrency < 1 || config.Concurrency > 1024"),
            "ex_ray_fatal_config_error's mux-concurrency range (1..=1024) no longer matches \
             handler.go's own bound — update the range to the vendored source"
        );

        let main_source = include_str!("../../../ex-ray/main.go");
        assert!(
            main_source.contains(r#"parseEnumOption(opts, "ech", allowedEchModes, echMode)"#),
            "ex_ray_fatal_config_error's unconditional `ech` enum check no longer matches \
             main.go's `parseOptsIntoFlags` — if this call moved back inside a `tlsEnabled` \
             gate, the check must be re-gated too"
        );

        let ech_source = include_str!("../../../ex-ray/third_party/v2ray-core/transport/internet/tls/config.go");
        assert!(
            ech_source.contains(&format!("const exp8357 = {V2RAY_CORE_EXP_8357_PREFIX:?}")),
            "V2RAY_CORE_EXP_8357_PREFIX no longer matches v2ray-core's own `exp8357` constant — \
             update the constant to the vendored source"
        );

        let options_source = include_str!("../../../ex-ray/options.go");
        assert!(
            options_source.contains("if c != \"1\" {"),
            "ex_ray_fatal_config_error's tls/server/fastOpen/__android_vpn bad-value check no \
             longer matches options.go's `parseBoolOption` — update the check to the vendored \
             source"
        );
        assert!(
            options_source.contains(r#"u.Scheme != "https" || u.Host == """#),
            "ex_ray_value_is_https_url no longer matches options.go's `parseURLOption` — update \
             the check to the vendored source"
        );
        assert!(
            main_source.contains(r#"parseStringOption(opts, "host", host, false)"#)
                && main_source.contains(r#"parseStringOption(opts, "path", path, false)"#),
            "ex_ray_fatal_config_error's host/path empty-is-fatal check no longer matches \
             main.go's `parseStringOption(..., emptyOK: false)` calls — update the check to the \
             vendored source"
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
    // with no `tls` flag (config.go's `if *tlsEnabled { ... }` guard, and
    // `mode=quic`'s own `*tlsEnabled = true` in the mode switch above it). A
    // permit or warning for this config would be for a fetch that provably
    // cannot happen.
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
    // (config.go's mode switch, `*tlsEnabled = true`) — first-wins, matching
    // every other flag here.
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
