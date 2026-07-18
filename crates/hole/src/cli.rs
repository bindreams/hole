// CLI subcommand dispatch.
//
// The `cli_log!` macro is exported from `crate::cli_log` at the crate root
// (visible here via `#[macro_use]` in `main.rs` and `lib.rs`).

use clap::{Parser, Subcommand};

// CLI structure =======================================================================================================

#[derive(Parser)]
#[command(name = "hole", about = "Shadowsocks GUI with transparent proxy", version = env!("HOLE_VERSION"))]
pub(crate) struct Cli {
    /// Open the dashboard window on launch instead of starting in the tray
    #[arg(long)]
    pub(crate) show_dashboard: bool,

    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Print version information
    Version,
    /// Check for updates and install the latest version
    Upgrade {
        /// Assume "yes" to the update consent prompt (for non-interactive use).
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Manage the privileged bridge service
    Bridge {
        #[command(subcommand)]
        action: BridgeAction,
    },
    /// Drive an installed bridge: start/stop the proxy and test servers
    Proxy {
        #[command(subcommand)]
        action: ProxyAction,
    },
    /// Manage PATH integration
    Path {
        #[command(subcommand)]
        action: PathAction,
    },
}

/// Proxy lifecycle subcommands. Thin wrappers over `BridgeRequest::Start` /
/// `Stop` / `TestServer` that read a `ServerEntry` from a JSON file. Designed
/// for the bug-repro workflow: hand-crafting a JSON config and driving the
/// running bridge from a shell without round-tripping through the GUI.
#[derive(Subcommand)]
pub(crate) enum ProxyAction {
    /// Start the proxy with a server config from a JSON file
    Start {
        /// Path to a JSON file containing a `ServerEntry` (server, server_port,
        /// method, password, optional plugin/plugin_opts).
        #[arg(long)]
        config_file: std::path::PathBuf,
        /// Local SOCKS5 port the bridge should bind.
        #[arg(long, default_value_t = 4073)]
        local_port: u16,
        /// Local HTTP CONNECT port the bridge should bind when
        /// `--http` is used. Defaults to 4074. Must differ from
        /// `--local-port` when both listeners are enabled.
        #[arg(long, default_value_t = 4074)]
        local_port_http: u16,
        /// Disable the user-facing SOCKS5 listener (default: enabled).
        /// With `--tunnel-mode full` this requires `--http` to be off
        /// too (a pure-VPN start: the TUN data plane binds an internal
        /// SOCKS5 listener on an ephemeral port; nothing listens on
        /// `--local-port`).
        #[arg(long)]
        no_socks5: bool,
        /// Enable the HTTP CONNECT listener (default: disabled). HTTP
        /// CONNECT is TCP-only; UDP still requires SOCKS5.
        #[arg(long)]
        http: bool,
        /// Tunnel mode. `full` installs the TUN adapter + split routes
        /// (the production default, requires elevation). `socks-only`
        /// binds only the SOCKS5 listener and skips all routing work
        /// (no elevation required; client-side SOCKS5 config needed).
        #[arg(long, value_enum, default_value_t = CliTunnelMode::Full)]
        tunnel_mode: CliTunnelMode,
    },
    /// Stop the proxy
    Stop,
    /// Run a one-shot connectivity test against a server config
    TestServer {
        /// Path to a JSON file containing a `ServerEntry`
        #[arg(long)]
        config_file: std::path::PathBuf,
    },
}

/// CLI-facing mirror of [`hole_common::protocol::TunnelMode`]. Separate
/// type because `clap::ValueEnum` wants kebab-case by default and the
/// wire protocol uses snake_case — converting here keeps both happy.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub(crate) enum CliTunnelMode {
    Full,
    SocksOnly,
}

impl From<CliTunnelMode> for hole_common::protocol::TunnelMode {
    fn from(mode: CliTunnelMode) -> Self {
        match mode {
            CliTunnelMode::Full => hole_common::protocol::TunnelMode::Full,
            CliTunnelMode::SocksOnly => hole_common::protocol::TunnelMode::SocksOnly,
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum BridgeAction {
    /// Run the bridge (foreground by default)
    Run {
        /// Override the IPC socket path
        #[arg(long)]
        socket_path: Option<std::path::PathBuf>,
        /// Run as a system service (invoked by SCM/launchd)
        #[arg(long)]
        service: bool,
        /// Override the log directory
        #[arg(long)]
        log_dir: Option<std::path::PathBuf>,
        /// Override the directory where the bridge writes its crash-recovery
        /// state files (`bridge-routes.json`, `bridge-dns.json`,
        /// `bridge-plugins.json`). Default: platform-specific user state dir.
        #[arg(long)]
        state_dir: Option<std::path::PathBuf>,
        /// Dev-supervisor readiness rendezvous: `<host:port>/<token>`. After
        /// the IPC socket is bound and its permissions applied, the bridge
        /// connects and echoes the token. Used by dev-console; not for
        /// service mode.
        #[arg(long)]
        ready_notify: Option<String>,
    },
    /// Install and start the bridge service
    Install {
        /// Override the log directory. The GUI's elevated-install path
        /// passes a per-invocation temp dir here so it can read this CLI's
        /// `gui-cli.log` back after the elevation completes (and surface it
        /// in the failure dialog).
        #[arg(long)]
        log_dir: Option<std::path::PathBuf>,
        /// Repair ownership of a user data directory tree that an earlier
        /// elevated install left root-owned (macOS only — a no-op
        /// elsewhere). The walk is bounded to this exact path; symlinks
        /// are never followed; hard-linked files are skipped. Best-effort:
        /// failures are logged but do not abort the install.
        #[arg(long)]
        repair_user_data_dir: Option<std::path::PathBuf>,
    },
    /// Stop and remove the bridge service
    Uninstall,
    /// Print bridge install/running status
    Status,
    /// View bridge logs
    Log {
        /// Override the log directory. Global so it parses before or after the
        /// nested `watch`/`path` subcommand.
        #[arg(long, global = true)]
        log_dir: Option<std::path::PathBuf>,
        #[command(subcommand)]
        action: Option<LogAction>,
    },
    /// Add the current user to the hole group (requires elevation)
    GrantAccess {
        /// Also send this IPC command after granting access (base64-encoded JSON)
        #[arg(long)]
        then_send: Option<String>,
        /// Read the IPC command from this file instead of --then-send
        #[arg(long, conflicts_with = "then_send")]
        then_send_file: Option<std::path::PathBuf>,
        /// Write the typed outcome (ElevatedOutcome JSON) here for an elevated
        /// parent to read back across stripped stdio. Meaningful only with the
        /// file-based request path, so it conflicts with the base64 channel.
        #[arg(long, conflicts_with = "then_send")]
        result_file: Option<std::path::PathBuf>,
    },
    /// Send a single IPC command to the bridge (requires elevation)
    IpcSend {
        /// Base64-encoded JSON of the BridgeRequest
        #[arg(long, required_unless_present = "request_file")]
        base64: Option<String>,
        /// Read the JSON request from this file
        #[arg(long, conflicts_with = "base64")]
        request_file: Option<std::path::PathBuf>,
        /// Write the typed outcome (ElevatedOutcome JSON) here for an elevated
        /// parent to read back across stripped stdio. Meaningful only with the
        /// file-based request path, so it conflicts with the base64 channel.
        #[arg(long, conflicts_with = "base64")]
        result_file: Option<std::path::PathBuf>,
    },
    /// Internal: perform the update cutover. On Windows the bridge spawns this
    /// detached as LocalSystem (a service cannot SCM-restart itself); it swaps
    /// the staged binaries and restarts the bridge service.
    Cutover {
        /// Directory holding the staged binaries (the bridge's extraction output).
        #[arg(long)]
        payload: std::path::PathBuf,
        /// Version being installed (used for the `.old-<ver>` rename-away name).
        #[arg(long)]
        target_version: String,
    },
    /// Disengage a standing lockdown cover when no bridge is alive to do it
    /// (elevated recovery hatch; last-writer-wins, not a privilege gate).
    Unlock,
}

#[derive(Subcommand)]
pub(crate) enum LogAction {
    /// Print the log file path
    Path,
    /// Stream log output (like tail -f)
    Watch {
        /// Number of existing lines to print before streaming
        #[arg(long, default_value_t = 0)]
        tail: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum PathAction {
    /// Add hole to the system PATH
    Add,
    /// Remove hole from the system PATH
    Remove,
}

// Dispatch ============================================================================================================

/// Parse CLI arguments. On Windows, attaches the parent console first so that
/// `--help`/`--version`/error output reaches the user's terminal — but only if
/// any args were passed. With zero args (the bare GUI launch from Explorer or
/// the autostart entry) no console is attached and the app stays silent. The
/// MSI installer launches with `--show-dashboard`, so it will attach to
/// `msiexec`'s console if `msiexec` was started from one — that's acceptable.
pub(crate) fn parse_args() -> Cli {
    #[cfg(target_os = "windows")]
    if std::env::args().len() > 1 {
        attach_console();
    }

    Cli::parse()
}

/// Return `true` if dispatching `command` should install a `gui-cli.log`
/// subscriber. Exempt commands:
///
/// - `Version` — pure stdout, no audit trail needed.
/// - `Bridge::Run` — installs its own `bridge.log` guard via
///   `hole_bridge::logging::init`. Calling init() again here would clash
///   (second `try_init` returns Err) and leave bridge events pointing at
///   the wrong subscriber.
/// - `Bridge::Log` — read-only inspection. No need to write a log entry to
///   read one.
///
/// Everything else installs the guard — those commands use `cli_log!` on
/// failure paths and benefit from a persistent audit trail.
pub(crate) fn should_install_cli_log_guard(command: &Command) -> bool {
    !matches!(
        command,
        Command::Version
            | Command::Bridge {
                action: BridgeAction::Run { .. }
            }
            | Command::Bridge {
                action: BridgeAction::Log { .. }
            }
    )
}

/// Resolve the directory where `dispatch` should install the `gui-cli.log`
/// guard for `command`. `None` means "don't install a guard" — see
/// [`should_install_cli_log_guard`]. A `Some` result means "install in this
/// directory".
///
/// `Bridge::Install { log_dir: Some(d), .. }` overrides the default — the
/// GUI's elevated-install path uses this to redirect the subscriber into a
/// per-invocation temp dir it can read back after the elevation completes
/// (so the failure dialog can include the underlying error text).
pub(crate) fn resolve_cli_log_dir(command: &Command) -> Option<std::path::PathBuf> {
    if !should_install_cli_log_guard(command) {
        return None;
    }
    match command {
        Command::Bridge {
            action: BridgeAction::Install { log_dir: Some(d), .. },
        } => Some(d.clone()),
        _ => Some(hole_common::logging::resolve_log_dir(None)),
    }
}

// Elevated-run owner resolution (#572) ================================================================================

/// Resolve the real interactive user for an elevated, non-`--service` bridge
/// run. `Some` only when this process is privileged AND not the launchd/SCM
/// daemon; the daemon (`--service`) and the unprivileged GUI both get `None`,
/// keeping their logs/state root-owned (the daemon) or self-owned (the GUI).
///
/// A resolve failure is non-fatal: log a warning and fall back to `None`, so
/// the run proceeds with root-owned files rather than aborting.
#[cfg(target_os = "macos")]
fn resolved_owner(service: bool) -> Option<hole_bridge::group::RealUser> {
    if service || !stepstool::is_privileged() {
        return None;
    }
    match hole_bridge::group::resolve_real_user() {
        Ok(u) => Some(u),
        Err(e) => {
            cli_log!(
                warn,
                "could not resolve the real user for an elevated run; logs/state stay root-owned: {e}"
            );
            None
        }
    }
}

/// Non-macOS twin: the elevated-run owner concept is macOS-only (the
/// osascript-admin elevation is what leaves user-home files root-owned), so
/// every other platform always gets `None`. Returns `Option<()>` and is only
/// referenced inside `#[cfg(target_os = "macos")]` blocks.
#[cfg(not(target_os = "macos"))]
#[allow(dead_code)] // exercised by the cross-platform `service_never_gets_an_owner` test; its only lib call sites are macOS-gated
fn resolved_owner(_service: bool) -> Option<()> {
    None
}

/// Extract `(uid, gid)` from a resolved [`RealUser`]. Named `to_ids` (not
/// `to_uid_gid`/a method) to avoid shadowing the local `owner_ids` binding at
/// the call site.
#[cfg(target_os = "macos")]
fn to_ids(u: &hole_bridge::group::RealUser) -> (u32, u32) {
    (u.uid, u.gid)
}

/// Per-user log directory under the resolved user's home, derived from `home`
/// (never `$HOME`/`dirs`, which under osascript-admin still point at the
/// invoking user but are easy to get wrong for an elevated process).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // non-test lib callers are macOS-gated; the path test uses it on all platforms
fn user_log_dir(home: &std::path::Path) -> std::path::PathBuf {
    home.join("Library/Application Support/hole/logs")
}

/// Per-user state directory under the resolved user's home. See
/// [`user_log_dir`].
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn user_state_dir(home: &std::path::Path) -> std::path::PathBuf {
    home.join("Library/Application Support/hole/state")
}

/// Dispatch a parsed subcommand to its handler. Exits the process when done.
///
/// For write-action subcommands, install a CLI log guard so that
/// `cli_log!(...)` calls are recorded in `gui-cli.log` in addition to the
/// user-facing terminal output. See [`should_install_cli_log_guard`] for
/// exactly which subcommands are exempted and [`resolve_cli_log_dir`] for
/// how the directory is chosen.
pub(crate) fn dispatch(command: Command) -> ! {
    // Owner for the gui-cli.log guard: only for guard-eligible commands
    // (`should_install_cli_log_guard` excludes `Bridge::Run`, so the daemon
    // is never touched) and only when this process is privileged.
    #[cfg(target_os = "macos")]
    let cli_owner: Option<(u32, u32)> = if should_install_cli_log_guard(&command) && stepstool::is_privileged() {
        hole_bridge::group::resolve_real_user().ok().map(|u| (u.uid, u.gid))
    } else {
        None
    };
    #[cfg(not(target_os = "macos"))]
    let cli_owner: Option<(u32, u32)> = None;
    let _cli_log_guard = resolve_cli_log_dir(&command)
        .map(|d| hole_common::logging::init(&d, "gui-cli", "gui-cli.log", "hole=info", cli_owner));
    let code = match command {
        Command::Version => {
            println!("hole {}", hole::version::VERSION);
            0
        }
        Command::Upgrade { yes } => handle_upgrade(yes),
        Command::Bridge { action } => handle_bridge(action),
        Command::Proxy { action } => handle_proxy(action),
        Command::Path { action } => handle_path(action),
    };

    std::process::exit(code)
}

fn handle_upgrade(yes: bool) -> i32 {
    cli_log!(info, "checking for updates...");
    match hole::update::check_for_update() {
        Ok(Some(info)) => {
            cli_log!(info, "update available: v{}", info.version);

            let download_dir = match tempfile::TempDir::with_prefix("hole-update-") {
                Ok(d) => d,
                Err(e) => {
                    cli_log!(error, "failed to create temp dir: {e}");
                    return 1;
                }
            };
            let dest = download_dir.path().join(&info.asset_name);

            cli_log!(info, "downloading {}...", info.asset_name);
            if let Err(e) = hole::update::download_asset(&info.asset_url, &dest) {
                cli_log!(error, "download failed: {e}");
                return 1;
            }

            cli_log!(info, "verifying...");
            // Fetch the manifest + signature once; they feed BOTH the local
            // verify and the bridge's offline re-verify (the bridge must not
            // re-fetch).
            let (sha256sums, sha256sums_minisig) =
                match hole::update::fetch_manifest(&info.sha256sums_url, &info.sha256sums_minisig_url) {
                    Ok(m) => m,
                    Err(e) => {
                        cli_log!(error, "manifest fetch failed: {e}");
                        return 1;
                    }
                };
            if let Err(e) =
                hole_common::verify::verify_payload_offline(&dest, &info.asset_name, &sha256sums, &sha256sums_minisig)
            {
                cli_log!(error, "verification failed: {e}");
                return 1;
            }

            // Read lockdown fresh at send time — not the cached snapshot.
            use std::io::{IsTerminal, Write};
            let status = send_bridge_request_inner(hole_common::protocol::BridgeRequest::Status);
            let lockdown_enabled = match crate::state::classify_lockdown(&status) {
                crate::state::LockdownRead::Known { enabled, .. } => enabled,
                crate::state::LockdownRead::WrongReply => {
                    cli_log!(
                        warn,
                        "consent gate: Status returned an unexpected reply ({status:?}); assuming lockdown off"
                    );
                    false
                }
                crate::state::LockdownRead::Unreadable => {
                    cli_log!(
                        warn,
                        "consent gate: Status read failed ({status:?}); assuming lockdown off"
                    );
                    false
                }
            };
            let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
            let consent = match hole::update::cli_consent_decision(lockdown_enabled, yes, interactive) {
                hole::update::CliConsent::Proceed { consent } => {
                    if consent {
                        cli_log!(info, "update consent granted");
                    }
                    consent
                }
                hole::update::CliConsent::Refuse => {
                    eprintln!("error: {}", hole::update::CONSENT_CLI_REFUSAL);
                    return 1;
                }
                hole::update::CliConsent::Prompt => {
                    print!("{}", hole::update::CONSENT_CLI_PROMPT);
                    if let Err(e) = std::io::stdout().flush() {
                        cli_log!(error, "failed to display consent prompt: {e}");
                        return 1;
                    }
                    let mut line = String::new();
                    match std::io::stdin().read_line(&mut line) {
                        Err(e) => {
                            cli_log!(warn, "consent prompt read failed: {e}");
                            return 1;
                        }
                        Ok(_) => {
                            if hole::update::cli_answer_confirms(&line) {
                                true
                            } else {
                                cli_log!(info, "update cancelled by user");
                                return 0;
                            }
                        }
                    }
                }
            };

            cli_log!(info, "installing...");
            // The privileged bridge owns the cutover (swap + service restart); the
            // GUI only hands it the verified payload + manifest.
            let apply = hole::update::build_apply_update(
                dest.clone(),
                info.version.to_string(),
                sha256sums,
                sha256sums_minisig,
                info.asset_name.clone(),
                hole::update::app_dest_hint(),
                consent,
            );
            match send_bridge_request_inner(apply) {
                Ok(hole_common::protocol::BridgeResponse::Ack) => {}
                Ok(hole_common::protocol::BridgeResponse::Error { message }) => {
                    cli_log!(error, "bridge rejected update: {message}");
                    return 1;
                }
                Ok(other) => {
                    cli_log!(error, "unexpected response: {other:?}");
                    return 1;
                }
                Err(crate::bridge_client::ClientError::ConsentRequired { message }) => {
                    cli_log!(
                        error,
                        "lockdown changed during the update; re-run to confirm: {message}"
                    );
                    return 1;
                }
                Err(e) => {
                    cli_log!(error, "installation failed: {e}");
                    return 1;
                }
            }

            cli_log!(info, "cutover started for v{}", info.version);
            0
        }
        Ok(None) => {
            cli_log!(info, "already up to date ({})", hole::version::VERSION);
            0
        }
        Err(e) => {
            cli_log!(error, "update check failed: {e}");
            1
        }
    }
}

fn handle_bridge(action: BridgeAction) -> i32 {
    match action {
        BridgeAction::Run {
            socket_path,
            service,
            log_dir,
            state_dir,
            ready_notify,
        } => {
            // Resolve the elevated-run owner once: `Some` only for a
            // privileged, non-`--service` run (the daemon and the
            // unprivileged GUI both get `None`). The owner picks the
            // user-home log/state dirs and chowns the files we write.
            #[cfg(target_os = "macos")]
            let owner = resolved_owner(service);
            #[cfg(target_os = "macos")]
            let owner_ids: Option<(u32, u32)> = owner.as_ref().map(to_ids);
            #[cfg(not(target_os = "macos"))]
            let owner_ids: Option<(u32, u32)> = None;

            // Precedence: explicit `--log-dir` or the resolved-user home (for an
            // elevated user-scoped run) → `HOLE_LOG_DIR` env → default. The chown
            // happens regardless of which dir wins, since `init_dual` chowns
            // `log_dir` with `owner_ids`.
            #[cfg(target_os = "macos")]
            let log_dir = hole_common::logging::resolve_log_dir(
                log_dir.or_else(|| owner.as_ref().map(|u| user_log_dir(&u.home))),
            );
            #[cfg(not(target_os = "macos"))]
            let log_dir = hole_common::logging::resolve_log_dir(log_dir);
            let _guard = hole_bridge::logging::init(&log_dir, owner_ids);
            tracing::info!("hole bridge starting");

            // Reclaim ownership of an already-existing user data tree that an
            // earlier elevated run left root-owned. Best-effort; the walk is
            // hardened (lchown, refuse symlink top, skip nlink>1).
            #[cfg(target_os = "macos")]
            if let (Some(u), Some((uid, gid))) = (owner.as_ref(), owner_ids) {
                crate::setup::repair_user_data_tree(&u.home.join("Library/Application Support/hole"), uid, gid);
            }

            if service && ready_notify.is_some() {
                cli_log!(error, "--ready-notify is not supported with --service");
                return 2;
            }

            // Canonicalize state_dir to an absolute path. If canonicalize
            // fails (e.g. directory doesn't exist yet), fall back to
            // joining against cwd so the service mode doesn't surprise the
            // user with a cwd-relative path (service cwd is `C:\Windows\System32`
            // on Windows or `/` on macOS).
            #[cfg(target_os = "macos")]
            let state_dir = state_dir.or_else(|| owner.as_ref().map(|u| user_state_dir(&u.home)));
            let state_dir = state_dir.unwrap_or_else(hole_common::paths::default_state_dir);
            let state_dir = state_dir.canonicalize().unwrap_or_else(|_| {
                std::env::current_dir()
                    .map(|cwd| cwd.join(&state_dir))
                    .unwrap_or(state_dir)
            });

            let socket_path = socket_path.unwrap_or_else(hole_common::protocol::default_bridge_socket_path);

            let result: Result<(), Box<dyn std::error::Error>> = if service {
                #[cfg(target_os = "macos")]
                {
                    hole_bridge::platform::os::run(&socket_path, &state_dir, &log_dir, hole::version::VERSION)
                }
                #[cfg(target_os = "windows")]
                {
                    hole_bridge::platform::os::run(&socket_path, &state_dir, &log_dir, hole::version::VERSION)
                        .map_err(|e| Box::new(e) as _)
                }
            } else {
                hole_bridge::foreground::run(
                    &socket_path,
                    &state_dir,
                    &log_dir,
                    ready_notify.as_deref(),
                    hole::version::VERSION,
                    owner_ids,
                )
            };

            if let Err(e) = result {
                // BridgeAction::Run installs its own bridge.log subscriber via
                // hole_bridge::logging::init, so we use the macro freely here
                // — the tracing call routes through that subscriber.
                cli_log!(error, "bridge error: {e}");
                return 1;
            }
            0
        }
        BridgeAction::Install {
            log_dir: _, // consumed by `resolve_cli_log_dir` already
            repair_user_data_dir,
        } => {
            // Header line — guarantees the gui-cli.log identifies the build
            // and host even if the rest of the install fails immediately.
            cli_log!(
                info,
                "hole bridge install: hole={}, os={}, target={}",
                hole::version::VERSION,
                std::env::consts::OS,
                std::env::consts::ARCH,
            );
            if let Err(e) = crate::setup::install_bridge(repair_user_data_dir.as_deref()) {
                cli_log!(error, "bridge install failed: {e}");
                return 1;
            }
            0
        }
        BridgeAction::Uninstall => {
            if let Err(e) = crate::setup::uninstall_bridge() {
                cli_log!(error, "bridge uninstall failed: {e}");
                return 1;
            }
            0
        }
        BridgeAction::Status => {
            use crate::setup::BridgeInstallStatus;
            match crate::setup::bridge_install_status() {
                BridgeInstallStatus::Running => {
                    println!("installed (running)");
                    0
                }
                BridgeInstallStatus::Installed => {
                    println!("installed (stopped)");
                    1
                }
                BridgeInstallStatus::NotInstalled => {
                    println!("not installed");
                    2
                }
            }
        }
        BridgeAction::Log { log_dir, action } => handle_bridge_log(log_dir, action),
        BridgeAction::GrantAccess {
            then_send,
            then_send_file,
            result_file,
        } => handle_grant_access(then_send, then_send_file, result_file),
        BridgeAction::IpcSend {
            base64,
            request_file,
            result_file,
        } => match (base64, request_file) {
            (Some(b64), _) => handle_ipc_send_b64(&b64),
            (_, Some(path)) => match crate::elevation::read_request_file(&path) {
                Ok(request) => send_bridge_request(request, result_file.as_deref()),
                Err(e) => {
                    cli_log!(error, "{e}");
                    1
                }
            },
            (None, None) => unreachable!("clap ensures one is present"),
        },
        BridgeAction::Cutover {
            payload,
            target_version,
        } => {
            // The detached LocalSystem child the bridge spawned: swap the staged
            // binaries and SCM-restart the service.
            match hole_bridge::cutover::run_detached(&payload, &target_version) {
                Ok(()) => 0,
                Err(e) => {
                    cli_log!(error, "cutover failed: {e}");
                    1
                }
            }
        }
        BridgeAction::Unlock => match hole_bridge::cutover::unlock() {
            Ok(()) => 0,
            Err(e) => {
                cli_log!(error, "unlock failed: {e}");
                1
            }
        },
    }
}

fn handle_bridge_log(log_dir: Option<std::path::PathBuf>, action: Option<LogAction>) -> i32 {
    let log_dir = log_dir.unwrap_or_else(hole_common::logging::default_log_dir);
    let log_path = log_dir.join("bridge.log");

    match action {
        None => {
            // Print entire log file to stdout
            match std::fs::read_to_string(&log_path) {
                Ok(contents) => {
                    print!("{contents}");
                    0
                }
                Err(e) => {
                    eprintln!("cannot read log file {}: {e}", log_path.display());
                    1
                }
            }
        }
        Some(LogAction::Path) => {
            println!("{}", log_path.display());
            0
        }
        Some(LogAction::Watch { tail }) => bridge_log_watch(&log_path, tail),
    }
}

/// Open `path` for tailing and capture a `same_file::Handle` tied to the
/// same underlying FD. The handle is built from `file.try_clone()` so there
/// is no TOCTOU race between opening the file and identifying it.
fn open_watch_reader(
    path: &std::path::Path,
) -> std::io::Result<(std::io::BufReader<std::fs::File>, same_file::Handle)> {
    let file = std::fs::File::open(path)?;
    let handle = same_file::Handle::from_file(file.try_clone()?)?;
    Ok((std::io::BufReader::new(file), handle))
}

/// Returns `Ok(true)` if the file currently at `path` is a different file
/// than the one identified by `current` (rename-rotation); `Ok(false)` if
/// it's the same file or if the path is transiently missing (rotation in
/// progress); `Err` for any other stat failure.
fn file_was_rotated(path: &std::path::Path, current: &same_file::Handle) -> std::io::Result<bool> {
    match same_file::Handle::from_path(path) {
        Ok(latest) => Ok(&latest != current),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Tail and follow a log file (like `tail -f`). Detects rename-rotation by
/// `file-rotate` and reopens `path` so the stream keeps flowing after
/// rollover.
fn bridge_log_watch(path: &std::path::Path, tail_lines: usize) -> i32 {
    use std::io::{BufRead, Seek, SeekFrom};

    let (mut reader, mut handle) = match open_watch_reader(path) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("cannot open log file {}: {e}", path.display());
            return 1;
        }
    };

    // If tail > 0, read and show the last N lines using the same reader.
    //
    // If rotation happens *during* the tail read, the tail lines come from
    // the old (pre-rotation) inode — that's the expected behavior. The
    // first Ok(0) after the tail completes will detect the swap and reopen.
    if tail_lines > 0 {
        let mut all_lines = Vec::new();
        let mut buf = String::new();
        while reader.read_line(&mut buf).unwrap_or(0) > 0 {
            all_lines.push(buf.clone());
            buf.clear();
        }
        let start = all_lines.len().saturating_sub(tail_lines);
        for line in &all_lines[start..] {
            print!("{line}");
        }
        // Reader is now at the end of the file; continue watching from here.
    } else {
        // Start from end
        let _ = reader.seek(SeekFrom::End(0));
    }

    // Poll for new content
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                match file_was_rotated(path, &handle) {
                    Ok(true) => {
                        // Drain any final bytes from the old (renamed) file
                        // before swapping. file-rotate may have flushed a
                        // line between our last Ok(0) and the rename.
                        loop {
                            line.clear();
                            match reader.read_line(&mut line) {
                                Ok(0) => break,
                                Ok(_) => print!("{line}"),
                                Err(_) => break,
                            }
                        }
                        match open_watch_reader(path) {
                            Ok((r, h)) => {
                                reader = r;
                                handle = h;
                                continue; // read the rotated file without sleeping
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                // New file not yet created; retry next tick.
                            }
                            Err(e) => {
                                eprintln!("reopen error: {e}");
                                return 1;
                            }
                        }
                    }
                    Ok(false) => { /* not rotated */ }
                    Err(e) => {
                        eprintln!("stat error: {e}");
                        return 1;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Ok(_) => {
                print!("{line}");
            }
            Err(e) => {
                eprintln!("read error: {e}");
                return 1;
            }
        }
    }
}

/// Handle the `bridge grant-access` command.
///
/// Creates the `hole` group, adds the current user to it, and on Windows
/// writes the user's SID to the `installer-user-sid` file so the bridge
/// includes it in the socket DACL on next startup. If the bridge is
/// already running, also updates the live socket DACL directly so the
/// GUI can connect without re-login. Used both by the installer (to set
/// up IPC access at install time) and by dev-console (to prepare IPC access
/// before the foreground dev bridge starts).
///
/// The direct-DACL-update path is a workaround for the Windows
/// token-snapshot limitation: process tokens are immutable snapshots of
/// group memberships captured at logon time. There is no Win32 API to
/// refresh a process's token to pick up new group memberships, and
/// `klist purge`/`nltest` only affect Kerberos/AD tickets, not local
/// group tokens. Adding the user's own SID directly to the DACL provides
/// immediate access — a user's own SID is always present in their token.
fn handle_grant_access(
    then_send: Option<String>,
    then_send_file: Option<std::path::PathBuf>,
    result_file: Option<std::path::PathBuf>,
) -> i32 {
    // Create group + add user + (on Windows) write installer SID file.
    if let Err(e) = hole_bridge::ipc::prepare_ipc_access() {
        cli_log!(error, "failed to prepare IPC access: {e}");
        return 1;
    }

    // On Windows, if the bridge is already running, also update the live
    // socket DACL directly so the GUI can connect immediately without
    // waiting for a bridge restart.
    #[cfg(target_os = "windows")]
    {
        let socket_path = hole_common::protocol::default_bridge_socket_path();
        if socket_path.exists() {
            match hole_bridge::group::installing_username() {
                Ok(username) => match hole_bridge::group::lookup_sid(&username) {
                    Ok(user_sid) => {
                        let sddl = hole_bridge::ipc::build_sddl(&[&user_sid]);
                        if let Err(e) = hole_bridge::ipc::set_dacl_from_sddl(&socket_path, &sddl, false) {
                            cli_log!(warn, "warning: failed to update live socket DACL: {e}");
                        } else {
                            cli_log!(info, "updated live socket DACL with user SID");
                        }
                    }
                    Err(e) => {
                        cli_log!(warn, "warning: could not look up user SID: {e}");
                    }
                },
                Err(e) => {
                    cli_log!(
                        warn,
                        "warning: could not determine installing user for live DACL update: {e}"
                    );
                }
            }
        }
    }

    // Optionally proxy a command to the bridge
    match (then_send, then_send_file) {
        (Some(b64), _) => handle_ipc_send_b64(&b64),
        (_, Some(path)) => match crate::elevation::read_request_file(&path) {
            Ok(request) => send_bridge_request(request, result_file.as_deref()),
            Err(e) => {
                cli_log!(error, "{e}");
                1
            }
        },
        (None, None) => 0,
    }
}

fn handle_ipc_send_b64(base64_request: &str) -> i32 {
    use base64::Engine;
    use hole_common::protocol::BridgeRequest;

    // Decode base64
    let json_bytes = match base64::engine::general_purpose::STANDARD.decode(base64_request) {
        Ok(b) => b,
        Err(e) => {
            cli_log!(error, "invalid base64: {e}");
            return 1;
        }
    };

    // Deserialize request
    let request: BridgeRequest = match serde_json::from_slice(&json_bytes) {
        Ok(r) => r,
        Err(e) => {
            cli_log!(error, "invalid request JSON: {e}");
            return 1;
        }
    };

    send_bridge_request(request, None)
}

/// CLI disposition for a typed start failure: process exit code + an optional error
/// line. Cancelled/AlreadyRunning are success-equivalent (0); a block and any other
/// failure are errors (1). Shared by both CLI start paths so exit codes never diverge.
pub(crate) fn start_error_cli(e: &hole_common::protocol::StartError) -> (i32, Option<String>) {
    use hole_common::protocol::StartError;
    match e {
        StartError::Cancelled | StartError::AlreadyRunning => (0, None),
        StartError::NetworkBlocked => (1, Some(hole_common::protocol::NETWORK_BLOCKED_MESSAGE.to_string())),
        StartError::Failed { message } => (1, Some(format!("bridge rejected start: {message}"))),
    }
}

/// Send a `BridgeRequest`, mapping the response to an exit code (0 on success,
/// 1 on error). Used by `bridge ipc-send`, which doesn't print the response
/// body. When `result_file` is `Some` (the elevated path), also mirror the
/// typed outcome there for the parent to read back across stripped stdio; the
/// exit-code map is unchanged and a result-file write failure only logs a warn.
fn send_bridge_request(request: hole_common::protocol::BridgeRequest, result_file: Option<&std::path::Path>) -> i32 {
    use hole_common::protocol::BridgeResponse;

    let inner = send_bridge_request_inner(request);

    if let Some(path) = result_file {
        let outcome = crate::elevation::classify_elevated_send(&inner);
        if let Err(e) = crate::elevation::write_result_file(path, &outcome) {
            cli_log!(warn, "failed to write result file: {e}");
        }
    }

    match inner {
        Ok(BridgeResponse::Ack) => 0,
        Ok(BridgeResponse::Status { .. }) => 0,
        Ok(BridgeResponse::Metrics { .. }) => 0,
        Ok(BridgeResponse::Diagnostics { .. }) => 0,
        Ok(BridgeResponse::TestServerResult { .. }) => 0,
        Ok(BridgeResponse::Error { message }) => {
            cli_log!(error, "bridge error: {message}");
            1
        }
        Ok(BridgeResponse::StartFailed(e)) => {
            let (code, log) = start_error_cli(&e);
            if let Some(line) = log {
                cli_log!(error, "{line}");
            }
            code
        }
        Err(msg) => {
            cli_log!(error, "{msg}");
            1
        }
    }
}

/// Underlying request driver. Returns the parsed `BridgeResponse` or the typed
/// `ClientError` (kept typed so the elevated classifier can distinguish a
/// control-plane `ConcurrentStart` from a transport failure).
fn send_bridge_request_inner(
    request: hole_common::protocol::BridgeRequest,
) -> Result<hole_common::protocol::BridgeResponse, crate::bridge_client::ClientError> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let socket_path = hole_common::protocol::default_bridge_socket_path();
        let mut client = crate::bridge_client::BridgeClient::connect(&socket_path).await?;
        client.send(request).await
    })
}

// Proxy subcommand ====================================================================================================

/// Read a `ServerEntry` from a JSON file. Returns Err with a user-facing
/// message on file IO or parse failure.
fn read_server_entry_file(path: &std::path::Path) -> Result<hole_common::config::ServerEntry, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_slice::<hole_common::config::ServerEntry>(&bytes)
        .map_err(|e| format!("failed to parse {} as ServerEntry JSON: {e}", path.display()))
}

fn handle_proxy(action: ProxyAction) -> i32 {
    use hole_common::protocol::{BridgeRequest, BridgeResponse, ProxyConfig};

    match action {
        ProxyAction::Start {
            config_file,
            local_port,
            local_port_http,
            no_socks5,
            http,
            tunnel_mode,
        } => {
            let entry = match read_server_entry_file(&config_file) {
                Ok(e) => e,
                Err(msg) => {
                    cli_log!(error, "{msg}");
                    return 1;
                }
            };
            let request = BridgeRequest::Start {
                config: ProxyConfig {
                    server: entry,
                    local_port,
                    tunnel_mode: tunnel_mode.into(),
                    filters: Vec::new(),
                    dns: hole_common::config::DnsConfig::default(),
                    proxy_socks5: !no_socks5,
                    proxy_http: http,
                    local_port_http,
                    diagnostic_plugin_tap: false,
                },
                // CLI-initiated start has no paired cancel; a fresh id is fine.
                attempt_id: uuid::Uuid::new_v4().to_string(),
                // A manual `hole proxy start` is fail-open (today's behavior);
                // the auto-connect stay-blocked cover is GUI-only.
                covered: false,
            };
            match send_bridge_request_inner(request) {
                Ok(BridgeResponse::Ack) => {
                    println!("proxy started on local_port {local_port}");
                    0
                }
                Ok(BridgeResponse::StartFailed(e)) => {
                    use hole_common::protocol::StartError;
                    match &e {
                        StartError::AlreadyRunning => println!("proxy already running on local_port {local_port}"),
                        StartError::Cancelled => println!("proxy start cancelled"),
                        _ => {}
                    }
                    let (code, log) = start_error_cli(&e);
                    if let Some(line) = log {
                        cli_log!(error, "{line}");
                    }
                    code
                }
                Ok(other) => {
                    cli_log!(error, "unexpected response: {other:?}");
                    1
                }
                Err(msg) => {
                    cli_log!(error, "{msg}");
                    1
                }
            }
        }
        ProxyAction::Stop => match send_bridge_request_inner(BridgeRequest::Stop) {
            Ok(BridgeResponse::Ack) => {
                println!("proxy stopped");
                0
            }
            Ok(BridgeResponse::Error { message }) => {
                cli_log!(error, "bridge rejected stop: {message}");
                1
            }
            Ok(other) => {
                cli_log!(error, "unexpected response: {other:?}");
                1
            }
            Err(msg) => {
                cli_log!(error, "{msg}");
                1
            }
        },
        ProxyAction::TestServer { config_file } => {
            let entry = match read_server_entry_file(&config_file) {
                Ok(e) => e,
                Err(msg) => {
                    cli_log!(error, "{msg}");
                    return 1;
                }
            };
            // The dev/admin CLI reads only a ServerEntry file — no AppConfig in
            // hand — so it bootstraps over the default DoH resolver.
            let dns = hole_common::config::DnsConfig::default();
            match send_bridge_request_inner(BridgeRequest::TestServer { entry, dns }) {
                Ok(BridgeResponse::TestServerResult { outcome }) => {
                    println!("{outcome:#?}");
                    // Reachable is the only "success" outcome; everything else
                    // is some flavor of failure that the operator wants to see.
                    if matches!(outcome, hole_common::protocol::ServerTestOutcome::Reachable { .. }) {
                        0
                    } else {
                        2
                    }
                }
                Ok(BridgeResponse::Error { message }) => {
                    cli_log!(error, "bridge rejected test-server: {message}");
                    1
                }
                Ok(other) => {
                    cli_log!(error, "unexpected response: {other:?}");
                    1
                }
                Err(msg) => {
                    cli_log!(error, "{msg}");
                    1
                }
            }
        }
    }
}

fn handle_path(action: PathAction) -> i32 {
    match action {
        PathAction::Add => {
            if let Err(e) = crate::path_management::add() {
                cli_log!(error, "path add failed: {e}");
                return 1;
            }
            0
        }
        PathAction::Remove => {
            if let Err(e) = crate::path_management::remove() {
                cli_log!(error, "path remove failed: {e}");
                return 1;
            }
            0
        }
    }
}

// Platform helpers ====================================================================================================

#[cfg(target_os = "windows")]
fn attach_console() {
    use windows::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    // Best-effort: if we're launched from a terminal, attach to it for stdout/stderr.
    // If not (e.g. launched from Explorer), this fails silently — that's fine.
    // SAFETY: AttachConsole has no preconditions beyond a valid PID constant.
    // ATTACH_PARENT_PROCESS is a well-known sentinel. The result is intentionally
    // ignored — failure simply means no console is available.
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod cli_tests;
