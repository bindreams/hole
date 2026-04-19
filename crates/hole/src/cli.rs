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
    Upgrade,
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
        /// Local SOCKS5 port the bridge should bind. Defaults to the
        /// production default of 4073.
        #[arg(long, default_value_t = 4073)]
        local_port: u16,
        /// Local HTTP CONNECT port the bridge should bind when
        /// `--http` is used. Defaults to 4074. Must differ from
        /// `--local-port` when both listeners are enabled.
        #[arg(long, default_value_t = 4074)]
        local_port_http: u16,
        /// Disable the SOCKS5 listener (default: enabled). Incompatible
        /// with `--tunnel-mode full`, since the TUN dispatcher hands
        /// captured traffic to the SOCKS5 listener.
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
        /// Override the directory where the bridge writes its route-recovery
        /// state file (`bridge-routes.json`). Default: platform-specific
        /// user state dir.
        #[arg(long)]
        state_dir: Option<std::path::PathBuf>,
    },
    /// Install and start the bridge service
    Install,
    /// Stop and remove the bridge service
    Uninstall,
    /// Print bridge install/running status
    Status,
    /// View bridge logs
    Log {
        /// Override the log directory
        #[arg(long)]
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
    },
    /// Send a single IPC command to the bridge (requires elevation)
    IpcSend {
        /// Base64-encoded JSON of the BridgeRequest
        #[arg(long, required_unless_present = "request_file")]
        base64: Option<String>,
        /// Read the JSON request from this file
        #[arg(long, conflicts_with = "base64")]
        request_file: Option<std::path::PathBuf>,
    },
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
/// Non-exempt (install the guard): `Upgrade`, `Bridge::{Install,
/// Uninstall, Status, GrantAccess, IpcSend}`, `Proxy::{Start, Stop,
/// TestServer}`, `Path::{Add, Remove}`. These all use `cli_log!` on
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

/// Dispatch a parsed subcommand to its handler. Exits the process when done.
///
/// For write-action subcommands (Upgrade, Bridge::{Install, Uninstall, Status,
/// GrantAccess, IpcSend}, and Path), install a CLI log guard so that
/// `cli_log!(...)` calls are recorded in `gui-cli.log` in addition to the
/// user-facing terminal output. See [`should_install_cli_log_guard`] for
/// the exemption list.
pub(crate) fn dispatch(command: Command) -> ! {
    let _cli_log_guard = if should_install_cli_log_guard(&command) {
        let log_dir = hole_common::logging::default_log_dir();
        Some(hole_common::logging::init(&log_dir, "gui-cli.log", "hole=info"))
    } else {
        None
    };
    let code = match command {
        Command::Version => {
            println!("hole {}", hole::version::VERSION);
            0
        }
        Command::Upgrade => handle_upgrade(),
        Command::Bridge { action } => handle_bridge(action),
        Command::Proxy { action } => handle_proxy(action),
        Command::Path { action } => handle_path(action),
    };

    std::process::exit(code)
}

fn handle_upgrade() -> i32 {
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
            if let Err(e) = hole::update::verify_asset(
                &dest,
                &info.asset_name,
                &info.sha256sums_url,
                &info.sha256sums_minisig_url,
            ) {
                cli_log!(error, "verification failed: {e}");
                return 1;
            }

            cli_log!(info, "installing...");
            if let Err(e) = hole::update::run_installer(&dest, true) {
                cli_log!(error, "installation failed: {e}");
                return 1;
            }

            cli_log!(info, "updated to v{}", info.version);
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
        } => {
            let log_dir = log_dir.unwrap_or_else(hole_common::logging::default_log_dir);
            let _guard = hole_bridge::logging::init(&log_dir);
            tracing::info!("hole bridge starting");

            // Canonicalize state_dir to an absolute path. If canonicalize
            // fails (e.g. directory doesn't exist yet), fall back to
            // joining against cwd so the service mode doesn't surprise the
            // user with a cwd-relative path (service cwd is `C:\Windows\System32`
            // on Windows or `/` on macOS).
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
                    hole_bridge::platform::os::run(&socket_path, &state_dir, &log_dir)
                }
                #[cfg(target_os = "windows")]
                {
                    hole_bridge::platform::os::run(&socket_path, &state_dir, &log_dir).map_err(|e| Box::new(e) as _)
                }
            } else {
                hole_bridge::foreground::run(&socket_path, &state_dir, &log_dir)
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
        BridgeAction::Install => {
            if let Err(e) = crate::setup::install_bridge() {
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
        } => handle_grant_access(then_send, then_send_file),
        BridgeAction::IpcSend { base64, request_file } => match (base64, request_file) {
            (Some(b64), _) => handle_ipc_send_b64(&b64),
            (_, Some(path)) => match crate::elevation::read_request_file(&path) {
                Ok(request) => send_bridge_request(request),
                Err(e) => {
                    cli_log!(error, "{e}");
                    1
                }
            },
            (None, None) => unreachable!("clap ensures one is present"),
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
/// up IPC access at install time) and by `dev.py` (to prepare IPC access
/// before the foreground dev bridge starts).
///
/// The direct-DACL-update path is a workaround for the Windows
/// token-snapshot limitation: process tokens are immutable snapshots of
/// group memberships captured at logon time. There is no Win32 API to
/// refresh a process's token to pick up new group memberships, and
/// `klist purge`/`nltest` only affect Kerberos/AD tickets, not local
/// group tokens. Adding the user's own SID directly to the DACL provides
/// immediate access — a user's own SID is always present in their token.
fn handle_grant_access(then_send: Option<String>, then_send_file: Option<std::path::PathBuf>) -> i32 {
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
            Ok(request) => send_bridge_request(request),
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

    send_bridge_request(request)
}

/// Send a `BridgeRequest`, mapping the response to an exit code (0 on
/// success, 1 on error). Used by `bridge ipc-send` which doesn't print the
/// response body.
fn send_bridge_request(request: hole_common::protocol::BridgeRequest) -> i32 {
    use hole_common::protocol::BridgeResponse;

    match send_bridge_request_inner(request) {
        Ok(BridgeResponse::Ack) => 0,
        Ok(BridgeResponse::Status { .. }) => 0,
        Ok(BridgeResponse::Metrics { .. }) => 0,
        Ok(BridgeResponse::Diagnostics { .. }) => 0,
        Ok(BridgeResponse::PublicIp { .. }) => 0,
        Ok(BridgeResponse::TestServerResult { .. }) => 0,
        Ok(BridgeResponse::Error { message }) => {
            cli_log!(error, "bridge error: {message}");
            1
        }
        Err(msg) => {
            cli_log!(error, "{msg}");
            1
        }
    }
}

/// Underlying request driver. Returns the parsed `BridgeResponse` or a
/// human-readable error message.
fn send_bridge_request_inner(
    request: hole_common::protocol::BridgeRequest,
) -> Result<hole_common::protocol::BridgeResponse, String> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let socket_path = hole_common::protocol::default_bridge_socket_path();
        let mut client = crate::bridge_client::BridgeClient::connect(&socket_path)
            .await
            .map_err(|e| format!("failed to connect to bridge: {e}"))?;
        client
            .send(request)
            .await
            .map_err(|e| format!("communication error: {e}"))
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
                },
            };
            match send_bridge_request_inner(request) {
                Ok(BridgeResponse::Ack) => {
                    println!("proxy started on local_port {local_port}");
                    0
                }
                Ok(BridgeResponse::Error { message }) => {
                    cli_log!(error, "bridge rejected start: {message}");
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
            match send_bridge_request_inner(BridgeRequest::TestServer { entry }) {
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
