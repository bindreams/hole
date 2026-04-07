// CLI subcommand dispatch.

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
    /// Manage PATH integration
    Path {
        #[command(subcommand)]
        action: PathAction,
    },
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

/// Dispatch a parsed subcommand to its handler. Exits the process when done.
pub(crate) fn dispatch(command: Command) -> ! {
    let code = match command {
        Command::Version => {
            println!("hole {}", hole_gui::version::VERSION);
            0
        }
        Command::Upgrade => handle_upgrade(),
        Command::Bridge { action } => handle_bridge(action),
        Command::Path { action } => handle_path(action),
    };

    std::process::exit(code)
}

fn handle_upgrade() -> i32 {
    eprintln!("checking for updates...");
    match hole_gui::update::check_for_update() {
        Ok(Some(info)) => {
            eprintln!("update available: v{}", info.version);

            let download_dir = match tempfile::TempDir::with_prefix("hole-update-") {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("failed to create temp dir: {e}");
                    return 1;
                }
            };
            let dest = download_dir.path().join(&info.asset_name);

            eprintln!("downloading {}...", info.asset_name);
            if let Err(e) = hole_gui::update::download_asset(&info.asset_url, &dest) {
                eprintln!("download failed: {e}");
                return 1;
            }

            eprintln!("verifying...");
            if let Err(e) = hole_gui::update::verify_asset(
                &dest,
                &info.asset_name,
                &info.sha256sums_url,
                &info.sha256sums_minisig_url,
            ) {
                eprintln!("verification failed: {e}");
                return 1;
            }

            eprintln!("installing...");
            if let Err(e) = hole_gui::update::run_installer(&dest, true) {
                eprintln!("installation failed: {e}");
                return 1;
            }

            eprintln!("updated to v{}", info.version);
            0
        }
        Ok(None) => {
            eprintln!("already up to date ({})", hole_gui::version::VERSION);
            0
        }
        Err(e) => {
            eprintln!("update check failed: {e}");
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
                    hole_bridge::platform::os::run(&socket_path, &state_dir)
                }
                #[cfg(target_os = "windows")]
                {
                    hole_bridge::platform::os::run(&socket_path, &state_dir).map_err(|e| Box::new(e) as _)
                }
            } else {
                hole_bridge::foreground::run(&socket_path, &state_dir)
            };

            if let Err(e) = result {
                eprintln!("bridge error: {e}");
                return 1;
            }
            0
        }
        BridgeAction::Install => {
            if let Err(e) = crate::setup::install_bridge() {
                eprintln!("bridge install failed: {e}");
                return 1;
            }
            0
        }
        BridgeAction::Uninstall => {
            if let Err(e) = crate::setup::uninstall_bridge() {
                eprintln!("bridge uninstall failed: {e}");
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
                    eprintln!("{e}");
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

/// Tail and follow a log file (like `tail -f`).
fn bridge_log_watch(path: &std::path::Path, tail_lines: usize) -> i32 {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};

    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("cannot open log file {}: {e}", path.display());
            return 1;
        }
    };

    let mut reader = BufReader::new(file);

    // If tail > 0, read and show the last N lines using the same reader
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
        eprintln!("failed to prepare IPC access: {e}");
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
                            eprintln!("warning: failed to update live socket DACL: {e}");
                        } else {
                            eprintln!("updated live socket DACL with user SID");
                        }
                    }
                    Err(e) => {
                        eprintln!("warning: could not look up user SID: {e}");
                    }
                },
                Err(e) => {
                    eprintln!("warning: could not determine installing user for live DACL update: {e}");
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
                eprintln!("{e}");
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
            eprintln!("invalid base64: {e}");
            return 1;
        }
    };

    // Deserialize request
    let request: BridgeRequest = match serde_json::from_slice(&json_bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("invalid request JSON: {e}");
            return 1;
        }
    };

    send_bridge_request(request)
}

fn send_bridge_request(request: hole_common::protocol::BridgeRequest) -> i32 {
    use hole_common::protocol::BridgeResponse;

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let socket_path = hole_common::protocol::default_bridge_socket_path();

        let mut client = match crate::bridge_client::BridgeClient::connect(&socket_path).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("failed to connect to bridge: {e}");
                return 1;
            }
        };

        match client.send(request).await {
            Ok(BridgeResponse::Ack) => 0,
            Ok(BridgeResponse::Status { .. }) => 0,
            Ok(BridgeResponse::Metrics { .. }) => 0,
            Ok(BridgeResponse::Diagnostics { .. }) => 0,
            Ok(BridgeResponse::PublicIp { .. }) => 0,
            Ok(BridgeResponse::Error { message }) => {
                eprintln!("bridge error: {message}");
                1
            }
            Err(e) => {
                eprintln!("communication error: {e}");
                1
            }
        }
    })
}

fn handle_path(action: PathAction) -> i32 {
    match action {
        PathAction::Add => {
            if let Err(e) = crate::path_management::add() {
                eprintln!("path add failed: {e}");
                return 1;
            }
            0
        }
        PathAction::Remove => {
            if let Err(e) = crate::path_management::remove() {
                eprintln!("path remove failed: {e}");
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
