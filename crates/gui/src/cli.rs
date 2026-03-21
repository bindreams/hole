// CLI subcommand dispatch.

use clap::{Parser, Subcommand};

// CLI structure =====

#[derive(Parser)]
#[command(name = "hole", about = "Shadowsocks GUI with transparent proxy", version = env!("HOLE_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print version information
    Version,
    /// Check for updates and install the latest version
    Upgrade,
    /// Manage the privileged daemon service
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Manage PATH integration
    Path {
        #[command(subcommand)]
        action: PathAction,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Run the daemon (invoked by the service manager)
    Run,
    /// Install and start the daemon service
    Install,
    /// Stop and remove the daemon service
    Uninstall,
    /// Print daemon install/running status
    Status,
    /// View daemon logs
    Log {
        #[command(subcommand)]
        action: Option<LogAction>,
    },
    /// Add the current user to the hole group (requires elevation)
    GrantAccess {
        /// Also send this IPC command after granting access (base64-encoded JSON)
        #[arg(long)]
        then_send: Option<String>,
    },
    /// Send a single IPC command to the daemon (requires elevation)
    IpcSend {
        /// Base64-encoded JSON of the DaemonRequest
        #[arg(long)]
        base64: String,
    },
}

#[derive(Subcommand)]
enum LogAction {
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
enum PathAction {
    /// Add hole to the system PATH
    Add,
    /// Remove hole from the system PATH
    Remove,
}

// Dispatch =====

/// Parse CLI arguments and dispatch to the appropriate handler.
/// This function exits the process when done.
pub fn dispatch() -> ! {
    #[cfg(target_os = "windows")]
    attach_console();

    let cli = Cli::parse();

    let code = match cli.command {
        Command::Version => {
            println!("hole {}", hole_gui::version::VERSION);
            0
        }
        Command::Upgrade => handle_upgrade(),
        Command::Daemon { action } => handle_daemon(action),
        Command::Path { action } => handle_path(action),
    };

    std::process::exit(code)
}

fn handle_upgrade() -> i32 {
    eprintln!("checking for updates...");
    match hole_gui::update::check_for_update() {
        Ok(Some(info)) => {
            eprintln!("update available: v{}", info.version);

            let download_dir = std::env::temp_dir().join("hole-update");
            if let Err(e) = std::fs::create_dir_all(&download_dir) {
                eprintln!("failed to create temp dir: {e}");
                return 1;
            }
            let dest = download_dir.join(&info.asset_name);

            eprintln!("downloading {}...", info.asset_name);
            if let Err(e) = hole_gui::update::download_asset(&info.asset_url, &dest) {
                eprintln!("download failed: {e}");
                return 1;
            }

            eprintln!("installing...");
            if let Err(e) = hole_gui::update::run_installer(&dest, true) {
                eprintln!("installation failed: {e}");
                // Best-effort cleanup
                let _ = std::fs::remove_file(&dest);
                return 1;
            }

            // Best-effort cleanup
            let _ = std::fs::remove_file(&dest);
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

fn handle_daemon(action: DaemonAction) -> i32 {
    match action {
        DaemonAction::Run => {
            let _guard = hole_daemon::logging::init();
            tracing::info!("hole daemon starting");
            hole_daemon::routing::teardown_split_routes().ok();

            if let Err(e) = hole_daemon::platform::os::run() {
                eprintln!("daemon error: {e}");
                return 1;
            }

            0
        }
        DaemonAction::Install => {
            if let Err(e) = crate::setup::install_daemon() {
                eprintln!("daemon install failed: {e}");
                return 1;
            }
            0
        }
        DaemonAction::Uninstall => {
            if let Err(e) = crate::setup::uninstall_daemon() {
                eprintln!("daemon uninstall failed: {e}");
                return 1;
            }
            0
        }
        DaemonAction::Status => {
            use crate::setup::DaemonInstallStatus;
            match crate::setup::daemon_install_status() {
                DaemonInstallStatus::Running => {
                    println!("installed (running)");
                    0
                }
                DaemonInstallStatus::Installed => {
                    println!("installed (stopped)");
                    1
                }
                DaemonInstallStatus::NotInstalled => {
                    println!("not installed");
                    2
                }
            }
        }
        DaemonAction::Log { action } => handle_daemon_log(action),
        DaemonAction::GrantAccess { then_send } => handle_grant_access(then_send),
        DaemonAction::IpcSend { base64 } => handle_ipc_send(&base64),
    }
}

fn handle_daemon_log(action: Option<LogAction>) -> i32 {
    let log_dir = hole_daemon::logging::log_dir();
    let log_path = log_dir.join("hole-daemon.log");

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
        Some(LogAction::Watch { tail }) => daemon_log_watch(&log_path, tail),
    }
}

/// Tail and follow a log file (like `tail -f`).
fn daemon_log_watch(path: &std::path::Path, tail_lines: usize) -> i32 {
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

fn handle_grant_access(then_send: Option<String>) -> i32 {
    use hole_common::protocol::PERMISSION_DENIED_HELP;

    // Ensure the group exists (may not if daemon was installed by an older version)
    if let Err(e) = hole_daemon::group::create_group() {
        eprintln!("failed to create group: {e}");
        return 1;
    }

    // Add current user to the hole group
    match hole_daemon::group::installing_username() {
        Ok(user) => {
            if let Err(e) = hole_daemon::group::add_user_to_group(&user) {
                eprintln!("failed to add '{user}' to group: {e}");
                return 1;
            }
            eprintln!("added '{user}' to '{}' group", hole_daemon::group::GROUP_NAME);
        }
        Err(e) => {
            eprintln!("could not determine current user: {e}");
            eprintln!("{PERMISSION_DENIED_HELP}");
            return 1;
        }
    }

    // Optionally proxy a command to the daemon
    if let Some(b64) = then_send {
        return handle_ipc_send(&b64);
    }

    0
}

fn handle_ipc_send(base64_request: &str) -> i32 {
    use base64::Engine;
    use hole_common::protocol::{DaemonRequest, DaemonResponse};

    // Decode base64
    let json_bytes = match base64::engine::general_purpose::STANDARD.decode(base64_request) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("invalid base64: {e}");
            return 1;
        }
    };

    // Deserialize request
    let request: DaemonRequest = match serde_json::from_slice(&json_bytes) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("invalid request JSON: {e}");
            return 1;
        }
    };

    // Connect and send
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        #[cfg(target_os = "windows")]
        let socket_id = hole_common::protocol::DAEMON_SOCKET_NAME;
        #[cfg(target_os = "macos")]
        let socket_id = hole_common::protocol::DAEMON_SOCKET_PATH;

        let mut client = match crate::daemon_client::DaemonClient::connect(socket_id).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("failed to connect to daemon: {e}");
                return 1;
            }
        };

        match client.send(request).await {
            Ok(DaemonResponse::Ack) => 0,
            Ok(DaemonResponse::Status { .. }) => 0,
            Ok(DaemonResponse::Error { message }) => {
                eprintln!("daemon error: {message}");
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

// Platform helpers =====

#[cfg(target_os = "windows")]
fn attach_console() {
    use windows::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    // Best-effort: if we're launched from a terminal, attach to it for stdout/stderr.
    // If not (e.g. launched from Explorer), this fails silently — that's fine.
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}
