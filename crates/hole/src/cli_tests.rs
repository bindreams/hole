use super::*;
use clap::Parser;
use skuld::temp_dir;
use std::path::Path;

#[skuld::test]
fn no_args_means_gui_mode() {
    let cli = Cli::try_parse_from(["hole"]).unwrap();
    assert!(cli.command.is_none());
    assert!(!cli.show_dashboard);
}

#[skuld::test]
fn show_dashboard_flag_alone() {
    let cli = Cli::try_parse_from(["hole", "--show-dashboard"]).unwrap();
    assert!(cli.command.is_none());
    assert!(cli.show_dashboard);
}

#[skuld::test]
fn version_subcommand_still_works() {
    let cli = Cli::try_parse_from(["hole", "version"]).unwrap();
    assert!(matches!(cli.command, Some(Command::Version)));
    assert!(!cli.show_dashboard);
}

#[skuld::test]
fn show_dashboard_rejected_in_subcommand_position() {
    // The flag is top-level only; mixing it after a subcommand should fail.
    assert!(Cli::try_parse_from(["hole", "bridge", "run", "--show-dashboard"]).is_err());
}

#[skuld::test]
fn show_dashboard_before_subcommand_parses() {
    // clap accepts the top-level flag before a subcommand. Both fields are
    // populated; main.rs is responsible for rejecting this combination at
    // runtime so the user sees an error rather than the flag being silently
    // ignored.
    let cli = Cli::try_parse_from(["hole", "--show-dashboard", "version"]).unwrap();
    assert!(cli.show_dashboard);
    assert!(matches!(cli.command, Some(Command::Version)));
}

// Dispatch guard exemption: must NOT install a gui-cli.log subscriber for
// commands that either have their own subscriber (`bridge run`) or don't
// need an audit trail (`version`, `bridge log [...]`). Installing one would
// either clobber the bridge's own subscriber via a failed try_init or
// create spurious `gui-cli.log` files for read-only inspection commands.

#[skuld::test]
fn dispatch_exempts_version_from_cli_log_guard() {
    assert!(!should_install_cli_log_guard(&Command::Version));
}

#[skuld::test]
fn dispatch_exempts_bridge_run_from_cli_log_guard() {
    let cmd = Command::Bridge {
        action: BridgeAction::Run {
            socket_path: None,
            service: false,
            log_dir: None,
            state_dir: None,
        },
    };
    assert!(!should_install_cli_log_guard(&cmd));
}

#[skuld::test]
fn dispatch_exempts_bridge_log_from_cli_log_guard() {
    let cmd = Command::Bridge {
        action: BridgeAction::Log {
            log_dir: None,
            action: None,
        },
    };
    assert!(!should_install_cli_log_guard(&cmd));
    let cmd = Command::Bridge {
        action: BridgeAction::Log {
            log_dir: None,
            action: Some(LogAction::Path),
        },
    };
    assert!(!should_install_cli_log_guard(&cmd));
    let cmd = Command::Bridge {
        action: BridgeAction::Log {
            log_dir: None,
            action: Some(LogAction::Watch { tail: 0 }),
        },
    };
    assert!(!should_install_cli_log_guard(&cmd));
}

#[skuld::test]
fn dispatch_installs_cli_log_guard_for_write_actions() {
    assert!(should_install_cli_log_guard(&Command::Upgrade));
    assert!(should_install_cli_log_guard(&Command::Bridge {
        action: BridgeAction::Install,
    }));
    assert!(should_install_cli_log_guard(&Command::Bridge {
        action: BridgeAction::Uninstall,
    }));
    assert!(should_install_cli_log_guard(&Command::Bridge {
        action: BridgeAction::Status,
    }));
    assert!(should_install_cli_log_guard(&Command::Path {
        action: PathAction::Add,
    }));
    // The new Proxy subcommand variants must also install the guard so
    // failures land in `gui-cli.log`.
    assert!(should_install_cli_log_guard(&Command::Proxy {
        action: ProxyAction::Stop,
    }));
    assert!(should_install_cli_log_guard(&Command::Proxy {
        action: ProxyAction::Start {
            config_file: std::path::PathBuf::from("/tmp/x.json"),
            local_port: 4073,
            tunnel_mode: CliTunnelMode::Full,
        },
    }));
    assert!(should_install_cli_log_guard(&Command::Proxy {
        action: ProxyAction::TestServer {
            config_file: std::path::PathBuf::from("/tmp/x.json"),
        },
    }));
}

// Tests: bridge_log_watch rotation detection ==========================================================================
//
// These exercise the `open_watch_reader` + `file_was_rotated` helpers in
// isolation. They simulate the rename+recreate sequence that `file-rotate`
// performs on size-based rollover.

#[skuld::test]
fn file_was_rotated_detects_rename_and_recreate(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("watched.log");
    std::fs::write(&path, b"original content\n").expect("seed watched.log");

    let (_reader, handle) = super::open_watch_reader(&path).expect("open_watch_reader");

    // Simulate file-rotate: rename current → .1, create a fresh active file.
    std::fs::rename(&path, dir.join("watched.log.1")).expect("rename watched.log");
    std::fs::write(&path, b"").expect("recreate watched.log");

    assert!(
        super::file_was_rotated(&path, &handle).expect("stat new file"),
        "file_was_rotated should detect the rename+recreate"
    );
}

#[skuld::test]
fn file_was_rotated_reports_false_for_unchanged_file_even_after_appends(#[fixture(temp_dir)] dir: &Path) {
    use std::io::Write;

    let path = dir.join("watched.log");
    std::fs::write(&path, b"initial\n").expect("seed watched.log");

    let (_reader, handle) = super::open_watch_reader(&path).expect("open_watch_reader");

    // Append to the same file — the inode/file-id is unchanged, so
    // file_was_rotated must return false.
    let mut appender = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("open for append");
    appender.write_all(b"more\n").expect("append bytes");
    drop(appender);

    assert!(
        !super::file_was_rotated(&path, &handle).expect("stat unchanged file"),
        "appending to the same file must not look like rotation"
    );
}

#[skuld::test]
fn file_was_rotated_reports_false_when_path_missing(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("watched.log");
    std::fs::write(&path, b"initial").expect("seed watched.log");

    let (_reader, handle) = super::open_watch_reader(&path).expect("open_watch_reader");

    // Simulate the sub-millisecond window in file-rotate between rename and
    // recreate: the path is transiently missing. `file_was_rotated` must
    // return Ok(false), not Err, so the watch loop will just retry on the
    // next poll tick.
    std::fs::remove_file(&path).expect("remove watched.log");

    assert!(
        !super::file_was_rotated(&path, &handle).expect("stat missing path"),
        "missing path must map to Ok(false), not an error"
    );
}

// Proxy subcommand parsing ============================================================================================

#[skuld::test]
fn proxy_start_parses_with_required_args() {
    let cli =
        Cli::try_parse_from(["hole", "proxy", "start", "--config-file", "/tmp/cfg.json"]).expect("parse proxy start");
    let Some(Command::Proxy {
        action: ProxyAction::Start {
            config_file,
            local_port,
            tunnel_mode,
        },
    }) = cli.command
    else {
        panic!("expected Command::Proxy::Start");
    };
    assert_eq!(config_file, std::path::PathBuf::from("/tmp/cfg.json"));
    assert_eq!(local_port, 4073, "default local_port should be 4073");
    assert!(
        matches!(tunnel_mode, CliTunnelMode::Full),
        "default tunnel mode should be Full"
    );
}

#[skuld::test]
fn proxy_start_accepts_socks_only_tunnel_mode() {
    let cli = Cli::try_parse_from([
        "hole",
        "proxy",
        "start",
        "--config-file",
        "/tmp/cfg.json",
        "--tunnel-mode",
        "socks-only",
    ])
    .expect("parse proxy start with --tunnel-mode socks-only");
    let Some(Command::Proxy {
        action: ProxyAction::Start { tunnel_mode, .. },
    }) = cli.command
    else {
        panic!("expected Command::Proxy::Start");
    };
    assert!(
        matches!(tunnel_mode, CliTunnelMode::SocksOnly),
        "tunnel_mode should be SocksOnly"
    );
}

#[skuld::test]
fn proxy_start_accepts_custom_local_port() {
    let cli = Cli::try_parse_from([
        "hole",
        "proxy",
        "start",
        "--config-file",
        "/tmp/cfg.json",
        "--local-port",
        "40730",
    ])
    .expect("parse proxy start with custom port");
    let Some(Command::Proxy {
        action: ProxyAction::Start { local_port, .. },
    }) = cli.command
    else {
        panic!("expected Command::Proxy::Start");
    };
    assert_eq!(local_port, 40730);
}

#[skuld::test]
fn proxy_stop_takes_no_args() {
    let cli = Cli::try_parse_from(["hole", "proxy", "stop"]).expect("parse proxy stop");
    assert!(matches!(
        cli.command,
        Some(Command::Proxy {
            action: ProxyAction::Stop
        })
    ));
}

#[skuld::test]
fn proxy_test_server_parses() {
    let cli = Cli::try_parse_from(["hole", "proxy", "test-server", "--config-file", "/tmp/cfg.json"])
        .expect("parse proxy test-server");
    let Some(Command::Proxy {
        action: ProxyAction::TestServer { config_file },
    }) = cli.command
    else {
        panic!("expected Command::Proxy::TestServer");
    };
    assert_eq!(config_file, std::path::PathBuf::from("/tmp/cfg.json"));
}

#[skuld::test]
fn proxy_start_requires_config_file_arg() {
    // Missing --config-file is a clap-level parse error.
    assert!(Cli::try_parse_from(["hole", "proxy", "start"]).is_err());
}

#[skuld::test]
fn read_server_entry_file_parses_valid_json(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("entry.json");
    std::fs::write(
        &path,
        r#"{"id":"x","name":"x","server":"127.0.0.1","server_port":8388,"method":"aes-256-gcm","password":"secret"}"#,
    )
    .unwrap();
    let entry = super::read_server_entry_file(&path).expect("parse entry");
    assert_eq!(entry.server, "127.0.0.1");
    assert_eq!(entry.server_port, 8388);
}

#[skuld::test]
fn read_server_entry_file_rejects_malformed_json(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("malformed.json");
    std::fs::write(&path, b"{not valid json}").unwrap();
    let err = super::read_server_entry_file(&path).expect_err("malformed json should error");
    assert!(
        err.contains("failed to parse"),
        "error should mention parse failure: {err}"
    );
}
