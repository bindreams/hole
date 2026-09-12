use super::*;
use clap::Parser;
use skuld::temp_dir;
use std::path::Path;

// Elevated-run owner resolution (#572) ================================================================================

#[skuld::test]
fn user_dirs_derive_from_home_not_env() {
    use std::path::Path;
    assert_eq!(
        super::user_log_dir(Path::new("/Users/alice")),
        Path::new("/Users/alice/Library/Application Support/hole/logs")
    );
    assert_eq!(
        super::user_state_dir(Path::new("/Users/alice")),
        Path::new("/Users/alice/Library/Application Support/hole/state")
    );
}

#[skuld::test]
fn service_never_gets_an_owner() {
    assert!(
        super::resolved_owner(true).is_none(),
        "--service must never resolve an owner"
    );
}

#[skuld::test]
fn no_args_shows_the_dashboard() {
    // The point of the feature: a bare launch is an explicit user launch.
    let cli = Cli::try_parse_from(["hole"]).unwrap();
    assert!(cli.command.is_none());
    assert!(cli.show_dashboard());
}

#[skuld::test]
fn show_dashboard_flag_is_explicit_default() {
    let cli = Cli::try_parse_from(["hole", "--show-dashboard"]).unwrap();
    assert!(cli.command.is_none());
    assert!(cli.show_dashboard());
}

#[skuld::test]
fn no_show_dashboard_suppresses_it() {
    let cli = Cli::try_parse_from(["hole", "--no-show-dashboard"]).unwrap();
    assert!(!cli.show_dashboard());
}

#[skuld::test]
fn last_dashboard_flag_wins() {
    let suppressed = Cli::try_parse_from(["hole", "--show-dashboard", "--no-show-dashboard"]).unwrap();
    assert!(!suppressed.show_dashboard(), "--no-show-dashboard came last");
    let shown = Cli::try_parse_from(["hole", "--no-show-dashboard", "--show-dashboard"]).unwrap();
    assert!(shown.show_dashboard(), "--show-dashboard came last");
}

#[skuld::test]
fn version_subcommand_still_works() {
    let cli = Cli::try_parse_from(["hole", "version"]).unwrap();
    assert!(matches!(cli.command, Some(Command::Version)));
    assert!(!cli.show_dashboard_flag_present());
}

#[skuld::test]
fn dashboard_flags_rejected_in_subcommand_position() {
    // The flags are top-level only; mixing either after a subcommand should fail.
    assert!(Cli::try_parse_from(["hole", "bridge", "run", "--show-dashboard"]).is_err());
    assert!(Cli::try_parse_from(["hole", "bridge", "run", "--no-show-dashboard"]).is_err());
}

#[skuld::test]
fn show_dashboard_before_subcommand_parses() {
    // clap accepts the top-level flag before a subcommand. Both fields are
    // populated; main.rs is responsible for rejecting this combination at
    // runtime so the user sees an error rather than the flag being silently
    // ignored.
    let cli = Cli::try_parse_from(["hole", "--show-dashboard", "version"]).unwrap();
    assert!(cli.show_dashboard_flag_present());
    assert!(matches!(cli.command, Some(Command::Version)));
}

#[skuld::test]
fn launch_constants_are_the_flags_clap_accepts() {
    // Guards drift between the lib constants and clap's derived long names.
    let shown = Cli::try_parse_from(["hole", hole::launch::SHOW_DASHBOARD]).expect("SHOW_DASHBOARD must parse");
    assert!(shown.show_dashboard());
    let hidden = Cli::try_parse_from(["hole", hole::launch::NO_SHOW_DASHBOARD]).expect("NO_SHOW_DASHBOARD must parse");
    assert!(!hidden.show_dashboard());
}

#[skuld::test]
fn flag_presence_distinguishes_default_from_explicit() {
    assert!(!Cli::try_parse_from(["hole"]).unwrap().show_dashboard_flag_present());
    for flag in [hole::launch::SHOW_DASHBOARD, hole::launch::NO_SHOW_DASHBOARD] {
        assert!(
            Cli::try_parse_from(["hole", flag])
                .unwrap()
                .show_dashboard_flag_present(),
            "{flag} must register as explicitly present"
        );
    }
}

#[skuld::test]
fn resolve_show_dashboard_lets_an_explicit_flag_beat_the_env_var() {
    // A relaunch sets the env var and passes no flag; a flag on the command line
    // is the user speaking and wins.
    assert!(
        !resolve_show_dashboard(false, true, true),
        "env suppresses a default launch"
    );
    assert!(
        resolve_show_dashboard(false, true, false),
        "no env, no flag: the default shows"
    );
    assert!(
        resolve_show_dashboard(true, true, true),
        "--show-dashboard beats the env var"
    );
    assert!(
        !resolve_show_dashboard(true, false, false),
        "--no-show-dashboard needs no env var"
    );
}

// Duplicate-launch argv resolution (the single-instance callback).

#[skuld::test]
fn forwarded_argv_defaults_to_revealing() {
    let argv = vec![r"C:\Program Files\hole\bin\hole.exe".to_string()];
    assert!(show_dashboard_from_argv(&argv));
}

#[skuld::test]
fn forwarded_argv_honors_suppression() {
    // The autostart entry landing on a running instance must stay quiet.
    let argv = vec![
        "/Applications/Hole.app/Contents/MacOS/hole".to_string(),
        hole::launch::NO_SHOW_DASHBOARD.to_string(),
    ];
    assert!(!show_dashboard_from_argv(&argv));
}

#[skuld::test]
fn forwarded_argv_honors_explicit_show() {
    let argv = vec!["hole".to_string(), hole::launch::SHOW_DASHBOARD.to_string()];
    assert!(show_dashboard_from_argv(&argv));
}

#[skuld::test]
fn unparseable_forwarded_argv_reveals() {
    // Should be unreachable, but the fallback must be the useful response to a
    // user double-clicking the icon, not silence.
    let argv = vec!["hole".to_string(), "--not-a-flag".to_string()];
    assert!(show_dashboard_from_argv(&argv));
}

#[skuld::test]
fn only_subcommands_want_a_console() {
    // A GUI launch must never attach: the console sends CTRL_CLOSE_EVENT to
    // every attached process when its window closes.
    assert!(!wants_console(&None));
    assert!(wants_console(&Some(Command::Version)));
    assert!(wants_console(&Some(Command::Upgrade { yes: false })));
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
            ready_notify: None,
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
    assert!(should_install_cli_log_guard(&Command::Upgrade { yes: false }));
    assert!(should_install_cli_log_guard(&Command::Bridge {
        action: BridgeAction::Install {
            log_dir: None,
            repair_user_data_dir: None,
        },
    }));
    assert!(should_install_cli_log_guard(&Command::Bridge {
        action: BridgeAction::Uninstall { keep_covers: false },
    }));
    assert!(should_install_cli_log_guard(&Command::Bridge {
        action: BridgeAction::Status,
    }));
    assert!(should_install_cli_log_guard(&Command::Path {
        action: PathAction::Add,
    }));
    // Proxy subcommand variants must also install the guard so
    // failures land in `gui-cli.log`.
    assert!(should_install_cli_log_guard(&Command::Proxy {
        action: ProxyAction::Stop,
    }));
    assert!(should_install_cli_log_guard(&Command::Proxy {
        action: ProxyAction::Start {
            config_file: std::path::PathBuf::from("/tmp/x.json"),
            local_port: 4073,
            local_port_http: 4074,
            no_socks5: false,
            http: false,
            tunnel_mode: CliTunnelMode::Full,
        },
    }));
    assert!(should_install_cli_log_guard(&Command::Proxy {
        action: ProxyAction::TestServer {
            config_file: std::path::PathBuf::from("/tmp/x.json"),
        },
    }));
}

#[skuld::test]
fn upgrade_parses_yes_flag() {
    let long = Cli::try_parse_from(["hole", "upgrade", "--yes"]).unwrap();
    assert!(matches!(long.command, Some(Command::Upgrade { yes: true })));
    let short = Cli::try_parse_from(["hole", "upgrade", "-y"]).unwrap();
    assert!(matches!(short.command, Some(Command::Upgrade { yes: true })));
    let default = Cli::try_parse_from(["hole", "upgrade"]).unwrap();
    assert!(matches!(default.command, Some(Command::Upgrade { yes: false })));
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

// start_error_cli disposition =========================================================================================

#[skuld::test]
fn start_error_cli_disposition() {
    use hole_common::protocol::StartError;
    assert_eq!(start_error_cli(&StartError::Cancelled), (0, None));
    assert_eq!(start_error_cli(&StartError::AlreadyRunning), (0, None));
    let (code, log) = start_error_cli(&StartError::NetworkBlocked);
    assert_eq!(
        (code, log.as_deref()),
        (1, Some(hole_common::protocol::NETWORK_BLOCKED_MESSAGE))
    );
    assert_eq!(
        start_error_cli(&StartError::Failed { message: "x".into() }),
        (1, Some("bridge rejected start: x".to_string()))
    );
}

// Proxy subcommand parsing ============================================================================================

#[skuld::test]
fn proxy_start_parses_with_required_args() {
    let cli =
        Cli::try_parse_from(["hole", "proxy", "start", "--config-file", "/tmp/cfg.json"]).expect("parse proxy start");
    let Some(Command::Proxy {
        action:
            ProxyAction::Start {
                config_file,
                local_port,
                tunnel_mode,
                ..
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
    assert_eq!(entry.server.expose(), "127.0.0.1");
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

/// `serde_json::Error`'s `Display` echoes the bytes around the failure, and
/// the file parsed here is a `ServerEntry`. That window is also the one with
/// no sink backstop: `arm_server` runs only on the success path.
#[skuld::test]
fn read_server_entry_file_never_echoes_the_file_contents(#[fixture(temp_dir)] dir: &Path) {
    // A password mistyped as a JSON number. serde_json reports "invalid type:
    // integer `N`", and the value it names IS the secret.
    const SECRET_PW: &str = "9876543210";
    let body = format!(
        r#"{{"id":"x","name":"x","server":"203.0.113.7","server_port":8388,"method":"aes-256-gcm","password":{SECRET_PW}}}"#
    );
    let path = dir.join("mistyped.json");
    std::fs::write(&path, body.as_bytes()).unwrap();

    // Guard: without it this test would also pass against a `serde_json` that
    // had stopped echoing, and would prove nothing.
    let raw = serde_json::from_slice::<hole_common::config::ServerEntry>(body.as_bytes())
        .expect_err("must not parse")
        .to_string();
    assert!(raw.contains(SECRET_PW), "guard: serde_json echoes the value: {raw}");

    let err = super::read_server_entry_file(&path).expect_err("mistyped json should error");
    assert!(!err.contains(SECRET_PW), "the secret reached the CLI message: {err}");
    assert!(err.contains("failed to parse"), "{err}");
    assert!(
        err.contains("line 1"),
        "position must survive so the message stays actionable: {err}"
    );
}

/// The elevation payload's own decode path, and the sharper of the two: it
/// carries a whole `BridgeRequest`, and `arm_request_redaction` runs only
/// after it succeeds, so nothing is armed on either failure arm.
#[skuld::test]
fn decode_b64_request_never_echoes_the_payload() {
    use base64::Engine as _;
    const SECRET_PW: &str = "9876543210";

    let json = format!(
        r#"{{"Start":{{"config":{{"server":{{"id":"x","name":"x","server":"203.0.113.7","server_port":8388,"method":"aes-256-gcm","password":{SECRET_PW}}},"local_port":4073}},"attempt_id":"a"}}}}"#
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());

    // Guard: serde_json really does name the offending value.
    let raw = serde_json::from_str::<hole_common::protocol::BridgeRequest>(&json)
        .expect_err("must not parse")
        .to_string();
    assert!(raw.contains(SECRET_PW), "guard: serde_json echoes the value: {raw}");

    let err = super::decode_b64_request(&encoded).expect_err("mistyped payload must be rejected");
    assert!(!err.contains(SECRET_PW), "the secret reached the CLI message: {err}");
    assert!(err.contains("line 1"), "position must survive: {err}");
}

/// The base64 arm carries no input at all — the payload is Hole's own
/// encoding, so a decode failure means corruption and the offending byte
/// would say nothing a retry doesn't.
#[skuld::test]
fn decode_b64_request_never_echoes_a_malformed_encoding() {
    // `@` is not in the base64 alphabet; `DecodeError` would name it and its
    // offset into the encoded secret-bearing payload.
    let err = super::decode_b64_request("not@base64").expect_err("malformed base64 must be rejected");
    assert!(!err.contains('@'), "the offending byte reached the message: {err}");
    assert!(!err.contains("offset"), "{err}");
    assert!(err.contains("base64"), "the message must still name the fault: {err}");
}

/// Paired positive: a well-formed payload still decodes, so the two guards
/// above are not passing because everything is rejected.
#[skuld::test]
fn decode_b64_request_round_trips_a_well_formed_payload() {
    use base64::Engine as _;
    use hole_common::protocol::BridgeRequest;

    let request = BridgeRequest::Cancel {
        attempt_id: "attempt-7".into(),
    };
    let encoded = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&request).expect("serialize"));
    assert_eq!(super::decode_b64_request(&encoded).expect("must decode"), request);
}

// `bridge install` flag parsing =======================================================================================
//
// The GUI's elevated-install path passes `--log-dir` to redirect the CLI's
// gui-cli.log into a per-invocation temp directory and
// `--repair-user-data-dir` to reclaim a root-owned user data tree (macOS).

#[skuld::test]
fn bridge_install_parses_with_no_flags() {
    let cli = Cli::try_parse_from(["hole", "bridge", "install"]).expect("parse bridge install");
    let Some(Command::Bridge {
        action: BridgeAction::Install {
            log_dir,
            repair_user_data_dir,
        },
    }) = cli.command
    else {
        panic!("expected Command::Bridge::Install");
    };
    assert!(log_dir.is_none(), "default log_dir is None");
    assert!(repair_user_data_dir.is_none(), "default repair_user_data_dir is None");
}

#[skuld::test]
fn bridge_install_parses_log_dir_flag() {
    let cli = Cli::try_parse_from(["hole", "bridge", "install", "--log-dir", "/tmp/hole-install-XXXX"])
        .expect("parse bridge install --log-dir");
    let Some(Command::Bridge {
        action: BridgeAction::Install { log_dir, .. },
    }) = cli.command
    else {
        panic!("expected Command::Bridge::Install");
    };
    assert_eq!(log_dir, Some(std::path::PathBuf::from("/tmp/hole-install-XXXX")));
}

#[skuld::test]
fn bridge_install_parses_repair_user_data_dir_flag() {
    let cli = Cli::try_parse_from([
        "hole",
        "bridge",
        "install",
        "--repair-user-data-dir",
        "/Users/test/Library/Application Support/hole",
    ])
    .expect("parse bridge install --repair-user-data-dir");
    let Some(Command::Bridge {
        action: BridgeAction::Install {
            repair_user_data_dir, ..
        },
    }) = cli.command
    else {
        panic!("expected Command::Bridge::Install");
    };
    assert_eq!(
        repair_user_data_dir,
        Some(std::path::PathBuf::from("/Users/test/Library/Application Support/hole"))
    );
}

#[skuld::test]
fn bridge_install_parses_both_flags() {
    let cli = Cli::try_parse_from([
        "hole",
        "bridge",
        "install",
        "--log-dir",
        "/tmp/L",
        "--repair-user-data-dir",
        "/tmp/R",
    ])
    .expect("parse bridge install with both flags");
    let Some(Command::Bridge {
        action: BridgeAction::Install {
            log_dir,
            repair_user_data_dir,
        },
    }) = cli.command
    else {
        panic!("expected Command::Bridge::Install");
    };
    assert_eq!(log_dir, Some(std::path::PathBuf::from("/tmp/L")));
    assert_eq!(repair_user_data_dir, Some(std::path::PathBuf::from("/tmp/R")));
}

// `bridge log --log-dir` position-independence ========================================================================
//
// --log-dir applies to `bridge log` regardless of position relative to the
// nested watch/path subcommand.

#[skuld::test]
fn bridge_log_dir_flag_accepted_after_watch_subcommand() {
    let cli = Cli::try_parse_from([
        "hole",
        "bridge",
        "log",
        "watch",
        "--tail",
        "50",
        "--log-dir",
        "/tmp/svc",
    ])
    .expect("--log-dir should be accepted after the watch subcommand");
    let Some(Command::Bridge {
        action: BridgeAction::Log { log_dir, action },
    }) = cli.command
    else {
        panic!("expected Bridge::Log");
    };
    assert_eq!(log_dir, Some(std::path::PathBuf::from("/tmp/svc")));
    assert!(matches!(action, Some(LogAction::Watch { tail: 50 })));
}

#[skuld::test]
fn bridge_log_dir_flag_accepted_after_path_subcommand() {
    let cli = Cli::try_parse_from(["hole", "bridge", "log", "path", "--log-dir", "/tmp/svc"])
        .expect("--log-dir should be accepted after the path subcommand");
    let Some(Command::Bridge {
        action: BridgeAction::Log { log_dir, action },
    }) = cli.command
    else {
        panic!("expected Bridge::Log");
    };
    assert_eq!(log_dir, Some(std::path::PathBuf::from("/tmp/svc")));
    assert!(matches!(action, Some(LogAction::Path)));
}

#[skuld::test]
fn bridge_log_dir_flag_still_accepted_before_subcommand() {
    let cli = Cli::try_parse_from([
        "hole",
        "bridge",
        "log",
        "--log-dir",
        "/tmp/svc",
        "watch",
        "--tail",
        "50",
    ])
    .expect("--log-dir before the subcommand must still parse");
    let Some(Command::Bridge {
        action: BridgeAction::Log { log_dir, action },
    }) = cli.command
    else {
        panic!("expected Bridge::Log");
    };
    assert_eq!(log_dir, Some(std::path::PathBuf::from("/tmp/svc")));
    assert!(matches!(action, Some(LogAction::Watch { tail: 50 })));
}

// `hole bridge log` reader default ====================================================================================
//
// Falls back to the installed service's log dir, not the per-user default.

#[skuld::test]
fn resolve_bridge_log_dir_falls_back_to_service_dir() {
    // Pins the load-bearing wiring: the baked fallback is the service dir, not
    // the per-user default. A revert to default_log_dir would fail this.
    assert_eq!(
        super::resolve_bridge_log_dir_from(None, None),
        hole_common::update_marker::service_log_dir()
    );
    assert_ne!(
        super::resolve_bridge_log_dir_from(None, None),
        hole_common::logging::default_log_dir()
    );
}

#[skuld::test]
fn resolve_bridge_log_dir_prefers_explicit_override() {
    let custom = std::path::PathBuf::from("/tmp/custom-logs");
    assert_eq!(super::resolve_bridge_log_dir_from(Some(custom.clone()), None), custom);
}

#[skuld::test]
fn resolve_bridge_log_dir_uses_env_when_no_override() {
    let env = std::path::PathBuf::from("/tmp/env-logs");
    assert_eq!(super::resolve_bridge_log_dir_from(None, Some(env.clone())), env);
}

#[skuld::test]
fn resolve_cli_log_dir_honors_install_log_dir_override() {
    let custom = std::path::PathBuf::from("/tmp/hole-install-XYZ");
    let cmd = Command::Bridge {
        action: BridgeAction::Install {
            log_dir: Some(custom.clone()),
            repair_user_data_dir: None,
        },
    };
    let resolved = resolve_cli_log_dir(&cmd);
    assert_eq!(resolved, Some(custom));
}

#[skuld::test]
fn resolve_cli_log_dir_falls_back_to_default_without_override() {
    let cmd = Command::Bridge {
        action: BridgeAction::Install {
            log_dir: None,
            repair_user_data_dir: None,
        },
    };
    let resolved = resolve_cli_log_dir(&cmd);
    assert_eq!(resolved, Some(hole_common::logging::default_log_dir()));
}

// `bridge cutover` / `bridge unlock` parsing ==========================================================================

#[skuld::test]
fn bridge_cutover_parses_payload_and_target_version() {
    let cli = Cli::try_parse_from([
        "hole",
        "bridge",
        "cutover",
        "--payload",
        "/tmp/x.msi",
        "--target-version",
        "0.3.0",
    ])
    .expect("parse bridge cutover");
    let Some(Command::Bridge {
        action: BridgeAction::Cutover {
            payload,
            target_version,
        },
    }) = cli.command
    else {
        panic!("expected Command::Bridge::Cutover");
    };
    assert_eq!(payload, std::path::PathBuf::from("/tmp/x.msi"));
    assert_eq!(target_version, "0.3.0");
}

#[skuld::test]
fn bridge_cutover_requires_both_flags() {
    assert!(
        Cli::try_parse_from(["hole", "bridge", "cutover", "--payload", "/tmp/x.msi"]).is_err(),
        "--target-version is required"
    );
    assert!(
        Cli::try_parse_from(["hole", "bridge", "cutover", "--target-version", "0.3.0"]).is_err(),
        "--payload is required"
    );
}

#[skuld::test]
fn bridge_unlock_takes_no_args() {
    let cli = Cli::try_parse_from(["hole", "bridge", "unlock"]).expect("parse bridge unlock");
    assert!(matches!(
        cli.command,
        Some(Command::Bridge {
            action: BridgeAction::Unlock
        })
    ));
}

// The MSI invokes these two by name; a rename here silently breaks the
// installer's uninstall custom actions (bindreams/hole#1003).

#[skuld::test]
fn bridge_release_covers_takes_no_args() {
    let cli = Cli::try_parse_from(["hole", "bridge", "release-covers"]).expect("parse bridge release-covers");
    assert!(matches!(
        cli.command,
        Some(Command::Bridge {
            action: BridgeAction::ReleaseCovers
        })
    ));
}

#[skuld::test]
fn bridge_uninstall_keeps_covers_only_when_asked() {
    let bare = Cli::try_parse_from(["hole", "bridge", "uninstall"]).expect("parse bridge uninstall");
    assert!(matches!(
        bare.command,
        Some(Command::Bridge {
            action: BridgeAction::Uninstall { keep_covers: false }
        })
    ));

    let kept = Cli::try_parse_from(["hole", "bridge", "uninstall", "--keep-covers"])
        .expect("parse bridge uninstall --keep-covers");
    assert!(matches!(
        kept.command,
        Some(Command::Bridge {
            action: BridgeAction::Uninstall { keep_covers: true }
        })
    ));
}

#[skuld::test]
fn resolve_cli_log_dir_returns_none_for_exempt_commands() {
    assert!(resolve_cli_log_dir(&Command::Version).is_none());
    assert!(resolve_cli_log_dir(&Command::Bridge {
        action: BridgeAction::Run {
            socket_path: None,
            service: false,
            log_dir: None,
            state_dir: None,
            ready_notify: None,
        },
    })
    .is_none());
}

// --result-file flag (elevated outcome sink) ==========================================================================

#[skuld::test]
fn ipc_send_parses_result_file_flag() {
    let cli = Cli::try_parse_from([
        "hole",
        "bridge",
        "ipc-send",
        "--request-file",
        "/tmp/req.json",
        "--result-file",
        "/tmp/res.json",
    ])
    .expect("parse ipc-send --result-file");
    let Some(Command::Bridge {
        action: BridgeAction::IpcSend {
            request_file,
            result_file,
            ..
        },
    }) = cli.command
    else {
        panic!("expected IpcSend");
    };
    assert_eq!(request_file, Some(std::path::PathBuf::from("/tmp/req.json")));
    assert_eq!(result_file, Some(std::path::PathBuf::from("/tmp/res.json")));
}

#[skuld::test]
fn grant_access_parses_result_file_flag() {
    let cli = Cli::try_parse_from([
        "hole",
        "bridge",
        "grant-access",
        "--then-send-file",
        "/tmp/req.json",
        "--result-file",
        "/tmp/res.json",
    ])
    .expect("parse grant-access --result-file");
    let Some(Command::Bridge {
        action:
            BridgeAction::GrantAccess {
                then_send_file,
                result_file,
                ..
            },
    }) = cli.command
    else {
        panic!("expected GrantAccess");
    };
    assert_eq!(then_send_file, Some(std::path::PathBuf::from("/tmp/req.json")));
    assert_eq!(result_file, Some(std::path::PathBuf::from("/tmp/res.json")));
}

#[skuld::test]
fn ipc_send_rejects_result_file_with_base64() {
    // --result-file is the file-path channel only; the b64 path drops it, so the
    // combination is rejected at parse time rather than silently ignored.
    assert!(Cli::try_parse_from([
        "hole",
        "bridge",
        "ipc-send",
        "--base64",
        "e30=",
        "--result-file",
        "/tmp/res.json",
    ])
    .is_err());
}

#[skuld::test]
fn grant_access_rejects_result_file_with_then_send() {
    assert!(Cli::try_parse_from([
        "hole",
        "bridge",
        "grant-access",
        "--then-send",
        "e30=",
        "--result-file",
        "/tmp/res.json",
    ])
    .is_err());
}

// Redaction arming ====================================================================================================
//
// The CLI writes a fourth log file (`gui-cli.log`) and executes no GUI arming
// site, so without these the wrapped writers are inert for its whole life.
//
// Every test below drives arming as a side effect of the real production
// call graph, never by calling `arm_request_redaction` directly — that's the
// only way a test can catch a path the funnel doesn't actually cover. Each
// test ends at
// [`super::send_bridge_request_inner_at`], the same funnel every real CLI
// invocation reaches, pointed at a socket path with no listener so the
// connect fails fast and safely instead of ever touching a live bridge.

/// A socket path guaranteed to have no listener: unique per test (by
/// `suffix`) and per process, and removed first in case a previous run
/// left a stale file.
fn unarmed_socket_path(suffix: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("hole-cli-test-{}-{suffix}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

#[skuld::test]
fn cli_proxy_start_arms_the_config_file_entry(#[fixture(temp_dir)] dir: &Path) {
    use hole_common::logging::redact_arm::token_for;
    use hole_common::protocol::{BridgeRequest, ProxyConfig};

    const ENTRY_ID: &str = "55555555-0000-4000-8000-000000000000";
    let mut entry = hole_common::config::ServerEntry::default_placeholder();
    entry.id = ENTRY_ID.to_string();
    entry.server = "203.0.113.7".into();

    // Exactly what `ProxyAction::Start`'s handler does with `--config-file`
    // before it builds the request.
    let config_path = dir.join("entry.json");
    std::fs::write(&config_path, serde_json::to_string(&entry).unwrap()).unwrap();
    let entry = super::read_server_entry_file(&config_path).expect("read the entry file");

    let request = BridgeRequest::Start {
        config: ProxyConfig {
            server: entry,
            ..ProxyConfig::default()
        },
        attempt_id: "attempt".to_string(),
        on_startup: None,
    };
    let _ = super::send_bridge_request_inner_at(request, &unarmed_socket_path("proxy-start"));

    assert_eq!(util::redact::redact_str("203.0.113.7"), token_for(ENTRY_ID));
}

#[skuld::test]
fn cli_test_server_arms_the_config_file_entry(#[fixture(temp_dir)] dir: &Path) {
    use hole_common::logging::redact_arm::token_for;
    use hole_common::protocol::BridgeRequest;

    const ENTRY_ID: &str = "66666666-0000-4000-8000-000000000000";
    let mut entry = hole_common::config::ServerEntry::default_placeholder();
    entry.id = ENTRY_ID.to_string();
    entry.server = "203.0.113.9".into();

    // Exactly what `ProxyAction::TestServer`'s handler does with
    // `--config-file` before it builds the request.
    let config_path = dir.join("entry.json");
    std::fs::write(&config_path, serde_json::to_string(&entry).unwrap()).unwrap();
    let entry = super::read_server_entry_file(&config_path).expect("read the entry file");

    let request = BridgeRequest::TestServer {
        entry,
        dns: Default::default(),
    };
    let _ = super::send_bridge_request_inner_at(request, &unarmed_socket_path("test-server"));

    assert_eq!(util::redact::redact_str("203.0.113.9"), token_for(ENTRY_ID));
}

/// The `--base64` elevation path: `decode_b64_request` (the real decoder)
/// feeds straight into the funnel, exactly as `handle_ipc_send_b64` does.
#[skuld::test]
fn cli_ipc_send_base64_arms_a_start_request() {
    use hole_common::logging::redact_arm::token_for;
    use hole_common::protocol::{BridgeRequest, ProxyConfig};

    const ENTRY_ID: &str = "77777777-0000-4000-8000-000000000000";
    let mut entry = hole_common::config::ServerEntry::default_placeholder();
    entry.id = ENTRY_ID.to_string();
    entry.server = "203.0.113.11".into();
    let request = BridgeRequest::Start {
        config: ProxyConfig {
            server: entry,
            ..ProxyConfig::default()
        },
        attempt_id: "attempt".to_string(),
        on_startup: None,
    };

    let b64 = crate::elevation::encode_request(&request);
    let decoded = super::decode_b64_request(&b64).expect("decode the base64 payload");
    let _ = super::send_bridge_request_inner_at(decoded, &unarmed_socket_path("ipc-send-b64"));

    assert_eq!(util::redact::redact_str("203.0.113.11"), token_for(ENTRY_ID));
}

/// The `--request-file` / `--then-send-file` elevation path:
/// `crate::elevation::read_request_file` is the exact function both
/// `hole bridge ipc-send --request-file` and `hole bridge grant-access
/// --then-send-file` call before handing the decoded request to the funnel —
/// there is no other code between them, so driving it once proves both.
///
/// This is also the case that must catch a classifier that silently skips a
/// secret-bearing variant: `Reload` is the request this exact path carries
/// when the elevation flow retries a running proxy's config after a
/// permission grant, and it was the one variant `arm_request_redaction`'s old
/// `_ => {}` let through unarmed.
#[skuld::test]
fn cli_request_file_arms_a_reload_request(#[fixture(temp_dir)] dir: &Path) {
    use hole_common::logging::redact_arm::token_for;
    use hole_common::protocol::{BridgeRequest, ProxyConfig};

    const ENTRY_ID: &str = "88888888-0000-4000-8000-000000000000";
    let mut entry = hole_common::config::ServerEntry::default_placeholder();
    entry.id = ENTRY_ID.to_string();
    entry.server = "203.0.113.13".into();
    let request = BridgeRequest::Reload {
        config: ProxyConfig {
            server: entry,
            ..ProxyConfig::default()
        },
    };

    let path = dir.join("request.json");
    std::fs::write(&path, serde_json::to_string(&request).unwrap()).unwrap();
    let decoded = crate::elevation::read_request_file(&path).expect("decode the request file");
    let _ = super::send_bridge_request_inner_at(decoded, &unarmed_socket_path("request-file-reload"));

    assert_eq!(util::redact::redact_str("203.0.113.13"), token_for(ENTRY_ID));
}

/// Arming is a *funnel* property, not a call-site obligation.
///
/// The rule is structural: one mechanism, invoked once, at the single point a
/// request reaches the wire — and the behavioral tests above exercise it
/// through that real call graph, not by calling it directly.
#[skuld::test]
fn redaction_is_armed_only_by_the_wire_funnel() {
    // Belt-and-braces alongside the behavioral tests above: this is a
    // call-graph shape (arming is invoked from exactly one place, crate-wide,
    // and no second mechanism exists beside it), which those tests can prove
    // for the paths they each drive but not rule out for the rest of the
    // crate. Scoped to every non-test source file under `src/` — not just
    // `cli.rs` — because the property this guards ("no ad-hoc `arm_server`
    // call exists anywhere") is falsified just as much by one appearing in
    // another file as by one appearing here. `*_tests.rs` files are skipped:
    // they legitimately reference these names in doc comments, `use`
    // imports, and (as here) the needle strings themselves.
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut sources: Vec<(String, String)> = Vec::new();
    for entry in walkdir::WalkDir::new(&src_root) {
        let entry = entry.expect("failed to walk crates/hole/src");
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name.ends_with("_tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(path).expect("failed to read a walked source file");
        sources.push((path.display().to_string(), text));
    }

    let calls = |needle: &str| -> Vec<String> {
        sources
            .iter()
            .flat_map(|(file, source)| {
                source
                    .lines()
                    .filter(|l| l.contains(needle))
                    // Strip *any* comment line (`//...`, which also matches doc
                    // comments `///...`), not just doc comments: a plain `//` comment
                    // mentioning the function name must not miscount as a call site.
                    .filter(|l| !l.trim_start().starts_with("//") && !l.contains(&format!("fn {needle}")))
                    .map(move |l| format!("{file}: {}", l.trim()))
            })
            .collect()
    };

    let arm_calls = calls("arm_request_redaction(");
    assert_eq!(
        arm_calls.len(),
        1,
        "arming must have exactly one call site, got: {arm_calls:?}"
    );

    // No second mechanism: a hand-rolled `arm_server` beside a send is how two
    // of the six paths used to do this, and is what let the sixth do nothing.
    let ad_hoc = calls("arm_server(");
    assert!(
        ad_hoc.iter().all(|l| l.contains("=> arm_server(")),
        "the only `arm_server` calls may be inside arm_request_redaction's match: {ad_hoc:?}"
    );

    // The one call site is inside the driver, ahead of the connect. Matched
    // by path component, not the rendered path string: `Display` renders
    // `\` on Windows, so a `/`-suffix check silently finds nothing there.
    let (_, cli_source) = sources
        .iter()
        .find(|(file, _)| std::path::Path::new(file).file_name() == Some(std::ffi::OsStr::new("cli.rs")))
        .expect("cli.rs must be among the walked sources");
    let driver = cli_source
        .split_once("fn send_bridge_request_inner_at(")
        .expect("the driver must exist")
        .1;
    let body = driver.split("\nfn ").next().expect("driver body");
    let arm_at = body.find("arm_request_redaction(").expect("the driver must arm");
    let connect_at = body.find("BridgeClient::connect(").expect("the driver must connect");
    assert!(arm_at < connect_at, "arming must precede the connect");
}
