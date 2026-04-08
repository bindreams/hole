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
