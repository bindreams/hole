use super::*;
use clap::Parser;

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
