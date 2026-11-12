//! The informational flags. garter is a SIP003 plugin configured by its environment; any other
//! invocation is a plugin run.

use std::ffi::OsString;

/// Stamped at build time from the release tags (`build.rs`).
pub const VERSION: &str = env!("GARTER_VERSION");

const HELP: &str = "garter: a SIP003 plugin that chains other SIP003 plugins.

It takes no arguments: shadowsocks launches it with the SIP003 environment
(SS_LOCAL_HOST, SS_REMOTE_HOST, SS_PLUGIN_OPTIONS, ...).

  --version  print the version
  --help     print this text";

/// The text to print, then exit 0, when `args` (without the program name) is exactly one informational flag;
/// `None` for a plugin run, including one whose arguments are not UTF-8.
pub fn info_output(args: impl IntoIterator<Item = OsString>) -> Option<String> {
    let mut args = args.into_iter();
    let flag = args.next()?;
    if args.next().is_some() {
        return None;
    }
    match flag.to_str()? {
        "--version" => Some(format!("garter {VERSION}")),
        "--help" | "-h" => Some(HELP.to_string()),
        _ => None,
    }
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod cli_tests;
