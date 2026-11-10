//! The user-facing text of a failed start or reload, in one place for the tray, the elevated path and the commands.

use hole_common::protocol::Refusal;

/// Single producer of the user-facing bridge-error string, shared by the elevated
/// and non-elevated paths so they read identically. The bridge message is shown
/// raw: it is authored by the bridge running as a system account (LocalSystem /
/// root) with system-scoped paths, and `ProxyConfig` carries no path field, so it
/// cannot contain user PII (#475). A future change that threads a user path into a
/// bridge request and echoes it here must revisit this.
pub fn bridge_error_toast(message: &str) -> String {
    format!("Bridge error: {message}")
}

/// Toast shown for a concurrent-start rejection (409). Shared by the live-Connect
/// (`tray::outcome_for_start_response`) and elevated (`tray::elevate_and_confirm`) paths so the
/// two surfaces read identically.
pub const CONCURRENT_START_MESSAGE: &str = "Another start is already in progress.";

/// What the GUI tells the user to do about a start refused over unreadable state files.
const STATE_BLOCKED_REMEDY: &str = "Use Help > Reset Network… to clear them.";

/// Final toast for a refused start, shared by the live-Connect and elevated paths so they read identically.
/// `NetworkBlocked` and `StateBlocked` are host-free and self-contained (shown raw); every other failure is wrapped by
/// [`bridge_error_toast`].
pub fn start_error_toast(refusal: &Refusal) -> String {
    match refusal {
        Refusal::NetworkBlocked => hole_common::protocol::NETWORK_BLOCKED_MESSAGE.to_string(),
        Refusal::StateBlocked { files } => hole_common::protocol::state_blocked_message(files, STATE_BLOCKED_REMEDY),
        Refusal::Failed { message } => bridge_error_toast(message),
    }
}

/// Why a reload did not apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadError {
    /// The reload's slow path stopped the session and its restart was refused: the proxy is down.
    Refused(Refusal),
    /// The bridge answered with a status the route has no meaning for, such as the framework's 413 for a config over
    /// the body limit. It refused the request without acting on it: the proxy runs on the previous settings.
    Rejected,
    /// The exchange failed (a transport or protocol error): whether the reload applied is not known.
    Transport,
}

/// Toast for a reload that did not apply. Each text stands alone: a caller may put a sentence before it, never one that
/// claims an outcome.
pub fn reload_error_toast(error: ReloadError) -> String {
    match error {
        ReloadError::Refused(refusal) => format!(
            "The proxy restarted to apply the change and did not come back up. {}",
            start_error_toast(&refusal)
        ),
        ReloadError::Rejected => "The Hole bridge rejected the change, so it was not applied.".to_owned(),
        ReloadError::Transport => "The Hole bridge did not answer, so the change may not have been applied.".to_owned(),
    }
}

#[cfg(test)]
#[path = "toast_tests.rs"]
mod toast_tests;
