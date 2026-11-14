//! User-facing messaging for config quarantine (#467).

use hole_common::config_store::ConfigRecovery;

/// Kind-neutral: covers both corruption (parse) and unreadable (IO) branches.
pub const RECOVERY_DIALOG_TITLE: &str = "Settings could not be loaded";

/// Native-dialog body for a config-recovery event. Paths are allowed here:
/// this is a local native dialog, not a toast (CONTRIBUTING.md "Console relay
/// and toasts"); the user needs to know where the backup is. `gui.log` gets a
/// parse error's kind, line and column, and an I/O error's text.
pub fn recovery_dialog_message(recovery: &ConfigRecovery) -> String {
    match &recovery.backup {
        Ok(bak) => format!(
            "Hole could not read its settings file, so it is starting with default settings.\n\n\
             The old file was backed up to:\n{}",
            bak.display()
        ),
        Err(_) => format!(
            "Hole could not read its settings file, so it is starting with default settings.\n\n\
             Backing up the old file also failed, so saving settings is disabled until Hole \
             restarts — otherwise the old file would be overwritten. Move or delete it to fix \
             this:\n{}",
            recovery.path.display()
        ),
    }
}

#[cfg(test)]
#[path = "config_recovery_tests.rs"]
mod config_recovery_tests;
