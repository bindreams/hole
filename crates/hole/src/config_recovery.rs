//! User-facing messaging for config quarantine (#467).

use hole_common::config_store::ConfigRecovery;
use util::dir::Refusal;

/// Kind-neutral: covers every [`ConfigRecovery`] branch: corruption (parse), unreadable (IO), newer-release, a refused
/// read and a folder that did not open.
pub const RECOVERY_DIALOG_TITLE: &str = "Settings could not be loaded";

/// Native-dialog body for a config-recovery event. Paths are allowed here:
/// this is a local native dialog, not a toast (CONTRIBUTING.md "Console relay
/// and toasts"); the user needs to know where the backup is. The underlying
/// parse/IO error text stays in `gui.log`.
pub fn recovery_dialog_message(recovery: &ConfigRecovery) -> String {
    match recovery {
        ConfigRecovery::Quarantined { backup, .. } => format!(
            "Hole could not read its settings file, so it is starting with default settings.\n\n\
             The old file was backed up to:\n{}",
            backup.display()
        ),
        ConfigRecovery::QuarantineFailed { path, .. } => format!(
            "Hole could not read its settings file, so it is starting with default settings.\n\n\
             Backing up the old file also failed, so saving settings is disabled until Hole \
             restarts — otherwise the old file would be overwritten. Move or delete it to fix \
             this:\n{}",
            path.display()
        ),
        ConfigRecovery::FolderNotOpened { path, .. } => format!(
            "Hole could not open the folder of its settings file, so it is starting with default settings.\n\n\
             Saving settings is disabled until Hole restarts. Check that this folder exists and that Hole \
             may use it:\n{}",
            path.parent().unwrap_or(path).display()
        ),
        ConfigRecovery::Refused { path, refusal } => {
            let (found, way_back) = what_was_refused(refusal);
            format!(
                "Hole could not read its settings file, so it is starting with default settings.\n\n\
                 {found} Hole left it untouched, and saving settings is disabled until Hole restarts. \
                 {way_back}:\n{}",
                path.display()
            )
        }
        ConfigRecovery::LeftInPlace { path, .. } => format!(
            "Hole's settings file was written by a newer version of Hole, so it is starting with \
             default settings.\n\n\
             The file was left untouched, and saving settings is disabled until Hole restarts \
             — otherwise it would be overwritten. Update Hole to the newer version to use it, or \
             move or delete it to start fresh:\n{}",
            path.display()
        ),
    }
}

/// What a refused read of the settings file found, and how to get past it, as sentences for the dialog. A link or
/// another account's file is refused only to a process run as administrator, so a normal start reads it; what is not
/// a regular file is refused to every process, so it has to be moved or deleted. A refusal of the folder is not one:
/// a folder that is refused is [`ConfigRecovery::FolderNotOpened`]. What is at the name may be a folder, so only the
/// finding that knows it is a file says so.
fn what_was_refused(refusal: &Refusal) -> (&'static str, &'static str) {
    const START_NORMALLY: &str =
        "If Hole was started as administrator (with sudo on macOS), quit it and start it normally";
    match refusal {
        Refusal::Symlink => (
            "What is at its name is a link, which Hole run as administrator does not follow.",
            START_NORMALLY,
        ),
        Refusal::NotRegular => (
            "What is at its name is not a regular file.",
            "To start fresh, move or delete it",
        ),
        Refusal::ForeignFile => (
            "The file belongs to another account than the one Hole runs as.",
            START_NORMALLY,
        ),
        Refusal::NotDirectory => unreachable!("a folder that is not one is FolderNotOpened, not a refused file"),
        #[cfg(unix)]
        Refusal::ForeignOwner { .. } => {
            unreachable!("a folder another account owns is FolderNotOpened, not a refused file")
        }
    }
}

#[cfg(test)]
#[path = "config_recovery_tests.rs"]
mod config_recovery_tests;
