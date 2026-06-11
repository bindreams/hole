use super::*;
use hole_common::config::ConfigError;
use std::path::PathBuf;

fn recovery(backup: Result<PathBuf, std::io::Error>) -> ConfigRecovery {
    ConfigRecovery {
        path: PathBuf::from("/cfg/config.json"),
        error: ConfigError::Read {
            source: std::io::Error::other("boom"),
        },
        backup,
    }
}

#[skuld::test]
fn message_with_backup_names_the_backup_file() {
    let msg = recovery_dialog_message(&recovery(Ok(PathBuf::from(
        "/cfg/config.json.2026-06-10T14-23-05Z.bak",
    ))));
    assert!(msg.contains("default settings"));
    assert!(msg.contains("/cfg/config.json.2026-06-10T14-23-05Z.bak"));
}

#[skuld::test]
fn message_without_backup_says_saving_is_disabled_and_names_the_original() {
    let msg = recovery_dialog_message(&recovery(Err(std::io::Error::other("denied"))));
    assert!(msg.contains("default settings"));
    assert!(msg.contains("disabled"));
    assert!(msg.contains("/cfg/config.json"));
    // The raw error text stays in gui.log, not the dialog.
    assert!(!msg.contains("denied"));
    assert!(!msg.contains("boom"));
}
