use super::*;
use hole_common::config::ConfigError;
use std::path::PathBuf;
use util::dir::Refusal;

fn path() -> PathBuf {
    PathBuf::from("/cfg/config.json")
}

fn unreadable() -> ConfigError {
    ConfigError::Read {
        source: std::io::Error::other("boom"),
    }
}

#[skuld::test]
fn message_with_backup_names_the_backup_file() {
    let msg = recovery_dialog_message(&ConfigRecovery::Quarantined {
        path: path(),
        error: unreadable(),
        backup: PathBuf::from("/cfg/config.json.unreadable.bak"),
    });
    assert!(msg.contains("default settings"));
    assert!(msg.contains("config.json.unreadable.bak"));
}

#[skuld::test]
fn message_without_backup_says_saving_is_disabled_and_names_the_original() {
    let msg = recovery_dialog_message(&ConfigRecovery::QuarantineFailed {
        path: path(),
        error: unreadable(),
        failure: std::io::Error::other("denied"),
    });
    assert!(msg.contains("default settings"));
    assert!(msg.contains("disabled"));
    assert!(msg.contains("/cfg/config.json"));
    // The underlying error text stays in gui.log, never in the dialog.
    assert!(!msg.contains("denied"));
    assert!(!msg.contains("boom"));
}

#[skuld::test]
fn message_for_a_folder_that_was_not_opened_names_the_folder_and_does_not_send_the_user_to_a_file() {
    let msg = recovery_dialog_message(&ConfigRecovery::FolderNotOpened {
        path: path(),
        failure: std::io::Error::other("denied"),
    });
    assert!(msg.contains("default settings"));
    assert!(msg.contains("disabled"));
    assert!(msg.contains("folder"));
    assert!(msg.contains("/cfg"));
    assert!(!msg.contains("config.json"), "there is no file to move: {msg}");
    assert!(!msg.contains("denied"));
}

#[skuld::test]
fn message_for_a_newer_file_says_it_was_left_and_saving_is_disabled() {
    let msg = recovery_dialog_message(&ConfigRecovery::LeftInPlace {
        path: path(),
        found: Some(2),
    });
    assert!(msg.contains("newer version"));
    assert!(msg.contains("untouched"));
    assert!(msg.contains("disabled"));
    assert!(msg.contains("/cfg/config.json"));
    assert!(!msg.contains("backed up"));
}

fn refused(refusal: Refusal) -> String {
    recovery_dialog_message(&ConfigRecovery::Refused { path: path(), refusal })
}

#[skuld::test]
fn message_for_a_refused_file_says_what_was_found_that_it_was_left_and_how_to_get_the_settings_back() {
    // What the way back is depends on what was found: a link or another account's file is refused only to a process
    // run as administrator, so starting Hole normally is the way back; what is neither a link nor a file is there for
    // every principal, so it has to be moved or deleted.
    for (refusal, found, way_back) in [
        (Refusal::Symlink, "a link", "start it normally"),
        (Refusal::ForeignFile, "another account", "start it normally"),
        (Refusal::NotRegular, "not a regular file", "move or delete it"),
    ] {
        let msg = refused(refusal);
        assert!(msg.contains("default settings"), "{msg}");
        assert!(msg.contains(found), "{refusal:?}: {msg}");
        assert!(msg.contains("untouched"), "{msg}");
        assert!(msg.contains("disabled"), "{msg}");
        assert!(msg.contains(way_back), "{refusal:?}: {msg}");
        assert!(msg.contains("/cfg/config.json"), "{msg}");
        assert!(!msg.contains("backed up"), "{msg}");
    }
}

/// The order of the other dialogs: what happened, what it means for the settings, the way back, the path last. What
/// is at the name may be a folder, so no sentence calls it a file but the ones that know it is one.
#[skuld::test]
fn a_refused_dialog_says_what_was_found_then_the_status_then_the_way_back_and_ends_with_the_path() {
    for (refusal, found, way_back) in [
        (Refusal::Symlink, "a link", "start it normally"),
        (Refusal::ForeignFile, "another account", "start it normally"),
        (Refusal::NotRegular, "not a regular file", "move or delete it"),
    ] {
        let msg = refused(refusal);
        let at = |needle: &str| {
            msg.find(needle)
                .unwrap_or_else(|| panic!("{refusal:?}: no {needle:?} in {msg}"))
        };

        assert!(at(found) < at("disabled"), "{refusal:?}: {msg}");
        assert!(at("disabled") < at(way_back), "{refusal:?}: {msg}");
        assert!(msg.ends_with("/cfg/config.json"), "{refusal:?}: {msg}");
        assert!(!msg.contains("The file was left"), "{refusal:?}: {msg}");
    }
}

#[skuld::test]
fn only_a_refusal_a_normal_start_cures_tells_the_user_to_start_normally() {
    let not_a_file = refused(Refusal::NotRegular);

    assert!(!not_a_file.contains("start it normally"), "{not_a_file}");
    assert!(!not_a_file.contains("administrator"), "{not_a_file}");
    assert!(!not_a_file.contains("sudo"), "{not_a_file}");
    for refusal in [Refusal::Symlink, Refusal::ForeignFile] {
        let msg = refused(refusal);
        assert!(msg.contains("as administrator"), "{msg}");
        assert!(msg.contains("sudo"), "{msg}");
    }
}

/// The text must read as sentences: a continuation inside a string literal that keeps the next line's indentation puts
/// a run of spaces in the middle of the dialog.
#[skuld::test]
fn no_message_has_a_run_of_spaces_or_a_line_broken_mid_sentence() {
    let messages = [
        recovery_dialog_message(&ConfigRecovery::Quarantined {
            path: path(),
            error: unreadable(),
            backup: PathBuf::from("/cfg/b"),
        }),
        recovery_dialog_message(&ConfigRecovery::QuarantineFailed {
            path: path(),
            error: unreadable(),
            failure: std::io::Error::other("x"),
        }),
        recovery_dialog_message(&ConfigRecovery::LeftInPlace {
            path: path(),
            found: None,
        }),
        recovery_dialog_message(&ConfigRecovery::FolderNotOpened {
            path: path(),
            failure: std::io::Error::other("x"),
        }),
        refused(Refusal::Symlink),
        refused(Refusal::NotRegular),
        refused(Refusal::ForeignFile),
    ];
    for msg in messages {
        assert!(!msg.contains("  "), "{msg:?}");
        for line in msg.lines().filter(|l| !l.is_empty()) {
            assert!(!line.starts_with(' '), "{msg:?}");
        }
    }
}
