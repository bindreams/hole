#![allow(clippy::disallowed_methods)] // attended test: bare-name host tools
use super::*;
use crate::config::ServerEntry;
use skuld::temp_dir;
use std::path::{Path, PathBuf};

/// Where a recovery put the file; panics if it was not quarantined.
fn quarantined(recovery: ConfigRecovery) -> PathBuf {
    match recovery {
        ConfigRecovery::Quarantined { backup, .. } => backup,
        other => panic!("expected a quarantine, got {other:?}"),
    }
}

/// The error a quarantine or a failed quarantine carries.
fn error_of(recovery: &ConfigRecovery) -> &ConfigError {
    match recovery {
        ConfigRecovery::Quarantined { error, .. } | ConfigRecovery::QuarantineFailed { error, .. } => error,
        other => panic!("expected an unreadable file, got {other:?}"),
    }
}

#[skuld::test]
fn load_valid_file_returns_config_and_no_recovery(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let original = AppConfig {
        servers: vec![ServerEntry::default_placeholder()],
        local_port: 5555,
        ..Default::default()
    };
    ConfigStore::load(dir, Principal::User).0.save(&original).unwrap();

    let (store, config, recovery) = ConfigStore::load(dir, Principal::User);

    assert_eq!(config, original);
    assert!(recovery.is_none());
    assert_eq!(store.path(), path);
    // No stray backup or temp files.
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1);
}

#[skuld::test]
fn load_missing_file_returns_defaults_and_no_recovery(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");

    let (_store, config, recovery) = ConfigStore::load(dir, Principal::User);

    assert_eq!(config, AppConfig::default());
    assert!(recovery.is_none());
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0);
}

#[skuld::test]
fn load_missing_directory_returns_defaults_and_makes_nothing(#[fixture(temp_dir)] dir: &Path) {
    let missing = dir.join("hole");

    let (_store, config, recovery) = ConfigStore::load(&missing, Principal::User);

    assert_eq!(config, AppConfig::default());
    assert!(recovery.is_none());
    assert!(!missing.exists());
}

#[skuld::test]
fn save_roundtrips_through_store(#[fixture(temp_dir)] dir: &Path) {
    let (store, mut config, _) = ConfigStore::load(dir, Principal::User);

    config.local_port = 6666;
    store.save(&config).unwrap();

    let (_, reloaded, recovery) = ConfigStore::load(dir, Principal::User);
    assert_eq!(reloaded, config);
    assert!(recovery.is_none());
}

const GARBAGE: &str = "not json at all {{{";

#[skuld::test]
fn corrupt_json_is_quarantined_to_the_types_backup_name(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    std::fs::write(&path, GARBAGE).unwrap();

    let (_store, config, recovery) = ConfigStore::load(dir, Principal::User);

    assert_eq!(config, AppConfig::default());
    let recovery = recovery.expect("corrupt file must produce a recovery");
    assert!(matches!(error_of(&recovery), ConfigError::Parse { .. }));
    assert_eq!(recovery.path(), path);

    let bak = quarantined(recovery);
    assert_eq!(bak, dir.join("config.json.unreadable.bak"));
    assert!(!path.exists(), "original must be moved away");
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), GARBAGE);
}

/// An empty file is not valid JSON — it must be quarantined, not silently
/// replaced (truncation is the classic crash-mid-save corruption shape).
#[skuld::test]
fn empty_file_is_quarantined(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    std::fs::write(&path, "").unwrap();

    let (_store, config, recovery) = ConfigStore::load(dir, Principal::User);

    assert_eq!(config, AppConfig::default());
    let recovery = recovery.expect("empty file must produce a recovery");
    assert!(matches!(error_of(&recovery), ConfigError::Parse { .. }));
    assert!(matches!(recovery, ConfigRecovery::Quarantined { .. }));
    assert!(!path.exists());
}

#[skuld::test]
fn an_older_backup_is_never_replaced(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    std::fs::write(&path, GARBAGE).unwrap();
    let occupied = dir.join("config.json.unreadable.bak");
    std::fs::write(&occupied, "older backup").unwrap();

    let (_store, _config, recovery) = ConfigStore::load(dir, Principal::User);

    let bak = quarantined(recovery.unwrap());
    assert_eq!(bak, dir.join("config.json.unreadable.2.bak"));
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), GARBAGE);
    assert_eq!(std::fs::read_to_string(&occupied).unwrap(), "older backup");
}

#[skuld::test]
fn save_works_after_successful_quarantine(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    std::fs::write(&path, GARBAGE).unwrap();

    let (store, config, _recovery) = ConfigStore::load(dir, Principal::User);
    store.save(&config).unwrap();

    let (_, reloaded, recovery) = ConfigStore::load(dir, Principal::User);
    assert_eq!(reloaded, config);
    assert!(recovery.is_none());
}

/// rename(2) preserves the inode, so the 0600 mode a save sets must survive
/// quarantine — the backup holds plaintext passwords.
#[cfg(unix)]
#[skuld::test]
fn quarantine_preserves_file_permissions(#[fixture(temp_dir)] dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("config.json");
    ConfigStore::load(dir, Principal::User)
        .0
        .save(&AppConfig::default())
        .unwrap(); // 0600
    std::fs::write(&path, GARBAGE).unwrap(); // truncating write keeps mode

    let (_store, _config, recovery) = ConfigStore::load(dir, Principal::User);

    let bak = quarantined(recovery.unwrap());
    let mode = std::fs::metadata(&bak).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

/// Restores a directory's permissions on drop, so a failing assert can't
/// leave the temp dir undeletable.
#[cfg(unix)]
struct RestorePerms<'a> {
    path: &'a Path,
    mode: u32,
}

#[cfg(unix)]
impl Drop for RestorePerms<'_> {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(self.path, std::fs::Permissions::from_mode(self.mode));
    }
}

/// An unreadable (not missing) file is a Read error and must be quarantined
/// the same way — rename does not require read permission.
/// CI runs as a non-root user, so 0o000 genuinely denies; under root the
/// read would succeed and flip the error branch, failing this test loudly.
#[cfg(unix)]
#[skuld::test]
fn unreadable_file_is_quarantined_via_rename(#[fixture(temp_dir)] dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("config.json");
    std::fs::write(&path, GARBAGE).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

    let (store, config, recovery) = ConfigStore::load(dir, Principal::User);

    assert_eq!(config, AppConfig::default());
    let recovery = recovery.expect("unreadable file must produce a recovery");
    assert!(matches!(error_of(&recovery), ConfigError::Read { .. }));
    let bak = quarantined(recovery);
    assert!(!path.exists());

    // Quarantine preserved the mode; relax it to inspect the contents.
    std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), GARBAGE);

    // Saving is allowed — the backup succeeded.
    store.save(&AppConfig::default()).unwrap();
}

/// macOS: `chflags uchg` makes rename/unlink of the file fail: nothing can move it aside.
#[cfg(target_os = "macos")]
#[skuld::test]
fn a_file_that_cannot_be_renamed_blocks_saving_and_stays(#[fixture(temp_dir)] dir: &Path) {
    struct ClearUchg<'a>(&'a Path);
    impl Drop for ClearUchg<'_> {
        fn drop(&mut self) {
            let _ = std::process::Command::new("/usr/bin/chflags")
                .arg("nouchg")
                .arg(self.0)
                .status();
        }
    }

    let path = dir.join("config.json");
    std::fs::write(&path, GARBAGE).unwrap();
    let status = std::process::Command::new("/usr/bin/chflags")
        .arg("uchg")
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success(), "chflags uchg failed");
    let _guard = ClearUchg(&path);

    let (store, config, recovery) = ConfigStore::load(dir, Principal::User);

    assert_eq!(config, AppConfig::default());
    assert!(matches!(recovery, Some(ConfigRecovery::QuarantineFailed { .. })));
    assert!(matches!(store.save(&config), Err(ConfigError::SaveBlocked)));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), GARBAGE);
}

/// Windows shape: a file held open without FILE_SHARE_DELETE refuses the rename.
#[cfg(windows)]
#[skuld::test]
fn a_file_that_cannot_be_renamed_blocks_saving_and_stays(#[fixture(temp_dir)] dir: &Path) {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;

    let path = dir.join("config.json");
    std::fs::write(&path, GARBAGE).unwrap();
    // Reads allowed, rename and delete refused (no FILE_SHARE_DELETE).
    let _holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&path)
        .unwrap();

    let (store, config, recovery) = ConfigStore::load(dir, Principal::User);

    assert_eq!(config, AppConfig::default());
    assert!(
        matches!(recovery, Some(ConfigRecovery::QuarantineFailed { .. })),
        "{recovery:?}"
    );
    assert!(matches!(store.save(&config), Err(ConfigError::SaveBlocked)));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), GARBAGE);
}

/// When the directory refuses the move, nothing can preserve the data — so saves must be blocked for the session.
/// (Non-root only, like `unreadable_file_is_quarantined_via_rename`.)
#[cfg(unix)]
#[skuld::test]
fn backup_failure_blocks_saving(#[fixture(temp_dir)] dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let subdir = dir.join("conf");
    std::fs::create_dir(&subdir).unwrap();
    let path = subdir.join("config.json");
    std::fs::write(&path, GARBAGE).unwrap();
    std::fs::set_permissions(&subdir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let guard = RestorePerms {
        path: &subdir,
        mode: 0o755,
    };

    let (store, config, recovery) = ConfigStore::load(&subdir, Principal::User);

    assert_eq!(config, AppConfig::default());
    assert!(
        matches!(recovery, Some(ConfigRecovery::QuarantineFailed { .. })),
        "backup cannot succeed in a read-only dir"
    );

    assert!(matches!(store.save(&config), Err(ConfigError::SaveBlocked)));
    drop(guard);
    // The corrupt original is untouched — neither quarantined nor overwritten.
    assert_eq!(std::fs::read_to_string(&path).unwrap(), GARBAGE);
}

/// A folder that cannot be opened (a file where a directory belongs) reads nothing: defaults, saving blocked, and no
/// move of anything by a path.
#[skuld::test]
fn a_folder_that_cannot_be_opened_blocks_saving(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("not-a-folder");
    std::fs::write(&file, b"x").unwrap();

    let (store, config, recovery) = ConfigStore::load(&file.join("hole"), Principal::User);

    assert_eq!(config, AppConfig::default());
    assert!(
        matches!(recovery, Some(ConfigRecovery::FolderNotOpened { .. })),
        "{recovery:?}"
    );
    assert!(matches!(store.save(&config), Err(ConfigError::SaveBlocked)));
    assert_eq!(std::fs::read(&file).unwrap(), b"x");
}

// The user's own file =================================================================================================

/// A dotfiles tool keeps `config.json` as a link: it is read through, and a save replaces the link, never the file it
/// points at.
#[skuld::test]
fn a_symlink_at_the_name_is_read_through_and_the_save_replaces_the_link(#[fixture(temp_dir)] dir: &Path) {
    let away = dir.join("dotfiles");
    std::fs::create_dir(&away).unwrap();
    let target = away.join("hole.json");
    let content = r#"{"version": 1, "local_port": 5555}"#;
    std::fs::write(&target, content).unwrap();
    let state = dir.join("state");
    std::fs::create_dir(&state).unwrap();
    util::dir::testing::file_link(&target, &state.join("config.json"));

    let (store, mut config, recovery) = ConfigStore::load(&state, Principal::User);

    assert!(recovery.is_none(), "{recovery:?}");
    assert_eq!(config.local_port, 5555);
    config.local_port = 6666;
    store.save(&config).unwrap();
    assert!(!std::fs::symlink_metadata(state.join("config.json"))
        .unwrap()
        .is_symlink());
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        content,
        "the target keeps its content"
    );
    assert_eq!(ConfigStore::load(&state, Principal::User).1.local_port, 6666);
}

/// A first run as an administrator makes the folder the system's; the user's own GUI still owns its file.
#[skuld::test]
fn a_file_a_user_owns_in_a_folder_the_system_owns_is_loaded(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    std::fs::write(&path, r#"{"version": 1, "local_port": 5555}"#).unwrap();
    util::dir::testing::own(&path);

    let (store, config, recovery) = ConfigStore::load(dir, Principal::User);

    assert!(recovery.is_none(), "{recovery:?}");
    assert_eq!(config.local_port, 5555);
    store.save(&config).unwrap();
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1, "nothing was quarantined");
}

/// A profile folder reached through the user's own link into a folder the system owns (a roaming profile redirected
/// to a shared one) is the user's to read and save in.
#[skuld::test]
fn a_config_folder_reached_through_a_users_link_into_a_system_folder_loads_and_saves(#[fixture(temp_dir)] dir: &Path) {
    let scratch = util::dir::testing::SystemScratch::new();
    let link = dir.join("profile");
    util::dir::testing::plant_link(scratch.root(), &link);
    let through = link.join(scratch.name());

    let (store, mut config, recovery) = ConfigStore::load(&through, Principal::User);
    assert!(recovery.is_none(), "{recovery:?}");
    config.local_port = 6666;
    store.save(&config).unwrap();

    assert!(scratch.path().join("config.json").is_file());
    assert_eq!(ConfigStore::load(&through, Principal::User).1.local_port, 6666);
}

/// A privileged process (a GUI run under `sudo`) walks the user's folder as the system: a user's link into a folder the
/// system owns is refused, which is a folder that cannot be opened, and nothing is written below the link.
#[skuld::test]
fn a_privileged_process_does_not_follow_a_users_link_into_a_system_folder(#[fixture(temp_dir)] dir: &Path) {
    let scratch = util::dir::testing::SystemScratch::new();
    let link = dir.join("profile");
    util::dir::testing::plant_link(scratch.root(), &link);

    let (store, config, recovery) = ConfigStore::load(&link, Principal::System);

    let Some(ConfigRecovery::FolderNotOpened { failure, .. }) = recovery else {
        panic!("expected a folder that was not opened, got {recovery:?}");
    };
    assert_eq!(Refusal::from_error(&failure), Some(&Refusal::Symlink), "{failure:?}");
    assert!(matches!(store.save(&config), Err(ConfigError::SaveBlocked)));
    assert!(!scratch.root().join("config.json").exists());
}

// A privileged process and a file its read refuses ====================================================================

/// A privileged process (a GUI run under `sudo`) does not read through a link at the name, and a refusal says nothing
/// about the file's content: it stays where it is, byte for byte, with defaults in memory and saving blocked.
#[skuld::test]
fn a_symlink_at_the_name_is_left_in_place_for_a_privileged_process(#[fixture(temp_dir)] dir: &Path) {
    let away = dir.join("dotfiles");
    std::fs::create_dir(&away).unwrap();
    let target = away.join("hole.json");
    let content = r#"{"version": 1, "local_port": 5555}"#;
    std::fs::write(&target, content).unwrap();
    let state = dir.join("state");
    std::fs::create_dir(&state).unwrap();
    let link = state.join("config.json");
    util::dir::testing::file_link(&target, &link);

    let (store, config, recovery) = ConfigStore::load(&state, Principal::System);

    assert_eq!(config, AppConfig::default());
    let recovery = recovery.expect("a refused read must produce a recovery");
    assert!(
        matches!(
            recovery,
            ConfigRecovery::Refused {
                refusal: Refusal::Symlink,
                ..
            }
        ),
        "{recovery:?}"
    );
    assert_eq!(recovery.path(), link);
    assert!(matches!(store.save(&config), Err(ConfigError::SaveBlocked)));
    assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink(), "the link stays");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), content);
    assert_eq!(
        std::fs::read_dir(&state).unwrap().count(),
        1,
        "nothing is made beside it"
    );
}

/// The first launch as an administrator made the folder the system's; the user's own file in it is not one a
/// privileged reader can vouch for. Stated for any runner: a runner that is a user owns both, and reads it.
#[skuld::test]
fn a_file_a_user_owns_in_a_folder_the_system_owns_is_refused_to_a_privileged_process(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let content = r#"{"version": 1, "local_port": 5555}"#;
    std::fs::write(&path, content).unwrap();
    util::dir::testing::own(&path);

    let (_store, config, recovery) = ConfigStore::load(dir, Principal::System);

    match util::dir::testing::runner_is_the_system() {
        true => {
            assert_eq!(config, AppConfig::default());
            assert!(
                matches!(
                    recovery,
                    Some(ConfigRecovery::Refused {
                        refusal: Refusal::ForeignFile,
                        ..
                    })
                ),
                "{recovery:?}"
            );
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                content,
                "the file is untouched"
            );
            assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1, "no backup is made");
        }
        false => {
            assert!(recovery.is_none(), "{recovery:?}");
            assert_eq!(config.local_port, 5555);
        }
    }
}

// The copy of a borrowed error ========================================================================================

#[skuld::test]
fn the_copy_of_an_error_keeps_its_os_code_and_its_kind() {
    let denied = io::Error::from_raw_os_error(5);
    let plain = io::Error::from(io::ErrorKind::TimedOut);

    assert_eq!(copy_of(&denied).raw_os_error(), Some(5));
    assert_eq!(copy_of(&denied).kind(), denied.kind());
    assert_eq!(copy_of(&plain).kind(), io::ErrorKind::TimedOut);
}

// Versioning ==========================================================================================================

/// What a release before the file was versioned wrote: no `version` key.
const UNVERSIONED: &str = r#"{"local_port": 5555, "future_field": 1}"#;

#[skuld::test]
fn a_file_with_no_version_loads_as_version_1_and_is_stamped_on_the_next_save(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    std::fs::write(&path, UNVERSIONED).unwrap();

    let (store, config, recovery) = ConfigStore::load(dir, Principal::User);

    assert!(recovery.is_none());
    assert_eq!(config.local_port, 5555);
    store.save(&config).unwrap();
    let on_disk: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(on_disk["version"], 1);
    assert_eq!(on_disk["local_port"], 5555);
}

#[skuld::test]
fn a_saved_file_leads_with_its_version(#[fixture(temp_dir)] dir: &Path) {
    let (store, _, _) = ConfigStore::load(dir, Principal::User);
    store.save(&AppConfig::default()).unwrap();

    let text = std::fs::read_to_string(dir.join("config.json")).unwrap();
    let first_key = text.lines().nth(1).unwrap().trim();
    assert!(first_key.starts_with(r#""version": 1"#), "{first_key}");
}

#[skuld::test]
fn a_version_1_file_loads_cleanly(#[fixture(temp_dir)] dir: &Path) {
    std::fs::write(dir.join("config.json"), r#"{"version": 1, "local_port": 5555}"#).unwrap();

    let (_, config, recovery) = ConfigStore::load(dir, Principal::User);

    assert!(recovery.is_none());
    assert_eq!(config.local_port, 5555);
}

/// A file from a newer release is never touched: defaults, saving off, no backup made.
#[skuld::test]
fn a_newer_file_is_left_intact_and_blocks_saving(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let newer = r#"{"version": 2, "local_port": 5555, "servers_v2": []}"#;
    std::fs::write(&path, newer).unwrap();

    let (store, config, recovery) = ConfigStore::load(dir, Principal::User);

    assert_eq!(config, AppConfig::default());
    let recovery = recovery.expect("a newer file must produce a recovery");
    assert!(
        matches!(recovery, ConfigRecovery::LeftInPlace { found: Some(2), .. }),
        "{recovery:?}"
    );
    assert!(matches!(store.save(&config), Err(ConfigError::SaveBlocked)));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), newer);
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1, "nothing is made beside it");
}

#[skuld::test]
fn a_version_too_large_for_u32_is_newer_too(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    std::fs::write(&path, r#"{"version": 18446744073709551616}"#).unwrap();

    let (_, _, recovery) = ConfigStore::load(dir, Principal::User);

    let recovery = recovery.unwrap();
    assert!(
        matches!(recovery, ConfigRecovery::LeftInPlace { found: None, .. }),
        "{recovery:?}"
    );
    assert!(path.exists());
}

/// A file that turns newer after the load (another release wrote it) is refused by the type, not overwritten.
#[skuld::test]
fn a_save_over_a_file_that_became_newer_is_refused(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let (store, config, _) = ConfigStore::load(dir, Principal::User);
    let newer = r#"{"version": 2}"#;
    std::fs::write(&path, newer).unwrap();

    let err = store.save(&config).unwrap_err();

    assert!(matches!(err, ConfigError::Write { .. }), "{err}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), newer);
}

/// A mid-session corrupt file is replaced by the next save, as before (#467's own case is the load-time quarantine).
#[skuld::test]
fn a_save_over_a_file_that_became_corrupt_overwrites_it(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let (store, mut config, _) = ConfigStore::load(dir, Principal::User);
    std::fs::write(&path, GARBAGE).unwrap();

    config.local_port = 6666;
    store.save(&config).unwrap();

    let (_, reloaded, recovery) = ConfigStore::load(dir, Principal::User);
    assert!(recovery.is_none());
    assert_eq!(reloaded.local_port, 6666);
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1, "no backup is made");
}

#[skuld::test]
fn save_creates_missing_directories(#[fixture(temp_dir)] dir: &Path) {
    let nested = dir.join("nested").join("deep");
    let (store, config, recovery) = ConfigStore::load(&nested, Principal::User);
    assert!(recovery.is_none());

    store.save(&config).unwrap();

    assert!(nested.join("config.json").exists());
}

#[skuld::test]
fn save_replaces_the_file_and_leaves_no_temp(#[fixture(temp_dir)] dir: &Path) {
    let (store, _, _) = ConfigStore::load(dir, Principal::User);
    store.save(&AppConfig::default()).unwrap();
    let changed = AppConfig {
        local_port: 7777,
        ..Default::default()
    };
    store.save(&changed).unwrap();

    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1);
    let (_, reloaded, _) = ConfigStore::load(dir, Principal::User);
    assert_eq!(reloaded, changed);
}

// Redaction arming ====================================================================================================

/// The GUI arms **every** entry, not only the selected one: `gui.log` can
/// carry any of them (the auto-test loop walks the whole list) and the
/// support-bundle collector reuses this registry.
#[skuld::test]
fn loading_a_config_arms_every_entry(#[fixture(temp_dir)] dir: &Path) {
    use crate::logging::redact_arm::token_for;

    let path = dir.join("config.json");
    let mut config = AppConfig::default();
    config
        .servers
        .push(entry_with("11111111-0000-4000-8000-000000000000", "203.0.113.7"));
    config
        .servers
        .push(entry_with("22222222-0000-4000-8000-000000000000", "203.0.113.9"));
    std::fs::write(&path, serde_json::to_string(&config).unwrap()).unwrap();

    let (_store, loaded, recovery) = ConfigStore::load(dir, Principal::User);
    assert!(recovery.is_none(), "setup: the config must load cleanly");
    assert_eq!(loaded.servers.len(), 2);

    assert_eq!(
        util::redact::redact_str("203.0.113.7"),
        token_for("11111111-0000-4000-8000-000000000000")
    );
    assert_eq!(
        util::redact::redact_str("203.0.113.9"),
        token_for("22222222-0000-4000-8000-000000000000"),
        "an unselected entry still reaches gui.log"
    );
}

fn entry_with(id: &str, server: &str) -> crate::config::ServerEntry {
    crate::config::ServerEntry {
        id: id.to_string(),
        server: server.into(),
        ..crate::config::ServerEntry::default_placeholder()
    }
}
