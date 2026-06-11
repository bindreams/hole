use super::*;
use crate::config::ServerEntry;
use skuld::temp_dir;
use std::path::Path;
use time::macros::datetime;

const NOW: time::OffsetDateTime = datetime!(2026-06-10 14:23:05 UTC);

// Direct `AppConfig::save` for test setup — sanctioned; see clippy.toml.
#[allow(clippy::disallowed_methods)]
#[skuld::test]
fn load_valid_file_returns_config_and_no_recovery(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let original = AppConfig {
        servers: vec![ServerEntry::default_placeholder()],
        local_port: 5555,
        ..Default::default()
    };
    original.save(&path).unwrap();

    let (store, config, recovery) = ConfigStore::load(path.clone(), NOW);

    assert_eq!(config, original);
    assert!(recovery.is_none());
    assert_eq!(store.path(), path);
    // No stray backup or temp files.
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1);
}

#[skuld::test]
fn load_missing_file_returns_defaults_and_no_recovery(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");

    let (_store, config, recovery) = ConfigStore::load(path.clone(), NOW);

    assert_eq!(config, AppConfig::default());
    assert!(recovery.is_none());
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0);
}

#[skuld::test]
fn save_roundtrips_through_store(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let (store, mut config, _) = ConfigStore::load(path.clone(), NOW);

    config.local_port = 6666;
    store.save(&config).unwrap();

    let (_, reloaded, recovery) = ConfigStore::load(path, NOW);
    assert_eq!(reloaded, config);
    assert!(recovery.is_none());
}

const GARBAGE: &str = "not json at all {{{";

#[skuld::test]
fn corrupt_json_is_quarantined_to_timestamped_bak(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    std::fs::write(&path, GARBAGE).unwrap();

    let (_store, config, recovery) = ConfigStore::load(path.clone(), NOW);

    assert_eq!(config, AppConfig::default());
    let recovery = recovery.expect("corrupt file must produce a recovery");
    assert!(matches!(recovery.error, ConfigError::Parse { .. }));
    assert_eq!(recovery.path, path);

    let bak = recovery.backup.expect("backup must succeed");
    assert_eq!(bak, dir.join("config.json.2026-06-10T14-23-05Z.bak"));
    assert!(!path.exists(), "original must be moved away");
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), GARBAGE);
}

/// An empty file is not valid JSON — it must be quarantined, not silently
/// replaced (truncation is the classic crash-mid-save corruption shape).
#[skuld::test]
fn empty_file_is_quarantined(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    std::fs::write(&path, "").unwrap();

    let (_store, config, recovery) = ConfigStore::load(path.clone(), NOW);

    assert_eq!(config, AppConfig::default());
    let recovery = recovery.expect("empty file must produce a recovery");
    assert!(matches!(recovery.error, ConfigError::Parse { .. }));
    assert!(recovery.backup.is_ok());
    assert!(!path.exists());
}

#[skuld::test]
fn backup_name_collision_appends_counter(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    std::fs::write(&path, GARBAGE).unwrap();
    let occupied = dir.join("config.json.2026-06-10T14-23-05Z.bak");
    std::fs::write(&occupied, "older backup").unwrap();

    let (_store, _config, recovery) = ConfigStore::load(path.clone(), NOW);

    let bak = recovery.unwrap().backup.unwrap();
    assert_eq!(bak, dir.join("config.json.2026-06-10T14-23-05Z-2.bak"));
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), GARBAGE);
    assert_eq!(std::fs::read_to_string(&occupied).unwrap(), "older backup");
}

#[skuld::test]
fn save_works_after_successful_quarantine(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    std::fs::write(&path, GARBAGE).unwrap();

    let (store, config, _recovery) = ConfigStore::load(path.clone(), NOW);
    store.save(&config).unwrap();

    let (_, reloaded, recovery) = ConfigStore::load(path, NOW);
    assert_eq!(reloaded, config);
    assert!(recovery.is_none());
}

/// rename(2) preserves the inode, so the 0600 mode `save()` sets on macOS
/// must survive quarantine — the backup holds plaintext passwords.
// Direct `AppConfig::save` for test setup — sanctioned; see clippy.toml.
#[allow(clippy::disallowed_methods)]
#[cfg(unix)]
#[skuld::test]
fn quarantine_preserves_file_permissions(#[fixture(temp_dir)] dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("config.json");
    AppConfig::default().save(&path).unwrap(); // 0600 on macOS
    std::fs::write(&path, GARBAGE).unwrap(); // truncating write keeps mode

    let (_store, _config, recovery) = ConfigStore::load(path, NOW);

    let bak = recovery.unwrap().backup.unwrap();
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

    let (store, config, recovery) = ConfigStore::load(path.clone(), NOW);

    assert_eq!(config, AppConfig::default());
    let recovery = recovery.expect("unreadable file must produce a recovery");
    assert!(matches!(recovery.error, ConfigError::Read { .. }));
    let bak = recovery.backup.expect("rename does not need read permission");
    assert!(!path.exists());

    // Quarantine preserved the mode; relax it to inspect the contents.
    std::fs::set_permissions(&bak, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), GARBAGE);

    // Saving is allowed — the backup succeeded.
    store.save(&AppConfig::default()).unwrap();
}

/// `chflags uchg` makes rename/unlink of the file fail while still allowing
/// new sibling files — exactly the "rename refused, copy fallback" shape.
#[cfg(target_os = "macos")]
#[skuld::test]
fn rename_refused_falls_back_to_copying_contents(#[fixture(temp_dir)] dir: &Path) {
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

    let (store, _config, recovery) = ConfigStore::load(path.clone(), NOW);

    let recovery = recovery.unwrap();
    let bak = recovery.backup.expect("copy fallback must succeed");
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), GARBAGE);
    // remove_file on a uchg file fails; the original stays behind (re-quarantined
    // on next start — safe, the contents are already backed up).
    assert!(path.exists());

    // Backup succeeded → the store allows saving; the OS then refuses the
    // atomic rename onto the uchg file, deterministically (EPERM → Write).
    assert!(matches!(
        store.save(&AppConfig::default()),
        Err(ConfigError::Write { .. })
    ));
}

/// Windows shape of the same fallback: a file held open without
/// FILE_SHARE_DELETE refuses rename/delete but allows new siblings.
#[cfg(windows)]
#[skuld::test]
fn rename_refused_falls_back_to_copying_contents(#[fixture(temp_dir)] dir: &Path) {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_SHARE_READ: u32 = 0x1;

    let path = dir.join("config.json");
    std::fs::write(&path, GARBAGE).unwrap();
    // Hold the file open for the duration of load: reads allowed, rename and
    // delete refused (no FILE_SHARE_DELETE), sibling create_new allowed.
    let _holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&path)
        .unwrap();

    let (_store, config, recovery) = ConfigStore::load(path.clone(), NOW);

    assert_eq!(config, AppConfig::default());
    let recovery = recovery.unwrap();
    let bak = recovery.backup.expect("copy fallback must succeed");
    assert_eq!(std::fs::read_to_string(&bak).unwrap(), GARBAGE);
    // remove_file is refused while the holder is open; the original stays
    // behind (re-quarantined on next start — safe, contents already backed up).
    assert!(path.exists());
}

/// When the directory refuses both rename and new files, nothing can preserve
/// the data — so saves must be blocked for the session.
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

    let (store, config, recovery) = ConfigStore::load(path.clone(), NOW);

    assert_eq!(config, AppConfig::default());
    let recovery = recovery.unwrap();
    recovery.backup.expect_err("backup cannot succeed in a read-only dir");

    assert!(matches!(store.save(&config), Err(ConfigError::SaveBlocked)));
    drop(guard);
    // The corrupt original is untouched — neither quarantined nor overwritten.
    assert_eq!(std::fs::read_to_string(&path).unwrap(), GARBAGE);
}
