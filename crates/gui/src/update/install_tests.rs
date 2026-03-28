use std::path::Path;

use super::*;

// Windows msiexec arg construction ====================================================================================

#[cfg(target_os = "windows")]
#[skuld::test]
fn msiexec_args_quiet() {
    let path = Path::new(r"C:\tmp\hole.msi");
    let args = msiexec_args(path, true);
    assert_eq!(args[0], "/i");
    assert_eq!(args[1], r"C:\tmp\hole.msi");
    assert!(args.contains(&"/quiet".to_string()));
    assert!(args.contains(&"/norestart".to_string()));
    // Should have a log flag
    assert!(args.iter().any(|a| a.starts_with("/L*v")));
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn msiexec_args_interactive() {
    let path = Path::new(r"C:\tmp\hole.msi");
    let args = msiexec_args(path, false);
    assert_eq!(args[0], "/i");
    assert_eq!(args[1], r"C:\tmp\hole.msi");
    assert!(!args.contains(&"/quiet".to_string()));
}

// macOS hdiutil arg construction ======================================================================================

#[cfg(target_os = "macos")]
#[skuld::test]
fn hdiutil_attach_args_correct() {
    let dmg = Path::new("/tmp/hole.dmg");
    let mount = Path::new("/tmp/hole-mount");
    let args = hdiutil_attach_args(dmg, mount);
    assert!(args.contains(&"attach".to_string()));
    assert!(args.contains(&"-nobrowse".to_string()));
    assert!(args.contains(&"-quiet".to_string()));
    assert!(args.contains(&"-mountpoint".to_string()));
}
