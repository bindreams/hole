use std::path::Path;

use super::*;

// Windows msiexec arg construction ====================================================================================

#[cfg(target_os = "windows")]
#[skuld::test]
fn msiexec_args_quiet() {
    let path = Path::new(r"C:\tmp\hole.msi");
    let args = msiexec_args(path, true);
    assert_eq!(
        args,
        [
            r"/i",
            r"C:\tmp\hole.msi",
            "/quiet",
            "/norestart",
            "/L*v",
            r"C:\tmp\hole.msi.log"
        ]
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn msiexec_args_interactive() {
    let path = Path::new(r"C:\tmp\hole.msi");
    let args = msiexec_args(path, false);
    assert_eq!(args, [r"/i", r"C:\tmp\hole.msi", "/L*v", r"C:\tmp\hole.msi.log"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn msiexec_argv_targets_system32_msiexec() {
    let argv = msiexec_argv(Path::new(r"C:\tmp\hole.msi"), false);
    assert!(
        argv[0].to_ascii_lowercase().ends_with(r"\system32\msiexec.exe"),
        "{argv:?}"
    );
    assert_eq!(&argv[1..], [r"/i", r"C:\tmp\hole.msi", "/L*v", r"C:\tmp\hole.msi.log"]);

    let quiet = msiexec_argv(Path::new(r"C:\tmp\hole.msi"), true);
    assert_eq!(
        &quiet[1..],
        [
            r"/i",
            r"C:\tmp\hole.msi",
            "/quiet",
            "/norestart",
            "/L*v",
            r"C:\tmp\hole.msi.log"
        ]
    );
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
