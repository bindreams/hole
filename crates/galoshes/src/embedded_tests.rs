use crate::embedded::{runtime_dir, EmbeddedBinary};

const TEST_DATA: &[u8] = b"#!/bin/sh\necho hello\n";

#[skuld::test]
fn runtime_dir_is_public() {
    // Compile-time guard: runtime_dir is pub so main() can source the crash
    // marker dir. A regression to private fails to compile here.
    let _f: fn() -> anyhow::Result<std::path::PathBuf> = runtime_dir;
}

fn test_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[skuld::test]
fn cold_start_extracts_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: test_sha256(TEST_DATA),
    };
    let verified = binary.prepare_in(dir.path()).unwrap();
    assert!(verified.fs_path().exists());
}

#[skuld::test]
fn warm_start_reuses_existing() {
    let dir = tempfile::tempdir().unwrap();
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: test_sha256(TEST_DATA),
    };
    let v1 = binary.prepare_in(dir.path()).unwrap();
    let fs_path1 = v1.fs_path().to_path_buf();
    drop(v1);
    let v2 = binary.prepare_in(dir.path()).unwrap();
    assert_eq!(v2.fs_path(), fs_path1);
}

#[skuld::test]
fn hash_mismatch_re_extracts() {
    let dir = tempfile::tempdir().unwrap();
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: test_sha256(TEST_DATA),
    };
    let v1 = binary.prepare_in(dir.path()).unwrap();
    let fs_path = v1.fs_path().to_path_buf();
    drop(v1);
    // Make writable before tampering (file was extracted with 0o500 on Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fs_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(&fs_path, b"tampered content").unwrap();
    let v2 = binary.prepare_in(dir.path()).unwrap();
    let content = std::fs::read(v2.fs_path()).unwrap();
    assert_eq!(content, TEST_DATA);
}

#[skuld::test]
fn wrong_embedded_hash_fails() {
    let dir = tempfile::tempdir().unwrap();
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: [0u8; 32],
    };
    let result = binary.prepare_in(dir.path());
    assert!(result.is_err());
}

// Resolution ==========================================================================================================

#[cfg(target_os = "linux")]
#[skuld::test]
fn resolve_linux_prefers_xdg_runtime_dir() {
    use crate::embedded::resolve;
    let path = resolve(Some("/run/user/1000"), Some("/home/x")).unwrap();
    assert_eq!(path, std::path::PathBuf::from("/run/user/1000/galoshes"));
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn resolve_linux_falls_back_to_home_cache() {
    use crate::embedded::resolve;
    let path = resolve(None, Some("/home/x")).unwrap();
    assert_eq!(path, std::path::PathBuf::from("/home/x/.cache/galoshes"));
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn resolve_linux_bails_when_nothing_resolves() {
    use crate::embedded::resolve;
    let err = resolve(None, None).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("XDG_RUNTIME_DIR"),
        "error should name XDG_RUNTIME_DIR: {msg}"
    );
    assert!(msg.contains("HOME"), "error should name HOME: {msg}");
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn resolve_macos_prefers_xdg_runtime_dir() {
    use crate::embedded::resolve;
    let path = resolve(Some("/some/runtime"), Some("/Users/x")).unwrap();
    assert_eq!(path, std::path::PathBuf::from("/some/runtime/galoshes"));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn resolve_macos_falls_back_to_library_caches() {
    use crate::embedded::resolve;
    let path = resolve(None, Some("/Users/x")).unwrap();
    assert_eq!(path, std::path::PathBuf::from("/Users/x/Library/Caches/galoshes"));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn resolve_macos_bails_when_nothing_resolves() {
    use crate::embedded::resolve;
    let err = resolve(None, None).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("XDG_RUNTIME_DIR"),
        "error should name XDG_RUNTIME_DIR: {msg}"
    );
    assert!(msg.contains("HOME"), "error should name HOME: {msg}");
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn resolve_windows_prefers_xdg_runtime_dir() {
    use crate::embedded::resolve;
    let path = resolve(Some(r"C:\run"), Some(r"C:\Users\x\AppData\Local")).unwrap();
    assert_eq!(path, std::path::PathBuf::from(r"C:\run\galoshes"));
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn resolve_windows_falls_back_to_localappdata() {
    use crate::embedded::resolve;
    let path = resolve(None, Some(r"C:\Users\x\AppData\Local")).unwrap();
    assert_eq!(path, std::path::PathBuf::from(r"C:\Users\x\AppData\Local\galoshes"));
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn resolve_windows_bails_when_nothing_resolves() {
    use crate::embedded::resolve;
    let err = resolve(None, None).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("XDG_RUNTIME_DIR"),
        "error should name XDG_RUNTIME_DIR: {msg}"
    );
    assert!(msg.contains("LOCALAPPDATA"), "error should name LOCALAPPDATA: {msg}");
}

// Noexec predicate ====================================================================================================

#[cfg(target_os = "linux")]
#[skuld::test]
fn check_noexec_linux_passes_on_zero_flag() {
    assert!(!crate::embedded::check_noexec_linux(0));
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn check_noexec_linux_detects_st_noexec() {
    assert!(crate::embedded::check_noexec_linux(libc::ST_NOEXEC));
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn check_noexec_linux_ignores_st_rdonly() {
    // ST_RDONLY set, ST_NOEXEC clear → not noexec
    assert!(!crate::embedded::check_noexec_linux(libc::ST_RDONLY));
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn check_noexec_linux_detects_st_noexec_combined_with_other_flags() {
    assert!(crate::embedded::check_noexec_linux(libc::ST_NOEXEC | libc::ST_RDONLY));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn check_noexec_macos_passes_on_zero_flag() {
    assert!(!crate::embedded::check_noexec_macos(0));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn check_noexec_macos_detects_mnt_noexec() {
    assert!(crate::embedded::check_noexec_macos(libc::MNT_NOEXEC as u32));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn check_noexec_macos_ignores_mnt_rdonly() {
    assert!(!crate::embedded::check_noexec_macos(libc::MNT_RDONLY as u32));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn check_noexec_macos_detects_mnt_noexec_combined_with_other_flags() {
    let combined = (libc::MNT_NOEXEC as u32) | (libc::MNT_RDONLY as u32);
    assert!(crate::embedded::check_noexec_macos(combined));
}
