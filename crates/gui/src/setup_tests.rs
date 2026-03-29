use super::*;

// CommandLineToArgvW roundtrip ========================================================================================

// The `build_cmdline` function has a `#[debug_ensures]` contract that roundtrips through the
// real `CommandLineToArgvW` API on every call. These tests exercise it with various edge cases.

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_simple_args() {
    build_cmdline(&["daemon", "install"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_space() {
    build_cmdline(&["hello world"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_tab() {
    build_cmdline(&["foo\tbar"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_embedded_quotes() {
    build_cmdline(&[r#"say "hi""#]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_trailing_backslash_with_spaces() {
    build_cmdline(&[r"C:\path to\dir\"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_backslash_before_quote() {
    build_cmdline(&[r#"a\"b"#]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_empty_string() {
    build_cmdline(&[""]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_realistic_msi_path() {
    build_cmdline(&[r"C:\Users\John Doe\AppData\Local\Temp\hole-update\hole.msi"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_path_no_spaces() {
    build_cmdline(&[r"C:\tmp\hole.msi"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_trailing_backslash_no_spaces() {
    build_cmdline(&[r"C:\tmp\"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_mixed_realistic() {
    build_cmdline(&["/i", r"C:\Users\John Doe\tmp\hole.msi", "/quiet", "/norestart"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_whitespace_only() {
    build_cmdline(&[" "]);
    build_cmdline(&["\t"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_newline() {
    build_cmdline(&["foo\nbar"]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_multiple_backslashes_before_quote() {
    build_cmdline(&[r#"a\\\\"b"#]);
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_multiple_empty_args() {
    build_cmdline(&["", ""]);
}

// Status detection ====================================================================================================

#[skuld::test]
fn daemon_install_status_returns_a_value() {
    // On a dev machine the daemon is typically not installed,
    // but we just verify the function runs without panicking.
    let status = daemon_install_status();
    // Should be one of the three variants
    assert!(matches!(
        status,
        DaemonInstallStatus::Running | DaemonInstallStatus::Installed | DaemonInstallStatus::NotInstalled
    ));
}

#[skuld::test]
fn daemon_binary_path_resolves() {
    let path = daemon_binary_path().expect("should resolve current exe");
    assert!(path.exists(), "resolved path should exist: {path:?}");
}
