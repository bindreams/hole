use super::*;

// CommandLineToArgvW roundtrip ========================================================================================

// The `build_cmdline` function has a `#[debug_ensures]` contract that roundtrips through the
// real `CommandLineToArgvW` API on every call. These tests exercise it with various edge cases.

#[cfg(target_os = "windows")]
#[skuld::test]
fn build_cmdline_simple_args() {
    build_cmdline(&["bridge", "install"]);
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
fn bridge_install_status_returns_a_value() {
    // On a dev machine the bridge is typically not installed,
    // but we just verify the function runs without panicking.
    let status = bridge_install_status();
    // Should be one of the three variants
    assert!(matches!(
        status,
        BridgeInstallStatus::Running | BridgeInstallStatus::Installed | BridgeInstallStatus::NotInstalled
    ));
}

#[skuld::test]
fn bridge_binary_path_resolves() {
    let path = bridge_binary_path().expect("should resolve current exe");
    assert!(path.exists(), "resolved path should exist: {path:?}");
}

// truncate_for_dialog =================================================================================================

#[skuld::test]
fn truncate_for_dialog_empty_input() {
    assert_eq!(truncate_for_dialog(""), "");
}

#[skuld::test]
fn truncate_for_dialog_under_limit_passthrough() {
    let s = "one\ntwo\nthree\n";
    assert_eq!(truncate_for_dialog(s), s);
}

#[skuld::test]
fn truncate_for_dialog_under_limit_no_trailing_newline() {
    let s = "single line no newline";
    assert_eq!(truncate_for_dialog(s), s);
}

#[skuld::test]
fn truncate_for_dialog_over_limit_cuts_at_line_boundary() {
    // Build a big repeating line, well over DIALOG_OUTPUT_BUDGET (3 KiB).
    let line = "AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA";
    let big = std::iter::repeat_n(line, 100).collect::<Vec<_>>().join("\n");
    let truncated = truncate_for_dialog(&big);
    assert!(truncated.starts_with("...\n"), "ellipsis prefix expected");
    assert!(truncated.len() < big.len(), "should be shorter");
    // The body after the ellipsis prefix should start at a line boundary
    // (no leading partial line).
    let body = truncated.strip_prefix("...\n").unwrap();
    assert!(body.starts_with("AAAA"), "body should start at a clean line boundary");
}

#[skuld::test]
fn truncate_for_dialog_over_limit_no_newline_falls_back_to_byte_cut() {
    // Single line that exceeds the budget — there's no newline within the
    // budget, so the function must fall back to a byte-aligned cut.
    let big = "x".repeat(DIALOG_OUTPUT_BUDGET + 500);
    let truncated = truncate_for_dialog(&big);
    assert!(truncated.starts_with("...\n"));
    let body = truncated.strip_prefix("...\n").unwrap();
    assert!(body.chars().all(|c| c == 'x'));
}

#[skuld::test]
fn truncate_for_dialog_never_splits_utf8() {
    // Build a string with a multi-byte char placed exactly at the
    // tentative byte-cut. Function must advance the cut to the next char
    // boundary — checked indirectly by asserting the output is valid UTF-8
    // and contains the cyrillic byte sequence intact.
    let lead = "x".repeat(DIALOG_OUTPUT_BUDGET);
    let trail = "Привет\n".repeat(10);
    let big = format!("{lead}{trail}");
    let truncated = truncate_for_dialog(&big);
    // No assertion required beyond "doesn't panic" — slicing on a non-char
    // boundary in `is_char_boundary`-loop code path is the bug we're
    // guarding against. Additionally check the trailing chars are intact.
    assert!(truncated.contains("Привет"));
}

// SetupError::ExitCode Display ========================================================================================

#[skuld::test]
fn exit_code_display_with_empty_output_no_log() {
    let e = SetupError::ExitCode {
        code: 1,
        output: String::new(),
        log_path: None,
    };
    let rendered = e.to_string();
    assert_eq!(rendered, "elevated process exited with code 1");
}

#[skuld::test]
fn exit_code_display_with_output_no_log() {
    let e = SetupError::ExitCode {
        code: 2,
        output: "first line\nsecond line".into(),
        log_path: None,
    };
    let rendered = e.to_string();
    assert_eq!(
        rendered,
        "elevated process exited with code 2\n\nfirst line\nsecond line"
    );
}

#[skuld::test]
fn exit_code_display_with_log_no_output() {
    let e = SetupError::ExitCode {
        code: 3,
        output: String::new(),
        log_path: Some(PathBuf::from("/tmp/hole-install-XXXX/gui-cli.log")),
    };
    let rendered = e.to_string();
    assert!(
        rendered.contains("elevated process exited with code 3"),
        "got: {rendered}"
    );
    assert!(
        rendered.contains("Full log: /tmp/hole-install-XXXX/gui-cli.log"),
        "got: {rendered}"
    );
}

#[skuld::test]
fn exit_code_display_with_output_and_log() {
    let e = SetupError::ExitCode {
        code: 4,
        output: "some error".into(),
        log_path: Some(PathBuf::from("/tmp/hole-install-XXXX/gui-cli.log")),
    };
    let rendered = e.to_string();
    assert!(rendered.contains("some error"));
    assert!(rendered.contains("Full log: /tmp/hole-install-XXXX/gui-cli.log"));
    // Sanity: no stray double-blank-then-blank artifacts.
    assert!(!rendered.contains("\n\n\n"));
}

#[skuld::test]
fn exit_code_display_with_unicode_output() {
    let e = SetupError::ExitCode {
        code: 5,
        output: "Привет\n世界".into(),
        log_path: None,
    };
    let rendered = e.to_string();
    assert!(rendered.contains("Привет"));
    assert!(rendered.contains("世界"));
}
