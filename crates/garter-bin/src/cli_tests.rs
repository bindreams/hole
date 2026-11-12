use std::ffi::OsString;

use crate::cli::{info_output, VERSION};

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

/// An argument no UTF-8 string spells: invalid UTF-8 bytes on Unix, an unpaired surrogate on Windows.
fn non_utf8() -> OsString {
    #[cfg(unix)]
    return std::os::unix::ffi::OsStringExt::from_vec(vec![0xff, 0xfe]);
    #[cfg(windows)]
    return std::os::windows::ffi::OsStringExt::from_wide(&[0xd800]);
}

#[skuld::test]
fn version_flag_prints_the_program_and_its_stamped_version() {
    assert_eq!(info_output(args(&["--version"])), Some(format!("garter {VERSION}")));
    assert!(!VERSION.is_empty());
}

#[skuld::test]
fn help_flag_names_both_flags() {
    for flag in ["--help", "-h"] {
        let text = info_output(args(&[flag])).unwrap();
        assert!(text.contains("--version") && text.contains("--help"), "{text}");
    }
}

#[skuld::test]
fn no_arguments_or_anything_else_is_a_plugin_run() {
    assert_eq!(info_output(args(&[])), None);
    assert_eq!(info_output(args(&["--versions"])), None);
    assert_eq!(info_output(args(&["--version", "--help"])), None);
}

#[skuld::test]
fn a_non_utf8_argument_is_a_plugin_run_not_a_panic() {
    assert_eq!(info_output([non_utf8()]), None);
    assert_eq!(info_output([OsString::from("--version"), non_utf8()]), None);
}
