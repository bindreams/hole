use crate::cli::{info_output, VERSION};

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
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
