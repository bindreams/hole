use super::*;

const FLAG: Option<&str> = Some("--no-show-dashboard");

// Windows `Run` value: everything that is not a dashboard flag is preserved
// byte-for-byte, so an unquoted path containing spaces is never re-parsed.

#[skuld::test]
fn adds_the_flag_to_an_argument_less_value() {
    assert_eq!(
        set_dashboard_flag_in_value(r"C:\Program Files\hole\bin\hole.exe", FLAG),
        r"C:\Program Files\hole\bin\hole.exe --no-show-dashboard"
    );
}

#[skuld::test]
fn tolerates_the_trailing_space_auto_launch_writes() {
    // auto-launch formats "{path} {args}", so an empty arg list leaves a
    // trailing space in every registration written before this change.
    assert_eq!(
        set_dashboard_flag_in_value(r"C:\Program Files\hole\bin\hole.exe ", FLAG),
        r"C:\Program Files\hole\bin\hole.exe --no-show-dashboard"
    );
}

#[skuld::test]
fn value_rewrite_is_idempotent() {
    let once = set_dashboard_flag_in_value(r"C:\hole\hole.exe", FLAG);
    assert_eq!(set_dashboard_flag_in_value(&once, FLAG), once);
}

#[skuld::test]
fn preserves_a_quoted_path() {
    assert_eq!(
        set_dashboard_flag_in_value(r#""C:\Program Files\hole\bin\hole.exe""#, FLAG),
        r#""C:\Program Files\hole\bin\hole.exe" --no-show-dashboard"#
    );
}

#[skuld::test]
fn replaces_the_opposite_dashboard_flag() {
    assert_eq!(
        set_dashboard_flag_in_value(r"C:\hole\hole.exe --show-dashboard", FLAG),
        r"C:\hole\hole.exe --no-show-dashboard"
    );
}

#[skuld::test]
fn replaces_a_dashboard_flag_that_is_not_last() {
    // Position-independent: a suffix-only strip would append a second flag and
    // leave both in the registration forever.
    assert_eq!(
        set_dashboard_flag_in_value(r"C:\hole\hole.exe --show-dashboard --future-flag", FLAG),
        r"C:\hole\hole.exe --future-flag --no-show-dashboard"
    );
}

#[skuld::test]
fn preserves_arguments_it_does_not_own() {
    // The module owns the dashboard flags and nothing else; an argument some
    // other feature registered must survive.
    assert_eq!(
        set_dashboard_flag_in_value(r"C:\hole\hole.exe --future-flag", FLAG),
        r"C:\hole\hole.exe --future-flag --no-show-dashboard"
    );
}

#[skuld::test]
fn does_not_match_a_flag_inside_a_longer_token() {
    // Whitespace-delimited only: a path or argument that merely contains the
    // flag as a substring is not an occurrence of it.
    let value = r"C:\hole\--show-dashboard-notaflag\hole.exe";
    assert_eq!(
        set_dashboard_flag_in_value(value, FLAG),
        format!("{value} --no-show-dashboard")
    );
}

#[skuld::test]
fn a_none_flag_removes_it_from_any_position() {
    assert_eq!(
        set_dashboard_flag_in_value(r"C:\hole\hole.exe --no-show-dashboard", None),
        r"C:\hole\hole.exe"
    );
    assert_eq!(
        set_dashboard_flag_in_value(r"C:\hole\hole.exe --show-dashboard --future-flag", None),
        r"C:\hole\hole.exe --future-flag"
    );
}

// macOS plist: ProgramArguments[0] is the program, the tail is arguments. Same
// contract — the dashboard flag is replaced, everything else preserved.

#[skuld::test]
fn appends_the_flag_to_program_arguments() {
    let existing = vec!["/Applications/Hole.app/Contents/MacOS/hole".to_string()];
    assert_eq!(
        set_dashboard_flag_in_arguments(&existing, FLAG),
        vec![
            "/Applications/Hole.app/Contents/MacOS/hole".to_string(),
            "--no-show-dashboard".to_string(),
        ]
    );
}

#[skuld::test]
fn program_arguments_rewrite_is_idempotent() {
    let existing = vec!["/x/hole".to_string(), "--no-show-dashboard".to_string()];
    assert_eq!(set_dashboard_flag_in_arguments(&existing, FLAG), existing);
}

#[skuld::test]
fn program_arguments_replaces_the_opposite_flag() {
    let existing = vec!["/x/hole".to_string(), "--show-dashboard".to_string()];
    assert_eq!(
        set_dashboard_flag_in_arguments(&existing, FLAG),
        vec!["/x/hole".to_string(), "--no-show-dashboard".to_string()]
    );
}

#[skuld::test]
fn program_arguments_preserves_what_it_does_not_own() {
    let existing = vec!["/x/hole".to_string(), "--future-flag".to_string()];
    assert_eq!(
        set_dashboard_flag_in_arguments(&existing, FLAG),
        vec![
            "/x/hole".to_string(),
            "--future-flag".to_string(),
            "--no-show-dashboard".to_string(),
        ]
    );
}

#[skuld::test]
fn an_empty_program_arguments_array_stays_empty() {
    // A malformed plist must not gain a phantom program entry.
    assert!(set_dashboard_flag_in_arguments(&[], FLAG).is_empty());
}

// Outcome classification, shared by both platform arms.

#[skuld::test]
fn absent_registration_is_no_registration() {
    assert_eq!(classify(None, &"anything".to_string()), Outcome::NoRegistration);
}

#[skuld::test]
fn unchanged_registration_is_already_current() {
    let value = "same".to_string();
    assert_eq!(classify(Some(&value), &value), Outcome::AlreadyCurrent);
}

#[skuld::test]
fn changed_registration_is_rewritten() {
    assert_eq!(
        classify(Some(&"before".to_string()), &"after".to_string()),
        Outcome::Rewritten
    );
}
