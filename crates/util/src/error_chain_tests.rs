use super::{error_chain, raw_os_error};

#[derive(Debug, thiserror::Error)]
#[error("outer")]
struct Outer(#[source] Middle);

#[derive(Debug, thiserror::Error)]
#[error("middle")]
struct Middle(#[source] std::io::Error);

#[skuld::test]
fn a_chain_names_every_cause_outermost_first() {
    let e = Outer(Middle(std::io::Error::other("root cause")));
    assert_eq!(error_chain(&e).to_string(), "outer -> middle -> root cause");
}

#[skuld::test]
fn an_error_without_a_source_prints_only_itself() {
    let e = std::io::Error::other("alone");
    assert_eq!(error_chain(&e).to_string(), "alone");
}

#[derive(Debug, thiserror::Error)]
#[error("wrapped: {0}")]
struct Embeds(#[source] std::io::Error);

#[skuld::test]
fn a_parent_that_embeds_its_cause_prints_it_twice() {
    let wrapped = Embeds(std::io::Error::other("root"));
    assert_eq!(error_chain(&wrapped).to_string(), "wrapped: root -> root");
}

#[skuld::test]
fn a_cause_whose_text_is_a_substring_of_its_parents_is_still_printed() {
    #[derive(Debug, thiserror::Error)]
    #[error("failed to open the config")]
    struct Parent(#[source] std::io::Error);
    let e = Parent(std::io::Error::other("open"));
    assert_eq!(error_chain(&e).to_string(), "failed to open the config -> open");
}

// raw_os_error ========================================================================================================

/// Carries an OS error as its `source()` and has no code of its own.
#[derive(Debug, thiserror::Error)]
#[error("wrapper")]
struct Wraps(#[source] std::io::Error);

#[skuld::test]
fn an_error_with_a_code_reports_it() {
    assert_eq!(raw_os_error(&std::io::Error::from_raw_os_error(32)), Some(32));
}

#[skuld::test]
fn an_error_without_a_code_or_a_source_reports_none() {
    assert_eq!(raw_os_error(&std::io::Error::other("no code")), None);
    assert_eq!(raw_os_error(&std::io::Error::from(std::io::ErrorKind::NotFound)), None);
}

#[skuld::test]
fn the_code_of_a_wrapped_os_error_is_found() {
    let wrapped = std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        Wraps(std::io::Error::from_raw_os_error(5)),
    );
    assert_eq!(wrapped.raw_os_error(), None, "guard: the outer error has no code");
    assert_eq!(raw_os_error(&wrapped), Some(5));
}

#[skuld::test]
fn the_code_is_found_through_every_level_of_wrapping() {
    let inner = std::io::Error::other(Wraps(std::io::Error::from_raw_os_error(32)));
    let outer = std::io::Error::other(Wraps(inner));
    assert_eq!(raw_os_error(&outer), Some(32));
}

#[skuld::test]
fn a_wrapped_error_without_a_code_reports_none() {
    let wrapped = std::io::Error::other(Wraps(std::io::Error::other("no code")));
    assert_eq!(raw_os_error(&wrapped), None);
}
