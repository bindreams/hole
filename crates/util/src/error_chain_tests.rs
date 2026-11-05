use super::error_chain;

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
