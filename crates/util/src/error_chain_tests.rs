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
fn a_cause_the_parent_already_prints_is_not_repeated() {
    let wrapped = Embeds(std::io::Error::other("root"));
    assert_eq!(error_chain(&wrapped).to_string(), "wrapped: root");
}

#[skuld::test]
fn a_parent_that_embeds_its_cause_still_shows_the_causes_beneath() {
    #[derive(Debug, thiserror::Error)]
    #[error("top: {0}")]
    struct Top(#[source] Middle);
    let e = Top(Middle(std::io::Error::other("root cause")));
    assert_eq!(error_chain(&e).to_string(), "top: middle -> root cause");
}
