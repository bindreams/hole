use super::{Chain, ChainError, Obsolete};
use crate::assert_contiguous;
use crate::versioned_file::fixtures::{DroppedFile, NoteV3};

// The backstop for a gap that only the build, not `cargo check`, reports through
// generic code: naming every current type makes the test target fail to
// type-check, for a gap anywhere in its chain.
assert_contiguous!(NoteV3);
assert_contiguous!(DroppedFile);

fn note(tags: &[&str], pinned: bool) -> NoteV3 {
    NoteV3 {
        title: "t".to_string(),
        tags: tags.iter().map(|s| s.to_string()).collect(),
        pinned,
    }
}

#[skuld::test]
fn chain_without_gap_decodes_oldest_to_newest() {
    // v1 gains `tags = ["imported"]` at v2 and `pinned = false` at v3.
    let v1 = br#"{"version":1,"title":"t"}"#;
    let v2 = br#"{"version":2,"title":"t","tags":["x","y"]}"#;
    let v3 = br#"{"version":3,"title":"t","tags":["x","y"],"pinned":true}"#;

    assert_eq!(<NoteV3 as Chain>::decode(1, v1).unwrap(), note(&["imported"], false));
    assert_eq!(<NoteV3 as Chain>::decode(2, v2).unwrap(), note(&["x", "y"], false));
    assert_eq!(<NoteV3 as Chain>::decode(3, v3).unwrap(), note(&["x", "y"], true));
}

#[skuld::test]
fn a_version_at_or_below_the_floor_is_obsolete() {
    let v1 = br#"{"version":1,"value":7}"#;
    let v2 = br#"{"version":2,"value":7}"#;

    assert!(matches!(
        <DroppedFile as Chain>::decode(1, v1),
        Err(ChainError::Obsolete)
    ));
    assert_eq!(<DroppedFile as Chain>::decode(2, v2).unwrap(), DroppedFile { value: 7 });
}

#[skuld::test]
fn a_wrong_shape_at_the_right_version_is_a_shape_error_that_does_not_echo_the_value() {
    const SECRET: &str = "203.0.113.7";
    let body = format!(r#"{{"version":3,"title":"t","tags":"{SECRET}","pinned":true}}"#);

    let err = match <NoteV3 as Chain>::decode(3, body.as_bytes()) {
        Err(ChainError::Shape(failure)) => failure,
        other => panic!("expected a shape error, got {other:?}"),
    };
    assert!(!err.to_string().contains(SECRET), "echoed: {err}");
    assert!(!format!("{err:?}").contains(SECRET), "echoed: {err:?}");
}

#[skuld::test]
fn a_shape_error_in_an_older_version_is_reported_not_migrated() {
    // v1 requires a `title`; without it no upgrade step may run.
    let body = br#"{"version":1}"#;
    assert!(matches!(<NoteV3 as Chain>::decode(1, body), Err(ChainError::Shape(_))));
}

#[skuld::test]
fn the_top_of_a_chain_is_the_current_version_or_the_floor() {
    assert_eq!(<NoteV3 as Chain>::TOP, 3);
    assert_eq!(<Obsolete<5> as Chain>::TOP, 5);
}

/// The `.stderr` fixtures are regenerated with `TRYBUILD=overwrite cargo test
/// -p util -- a_chain_with_a_gap_does_not_compile`; the toolchain is pinned in
/// `rust-toolchain.toml`, so they move only when it does.
#[skuld::test]
fn a_chain_with_a_gap_does_not_compile() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/*.rs");
    cases.pass("tests/compile_pass/*.rs");
}
