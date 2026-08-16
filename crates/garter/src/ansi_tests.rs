use crate::ansi::strip_sgr;

#[skuld::test]
fn a_complete_sgr_pair_is_removed() {
    assert_eq!(strip_sgr("\x1b[31mred\x1b[0m"), "red");
}

/// Regression: `anstream::adapter::strip_str` eats the `i` of "invalid" here;
/// `strip_sgr` must not.
#[skuld::test]
fn a_lone_escape_leaves_surrounding_text_untouched() {
    let line = "error: config \x1binvalid detail text here";
    assert_eq!(strip_sgr(line), line);
}

/// Regression: `anstream::adapter::strip_str` eats the leading `t` of
/// "truncated" here; `strip_sgr` must not.
#[skuld::test]
fn a_truncated_sequence_with_no_terminator_leaves_text_untouched() {
    let line = "\x1b[31truncated and no terminator, rest here";
    assert_eq!(strip_sgr(line), line);
}

#[skuld::test]
fn adjacent_sequences_are_all_removed() {
    let line = "\x1b[2m2026\x1b[0m \x1b[32m INFO\x1b[0m plain text";
    assert_eq!(strip_sgr(line), "2026  INFO plain text");
}

/// A colon-separated sub-parameter SGR (the standard truecolor form) must
/// also be removed, not just the semicolon form.
#[skuld::test]
fn a_colon_subparameter_truecolor_sequence_is_removed() {
    assert_eq!(strip_sgr("\x1b[38:2:255:0:0mred\x1b[0m"), "red");
}
