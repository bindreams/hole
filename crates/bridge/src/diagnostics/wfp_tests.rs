use super::*;

#[skuld::test]
fn truncate_utf8_empty_returns_empty() {
    assert_eq!(truncate_utf8("", 10), "");
}

#[skuld::test]
fn truncate_utf8_under_cap_returns_input() {
    assert_eq!(truncate_utf8("hello", 10), "hello");
}

#[skuld::test]
fn truncate_utf8_ascii_at_cap_returns_prefix() {
    assert_eq!(truncate_utf8("abcdef", 3), "abc");
}

#[skuld::test]
fn truncate_utf8_walks_back_to_char_boundary() {
    let s = "a\u{1F980}b"; // a + 🦀 (4 UTF-8 bytes) + b = 6 bytes
                           // Cutting at 3 would split the crab; must walk back to 1.
    assert_eq!(truncate_utf8(s, 3), "a");
}

#[skuld::test]
fn truncate_utf8_exact_boundary_keeps_full_codepoint() {
    let s = "a\u{1F980}b";
    // Cap of 5 leaves room for a + crab (1 + 4 = 5), not b.
    assert_eq!(truncate_utf8(s, 5), "a\u{1F980}");
}
