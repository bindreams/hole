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
    let s = "a\u{1F980}b"; // a + crab (4 UTF-8 bytes) + b = 6 bytes
                           // Cutting at 3 would split the crab; must walk back to 1.
    assert_eq!(truncate_utf8(s, 3), "a");
}

#[skuld::test]
fn truncate_utf8_exact_boundary_keeps_full_codepoint() {
    let s = "a\u{1F980}b";
    // Cap of 5 leaves room for a + crab (1 + 4 = 5), not b.
    assert_eq!(truncate_utf8(s, 5), "a\u{1F980}");
}

#[skuld::test]
fn watched_matches_empty_text_returns_empty() {
    assert!(watched_matches("").is_empty());
}

#[skuld::test]
fn watched_matches_no_watched_substring_returns_empty() {
    assert!(watched_matches("Microsoft Kernel Debug Network Adapter").is_empty());
}

#[skuld::test]
fn watched_matches_case_insensitive_hit() {
    let hits = watched_matches("Wintun Userspace Tunnel");
    assert_eq!(hits, vec!["wintun"]);
}

#[skuld::test]
fn watched_matches_multiple_hits_deduped_by_constant_list() {
    // Both "wintun" and "wireguard" appear; expect exactly those two entries,
    // one per watched substring (not one per occurrence).
    let hits = watched_matches("WireGuard LLC\nwintun-bindings 0.7\nwintun driver");
    assert_eq!(hits.len(), 2);
    assert!(hits.contains(&"wintun"));
    assert!(hits.contains(&"wireguard"));
}
