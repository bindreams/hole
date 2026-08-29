//! Addresses here are from the documentation ranges (RFC 5737 `203.0.113.0/24`,
//! RFC 3849 `2001:db8::/32`) and the `.invalid` TLD, so they appear in no
//! workspace fixture and read unambiguously as "this is the secret".
//!
//! The registry is process-global and grow-only. These tests are written for
//! `cargo nextest`, which runs each one in its own process; under a shared
//! process an arming in one test would be visible to the next.

use std::borrow::Cow;
use std::io::Write as _;

use garter::test_utils::WaitableWriter;
use garter::tracing_test::set_default_in_current_thread;

use super::{arm, armed_literal_count, redact_bytes, redact_str, RedactingWriter};

const TOKEN_A: &str = "<server:aaaaaaaa>";
const TOKEN_B: &str = "<server:bbbbbbbb>";
const ADDR: &str = "203.0.113.7";
const HOST: &str = "vpn.example.invalid";

fn arm_one(token: &str, literal: &str) {
    arm(token, [literal.to_string()]);
}

/// A `fmt` subscriber writing into a `WaitableWriter`, for the two tests
/// that assert on what `arm` itself logs.
fn capture() -> (impl tracing::Subscriber + Send + Sync, WaitableWriter) {
    let writer = WaitableWriter::new();
    let sink = writer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink)
        .with_ansi(false)
        .with_target(true)
        .finish();
    (subscriber, writer)
}

// redact_bytes / redact_str ===========================================================================================

#[skuld::test]
fn empty_registry_passes_bytes_through_unchanged() {
    let input = format!("connecting to {ADDR}:8388").into_bytes();
    let out = redact_bytes(&input);
    assert!(
        matches!(out, Cow::Borrowed(_)),
        "the empty registry must not re-encode; got an owned buffer"
    );
    assert_eq!(&*out, &input[..]);
}

#[skuld::test]
fn armed_literal_is_replaced_by_its_token() {
    arm_one(TOKEN_A, ADDR);
    let line = format!("connecting to {ADDR}:8388");
    let out = redact_str(&line);
    assert_eq!(out, format!("connecting to {TOKEN_A}:8388"));
    assert!(!out.contains(ADDR));
}

#[skuld::test]
fn two_literals_armed_under_one_token_share_it() {
    arm(TOKEN_A, [ADDR.to_string(), HOST.to_string()]);
    let line = format!("{HOST} resolved to {ADDR}");
    let out = redact_str(&line);
    assert_eq!(out, format!("{TOKEN_A} resolved to {TOKEN_A}"));
}

#[skuld::test]
fn arming_a_second_entry_keeps_the_first_redacted() {
    arm_one(TOKEN_A, ADDR);
    arm_one(TOKEN_B, "203.0.113.9");
    let line = format!("a={ADDR} b=203.0.113.9");
    let out = redact_str(&line);
    assert_eq!(out, format!("a={TOKEN_A} b={TOKEN_B}"));
}

#[skuld::test]
fn concurrent_arms_from_two_threads_both_survive() {
    // A plain read-build-store would let the later store discard the other
    // caller's literal permanently — nothing re-arms.
    std::thread::scope(|s| {
        s.spawn(|| arm_one(TOKEN_A, ADDR));
        s.spawn(|| arm_one(TOKEN_B, "203.0.113.9"));
    });
    let line = format!("a={ADDR} b=203.0.113.9");
    let out = redact_str(&line);
    assert_eq!(out, format!("a={TOKEN_A} b={TOKEN_B}"));
}

#[skuld::test]
fn re_arming_the_same_literal_replaces_its_token() {
    arm_one(TOKEN_A, ADDR);
    arm_one(TOKEN_B, ADDR);
    let line = format!("connecting to {ADDR}");
    let out = redact_str(&line);
    assert_eq!(out, format!("connecting to {TOKEN_B}"));
}

#[skuld::test]
fn re_arming_does_not_grow_the_pattern_set() {
    arm(TOKEN_A, [ADDR.to_string(), HOST.to_string()]);
    let after_first = armed_literal_count();
    assert_eq!(after_first, 2);
    for _ in 0..10 {
        arm(TOKEN_A, [ADDR.to_string(), HOST.to_string()]);
    }
    assert_eq!(
        armed_literal_count(),
        after_first,
        "a long-running service re-arms on every config touch; the automaton must stay bounded"
    );
}

#[skuld::test]
fn a_token_replacement_announces_both_tokens() {
    let (subscriber, writer) = capture();
    let _guard = set_default_in_current_thread(subscriber);

    arm_one(TOKEN_A, ADDR);
    arm_one(TOKEN_B, ADDR);

    let log = writer.snapshot();
    assert!(
        log.contains(TOKEN_A),
        "announcement must name the superseded token: {log}"
    );
    assert!(log.contains(TOKEN_B), "announcement must name the new token: {log}");
    assert!(!log.contains(ADDR), "announcement must not name the address: {log}");
    assert!(!log.contains(HOST), "announcement must not name the hostname: {log}");
}

#[skuld::test]
fn a_longer_armed_literal_wins_over_its_own_prefix() {
    // `MatchKind::Standard` would redact `10.0.0.12` as `<token-for-.1>2`,
    // leaking the trailing byte and mis-attributing the line.
    arm_one(TOKEN_A, "10.0.0.1");
    arm_one(TOKEN_B, "10.0.0.12");
    let out = redact_str("remote 10.0.0.12:8388");
    assert_eq!(out, format!("remote {TOKEN_B}:8388"));
}

#[skuld::test]
fn an_empty_literal_is_not_armed() {
    arm(TOKEN_A, [String::new(), "   ".to_string(), ADDR.to_string()]);
    assert_eq!(armed_literal_count(), 1, "only the real literal may be armed");
    let line = format!("connecting to {ADDR}:8388");
    let out = redact_str(&line);
    assert_eq!(
        out,
        format!("connecting to {TOKEN_A}:8388"),
        "a zero-width pattern would shred every position and leave the address in the clear"
    );
    assert_eq!(redact_str("ordinary text"), "ordinary text");
}

#[skuld::test]
fn a_vocabulary_colliding_literal_is_armed_and_warned() {
    let (subscriber, writer) = capture();
    let _guard = set_default_in_current_thread(subscriber);

    // Nothing validates a configured host, so `server: "hole"` is reachable.
    arm_one(TOKEN_A, "hole");

    let log = writer.snapshot();
    assert!(log.contains("WARN"), "a colliding literal must say so out loud: {log}");
    assert!(log.contains(TOKEN_A), "the warning must name the token: {log}");
    // Privacy does not yield to legibility: the literal is armed anyway.
    assert_eq!(redact_str("connect hole"), format!("connect {TOKEN_A}"));
}

// RedactingWriter =====================================================================================================

#[skuld::test]
fn write_returns_the_input_length_when_redaction_grows_it() {
    arm_one(TOKEN_A, ADDR);
    let line = format!("remote {ADDR}\n");
    let mut w = RedactingWriter::new(Vec::new());
    let n = w.write(line.as_bytes()).expect("write");
    assert_eq!(n, line.len(), "must report input bytes consumed, not output emitted");
}

#[skuld::test]
fn write_returns_the_input_length_when_redaction_shrinks_it() {
    arm_one("<s>", HOST);
    let line = format!("remote {HOST}\n");
    let mut w = RedactingWriter::new(Vec::new());
    let n = w.write(line.as_bytes()).expect("write");
    assert_eq!(n, line.len(), "must report input bytes consumed, not output emitted");
}

#[skuld::test]
fn a_multi_line_event_is_redacted_in_every_line() {
    arm_one(TOKEN_A, ADDR);
    // One `write_all`, `dump!`-shaped block scalar, literal on the third line.
    let event = format!("proxy started\n  config:\n    server_ip: {ADDR}\n    port: 8388\n");
    let mut w = RedactingWriter::new(Vec::new());
    w.write_all(event.as_bytes()).expect("write_all");
    let out = String::from_utf8(w.into_inner()).expect("utf-8");
    assert!(!out.contains(ADDR), "address survived a multi-line event: {out}");
    assert!(out.contains(TOKEN_A), "token missing from a multi-line event: {out}");
    assert!(out.contains("port: 8388"), "unrelated lines must be untouched: {out}");
}
