use skuld::env;

use crate::sip003::{
    join_plugin_options, parse_plugin_options, split_plugin_options, MalformedOptions, OptionSegment, PluginEnv,
};

#[skuld::test]
fn parse_env_all_set(#[fixture] env: &skuld::EnvGuard) {
    env.set("SS_LOCAL_HOST", "127.0.0.1");
    env.set("SS_LOCAL_PORT", "1080");
    env.set("SS_REMOTE_HOST", "example.com");
    env.set("SS_REMOTE_PORT", "443");
    env.set("SS_PLUGIN_OPTIONS", "tls;host=example.com");

    let result = PluginEnv::from_env().unwrap();
    assert_eq!(result.local_host, "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.local_port, 1080);
    assert_eq!(result.remote_host, "example.com");
    assert_eq!(result.remote_port, 443);
    assert_eq!(result.plugin_options.as_deref(), Some("tls;host=example.com"));
}

#[skuld::test]
fn parse_env_missing_required_var(#[fixture] env: &skuld::EnvGuard) {
    env.remove("SS_LOCAL_HOST");
    env.remove("SS_LOCAL_PORT");
    env.remove("SS_REMOTE_HOST");
    env.remove("SS_REMOTE_PORT");
    env.remove("SS_PLUGIN_OPTIONS");

    let result = PluginEnv::from_env();
    assert!(result.is_err());
}

#[skuld::test]
fn parse_env_no_plugin_options(#[fixture] env: &skuld::EnvGuard) {
    env.set("SS_LOCAL_HOST", "0.0.0.0");
    env.set("SS_LOCAL_PORT", "1080");
    env.set("SS_REMOTE_HOST", "server.example.com");
    env.set("SS_REMOTE_PORT", "8388");
    env.remove("SS_PLUGIN_OPTIONS");

    let result = PluginEnv::from_env().unwrap();
    assert!(result.plugin_options.is_none());
}

#[skuld::test]
fn parse_plugin_options_basic() {
    let opts = parse_plugin_options("tls;host=example.com;mode=websocket");
    assert_eq!(
        opts,
        vec![
            ("tls".to_string(), "".to_string()),
            ("host".to_string(), "example.com".to_string()),
            ("mode".to_string(), "websocket".to_string()),
        ]
    );
}

#[skuld::test]
fn parse_plugin_options_escaped() {
    let opts = parse_plugin_options(r"path=/a\;b;key=val\\ue");
    assert_eq!(
        opts,
        vec![
            ("path".to_string(), "/a;b".to_string()),
            ("key".to_string(), r"val\ue".to_string()),
        ]
    );
}

#[skuld::test]
fn parse_plugin_options_empty() {
    let opts = parse_plugin_options("");
    assert!(opts.is_empty());
}

#[skuld::test]
fn plugin_env_local_addr(#[fixture] env: &skuld::EnvGuard) {
    env.set("SS_LOCAL_HOST", "127.0.0.1");
    env.set("SS_LOCAL_PORT", "1080");
    env.set("SS_REMOTE_HOST", "example.com");
    env.set("SS_REMOTE_PORT", "443");
    env.remove("SS_PLUGIN_OPTIONS");

    let result = PluginEnv::from_env().unwrap();
    let addr = result.local_addr();
    assert_eq!(addr.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(addr.port(), 1080);
}

#[skuld::test]
fn parse_plugin_options_escaped_equals_in_key() {
    let opts = parse_plugin_options(r"k\=ey=value");
    assert_eq!(opts, vec![("k=ey".to_string(), "value".to_string()),]);
}

#[skuld::test]
fn parse_plugin_options_equals_in_value() {
    let opts = parse_plugin_options("key=a=b");
    assert_eq!(opts, vec![("key".to_string(), "a=b".to_string()),]);
}

// Segment primitives ==================================================================================================

/// The segments of `opts`, or panic — for inputs that are not testing rejection.
fn segs(opts: &str) -> Vec<OptionSegment<'_>> {
    split_plugin_options(opts).expect("well-formed options")
}

#[skuld::test]
fn split_reports_raw_segments_and_decoded_keys() {
    let s = segs("host=example.com;tls;path=/foo");
    let raws: Vec<&str> = s.iter().map(|x| x.raw).collect();
    let keys: Vec<&str> = s.iter().map(|x| x.key.as_str()).collect();
    assert_eq!(raws, ["host=example.com", "tls", "path=/foo"]);
    assert_eq!(keys, ["host", "tls", "path"]);
}

// The key is decoded so a caller can compare it, but `raw` is not — a value is
// never re-escaped, so it cannot be altered by passing through here.
#[skuld::test]
fn split_decodes_the_key_but_leaves_the_segment_raw() {
    let s = segs(r"k\=ey=a\;b");
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].key, "k=ey");
    assert_eq!(s[0].value, "a;b");
    assert_eq!(s[0].raw, r"k\=ey=a\;b");
}

// See `OptionSegment::key` for why this decoding rule differs from `parse_plugin_options`.
#[skuld::test]
fn split_decodes_a_key_the_way_a_sip003_plugin_does() {
    assert_eq!(segs(r"ech\-doh=x")[0].key, "ech-doh");
    assert_eq!(segs(r"log\level=warning")[0].key, "loglevel");
    // The narrower `parse_plugin_options` alphabet deliberately differs.
    assert_eq!(parse_plugin_options(r"ech\-doh=x")[0].0, r"ech\-doh");
}

// An escaped `;` is part of a value, not a separator.
#[skuld::test]
fn split_does_not_break_on_an_escaped_semicolon() {
    let s = segs(r"path=/a\;b;mode=websocket");
    let raws: Vec<&str> = s.iter().map(|x| x.raw).collect();
    assert_eq!(raws, [r"path=/a\;b", "mode=websocket"]);
}

// The three-way distinction, pinned side by side because two of these look
// alike and only one is benign. ex-ray accepts a trailing separator, and rejects
// an empty key in EITHER shape — `;;` (an empty segment) or `=v` (a non-empty
// segment whose key is empty).
#[skuld::test]
fn split_normalizes_a_trailing_separator_but_rejects_an_empty_key() {
    // Accepted by ex-ray; the splitter emits no empty segment for it. Dropping
    // it is required — appending after it would produce `a=1;;…`, which is not.
    let s = segs("a=1;");
    assert_eq!(s.iter().map(|x| x.raw).collect::<Vec<_>>(), ["a=1"]);

    // Rejected by ex-ray (`empty key in ""`), so rejected here.
    assert_eq!(
        split_plugin_options("a=1;;b=2"),
        Err(MalformedOptions::EmptyKey { index: 1 })
    );
    assert_eq!(
        split_plugin_options("a=1;;"),
        Err(MalformedOptions::EmptyKey { index: 1 })
    );
    assert_eq!(split_plugin_options("=v"), Err(MalformedOptions::EmptyKey { index: 0 }));
    assert_eq!(
        split_plugin_options("host=h;=v;mux=0"),
        Err(MalformedOptions::EmptyKey { index: 1 })
    );
}

#[skuld::test]
fn split_of_the_empty_string_is_empty() {
    assert!(segs("").is_empty());
}

// `value` alone cannot tell `tls` (bare) from `tls=` (explicit empty) apart —
// both decode to `""`. `has_value` is the field that can, which matters
// because ex-ray's own parser does not treat them alike either: bare `tls`
// reads as `"1"` there, `tls=` as `""` (`crates/ex-ray/args.go`).
#[skuld::test]
fn has_value_distinguishes_a_bare_key_from_an_explicit_empty_one() {
    let s = segs("tls;host=");
    assert_eq!(
        (s[0].key.as_str(), s[0].value.as_str(), s[0].has_value),
        ("tls", "", false)
    );
    assert_eq!(
        (s[1].key.as_str(), s[1].value.as_str(), s[1].has_value),
        ("host", "", true)
    );
}

// A trailing unpaired backslash would escape the `;` a caller appends after it,
// swallowing the appended directive. ex-ray already rejects such a string, so it
// is rejected here rather than silently made parseable-but-wrong.
#[skuld::test]
fn split_rejects_a_dangling_trailing_escape() {
    assert_eq!(split_plugin_options(r"path=/a\"), Err(MalformedOptions::DanglingEscape));
    assert_eq!(split_plugin_options(r"a=1;b=2\"), Err(MalformedOptions::DanglingEscape));
    // A PAIRED trailing backslash is a value, not a dangling escape.
    assert_eq!(segs(r"path=/a\\")[0].raw, r"path=/a\\");
}

#[skuld::test]
fn join_separates_with_semicolons() {
    assert_eq!(join_plugin_options(["a=1", "b=2"]), "a=1;b=2");
    assert_eq!(join_plugin_options(["a=1"]), "a=1");
    assert_eq!(join_plugin_options(std::iter::empty::<&str>()), "");
}

// The load-bearing property for every caller: on input the primitive ACCEPTS,
// split-then-join preserves the pairs a plugin will read, byte-level escapes and
// all. Rejected input has no round-trip to speak of.
#[skuld::test]
fn split_then_join_preserves_the_parsed_pairs() {
    for input in [
        "host=example.com;path=/foo",
        r"path=/a\;b;key=val\\ue",
        r"k\=ey=value",
        "key=a=b",
        "tls;server;mux=8",
        "loglevel=warning;path=/foo",
        "a=1;",
    ] {
        let rejoined = join_plugin_options(segs(input).iter().map(|x| x.raw));
        assert_eq!(
            parse_plugin_options(&rejoined),
            parse_plugin_options(input.trim_end_matches(';')),
            "split/join changed the parsed pairs of {input:?} (rejoined {rejoined:?})"
        );
    }
}

// Appending after a join must not merge into a trailing escaped semicolon —
// `mux` must survive as its own key-value pair.
#[skuld::test]
fn appending_after_a_join_survives_a_trailing_escaped_semicolon() {
    let appended = join_plugin_options(segs(r"path=/a\;").iter().map(|x| x.raw).chain(["mux=0"]));
    assert_eq!(appended, r"path=/a\;;mux=0");
    assert_eq!(
        parse_plugin_options(&appended),
        vec![("path".into(), "/a;".to_string()), ("mux".into(), "0".to_string())],
    );
}
