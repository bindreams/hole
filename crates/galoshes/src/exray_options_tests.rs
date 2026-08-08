use crate::exray_options::ex_ray_options;

#[skuld::test]
fn mux_is_disabled_by_default() {
    assert_eq!(ex_ray_options(None).unwrap(), "mux=0");
    assert_eq!(ex_ray_options(Some("")).unwrap(), "mux=0");
    assert_eq!(
        ex_ray_options(Some("host=cloudfront.com;path=/")).unwrap(),
        "host=cloudfront.com;path=/;mux=0"
    );
}

#[skuld::test]
fn server_mode_and_other_directives_survive() {
    // `Mode::from_plugin_options` keys off `server`; appending must not disturb it.
    let out = ex_ray_options(Some("server;host=cloudfront.com;path=/;tls")).unwrap();
    assert_eq!(out, "server;host=cloudfront.com;path=/;tls;mux=0");
    assert_eq!(
        garter::Mode::from_plugin_options(Some(&out)).unwrap(),
        garter::Mode::Server
    );
}

#[skuld::test]
fn an_operator_mux_wins() {
    // ex-ray is first-wins, so an earlier `mux=` overrides the appended default.
    let out = ex_ray_options(Some("mux=8;path=/")).unwrap();
    let pairs = garter::parse_plugin_options(&out).unwrap();
    let first_mux = pairs.iter().find(|(k, _)| k == "mux").expect("mux key present");
    assert_eq!(first_mux.1, "8");
}

#[skuld::test]
fn an_escaped_spelling_of_mux_still_overrides() {
    // ex-ray unescapes `mu\x` to `mux`, so this is a duplicate key to it. Segments
    // are appended raw and never deduplicated, so first-wins still resolves it.
    let out = ex_ray_options(Some(r"mu\x=8;path=/")).unwrap();
    assert_eq!(out, r"mu\x=8;path=/;mux=0");
    let segments = garter::split_plugin_options(&out).unwrap();
    assert_eq!(segments[0].key, "mux");
}

#[skuld::test]
fn an_escaped_trailing_semicolon_is_not_swallowed() {
    // A naive strip-then-append yields `path=/a\;mux=0`, which ex-ray reads as
    // ONE pair with no mux key at all.
    let out = ex_ray_options(Some(r"path=/a\;")).unwrap();
    assert_eq!(out, r"path=/a\;;mux=0");
    assert_eq!(
        garter::parse_plugin_options(&out).unwrap(),
        vec![("path".into(), "/a;".into()), ("mux".into(), "0".into())]
    );
}

#[skuld::test]
fn a_trailing_separator_does_not_make_an_empty_segment() {
    // `mode=websocket;;mux=0` makes ex-ray reject the WHOLE string ("empty key")
    // and fall back to every flag default.
    let out = ex_ray_options(Some("mode=websocket;")).unwrap();
    assert_eq!(out, "mode=websocket;mux=0");
}

// These two assert galoshes' OWN disposition, not garter's classification: on a
// string ex-ray would silently discard, `ex_ray_options` must not hand back
// something that looks usable.
#[skuld::test]
fn a_dangling_final_escape_is_rejected() {
    // `path=/a\` + `;mux=0` = `path=/a\;mux=0`: the escape swallows the separator
    // and mux disappears. Odd/even trailing runs are pinned Go-side in
    // `TestParseOptsIntoFlagsMux`.
    assert!(ex_ray_options(Some(r"path=/a\")).is_err());
    assert!(ex_ray_options(Some(r"path=/a\\\")).is_err());
    assert!(ex_ray_options(Some(r"path=/a\\")).is_ok());
}

#[skuld::test]
fn an_empty_key_segment_is_rejected() {
    assert!(ex_ray_options(Some("=v")).is_err());
    assert!(ex_ray_options(Some("host=cloudfront.com;=v")).is_err());
    // An empty interior segment is the same input class.
    assert!(ex_ray_options(Some("host=cloudfront.com;;path=/")).is_err());
}
