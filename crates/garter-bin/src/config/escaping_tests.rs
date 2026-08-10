use super::escaping::*;

// config_path_from_plugin_options =====================================================================================

#[skuld::test]
fn config_path_found() {
    assert_eq!(
        config_path_from_plugin_options(Some("config=/etc/chain.yaml"))
            .unwrap()
            .path,
        "/etc/chain.yaml"
    );
    assert_eq!(
        config_path_from_plugin_options(Some("mode=quic;config=/etc/chain.yaml;path=/x"))
            .unwrap()
            .path,
        "/etc/chain.yaml"
    );
}

#[skuld::test]
fn config_path_missing_is_an_error() {
    assert!(config_path_from_plugin_options(None).is_err());
    assert!(config_path_from_plugin_options(Some("")).is_err());
    assert!(config_path_from_plugin_options(Some("mode=quic")).is_err());
    // A bare key or an explicitly empty value are both "no path named",
    // not "path is the empty string".
    assert!(config_path_from_plugin_options(Some("config")).is_err());
    assert!(config_path_from_plugin_options(Some("config=")).is_err());
}

#[skuld::test]
fn config_path_malformed_options_is_a_distinct_error() {
    let err = config_path_from_plugin_options(Some(r"config=/etc/chain.yaml;path=/a\")).unwrap_err();
    assert!(
        err.to_string().contains("malformed SS_PLUGIN_OPTIONS"),
        "expected a malformed-options error, got: {err}"
    );
}

#[skuld::test]
fn config_path_reports_mangling_with_corrected_spellings() {
    let config = config_path_from_plugin_options(Some(r"config=C:\Users\x\chain.yaml")).unwrap();
    assert_eq!(config.path, "C:Usersxchain.yaml");
    let mangled = config.mangled_from.expect("expected mangling to be detected");
    assert_eq!(mangled.doubled, r"C:\\Users\\x\\chain.yaml");
    assert_forward_slashes_platform_correct(&mangled, "C:/Users/x/chain.yaml");
}

// A forward-slash spelling only round-trips to the SAME path on Windows
// (which accepts both separators) — on Unix `\` is an ordinary filename
// byte, so it must not be offered as a "fix" there.
fn assert_forward_slashes_platform_correct(mangled: &MangledPath, expected_on_windows: &str) {
    if cfg!(windows) {
        assert_eq!(mangled.forward_slashes.as_deref(), Some(expected_on_windows));
    } else {
        assert!(
            mangled.forward_slashes.is_none(),
            "forward-slash spelling must not be offered off Windows, got {:?}",
            mangled.forward_slashes
        );
    }
}

#[skuld::test]
fn config_path_reports_no_mangling_for_a_correctly_escaped_path() {
    let config = config_path_from_plugin_options(Some(r"config=C:\\Users\\x\\chain.yaml")).unwrap();
    assert_eq!(config.path, r"C:\Users\x\chain.yaml");
    assert!(config.mangled_from.is_none());
}

// A Windows UNC path's leading `\\` is genuinely ambiguous SIP003 input
// (see `reconstruct_intended`'s doc comment) — this pins that it's read as
// two literal backslashes, not as one legitimate SIP003 escape.
#[skuld::test]
fn config_path_unc_prefix_keeps_both_leading_backslashes() {
    let config = config_path_from_plugin_options(Some(r"config=\\fileserver\share\chain.yaml")).unwrap();
    let mangled = config.mangled_from.expect("expected mangling to be detected");
    assert_eq!(mangled.doubled, r"\\\\fileserver\\share\\chain.yaml");
    assert_forward_slashes_platform_correct(&mangled, "//fileserver/share/chain.yaml");

    // The suggestion must round-trip back to the exact original UNC path.
    let doubled_opts = format!("config={}", mangled.doubled);
    let doubled_segments = garter::split_plugin_options(&doubled_opts).unwrap();
    assert_eq!(doubled_segments[0].value, r"\\fileserver\share\chain.yaml");
}

// The extended-length prefix `\\?\` starts the same way and must get the
// same treatment.
#[skuld::test]
fn config_path_extended_length_prefix_keeps_both_leading_backslashes() {
    let config = config_path_from_plugin_options(Some(r"config=\\?\C:\very\long\chain.yaml")).unwrap();
    let mangled = config.mangled_from.expect("expected mangling to be detected");
    let doubled_opts = format!("config={}", mangled.doubled);
    let doubled_segments = garter::split_plugin_options(&doubled_opts).unwrap();
    assert_eq!(doubled_segments[0].value, r"\\?\C:\very\long\chain.yaml");
}

// A partially-escaped value (one separator correctly doubled, the rest
// not) must not double-escape the already-correct part in its suggestion.
#[skuld::test]
fn config_path_mixed_escaping_suggests_the_fully_corrected_spelling() {
    let config = config_path_from_plugin_options(Some(r"config=C:\\shared\data\chain.yaml")).unwrap();
    assert_eq!(config.path, r"C:\shareddatachain.yaml");
    let mangled = config.mangled_from.expect("expected mangling to be detected");
    assert_eq!(mangled.doubled, r"C:\\shared\\data\\chain.yaml");
    assert_forward_slashes_platform_correct(&mangled, "C:/shared/data/chain.yaml");
}

// A suggestion must re-escape EVERY SIP003 metacharacter it decoded while
// reconstructing the intended path, not just `\` — otherwise it names a
// spelling that no longer round-trips through the shared decoder as ONE
// segment.
#[skuld::test]
fn config_path_mangled_suggestion_reescapes_semicolons_and_equals() {
    let config = config_path_from_plugin_options(Some(r"config=C:\dir\my\;chain.yaml")).unwrap();
    let mangled = config.mangled_from.expect("expected mangling to be detected");

    let doubled_opts = format!("config={}", mangled.doubled);
    let doubled_segments = garter::split_plugin_options(&doubled_opts)
        .unwrap_or_else(|e| panic!("doubled suggestion {:?} does not even parse: {e}", mangled.doubled));
    assert_eq!(
        doubled_segments.len(),
        1,
        "doubled suggestion {:?} split into more than one segment",
        mangled.doubled
    );
    assert_eq!(doubled_segments[0].value, r"C:\dir\my;chain.yaml");

    if cfg!(windows) {
        let fs = mangled
            .forward_slashes
            .as_deref()
            .expect("Windows must offer a forward-slash spelling");
        let forward_opts = format!("config={fs}");
        let forward_segments = garter::split_plugin_options(&forward_opts)
            .unwrap_or_else(|e| panic!("forward-slash suggestion {fs:?} does not even parse: {e}"));
        assert_eq!(
            forward_segments.len(),
            1,
            "forward-slash suggestion {fs:?} split into more than one segment"
        );
        assert_eq!(forward_segments[0].value, "C:/dir/my;chain.yaml");
    } else {
        assert!(mangled.forward_slashes.is_none());
    }
}

#[skuld::test]
fn config_path_first_wins_on_duplicate_key() {
    // ex-ray's Args.Get is first-wins; the FIRST config= must be the one
    // consulted.
    assert_eq!(
        config_path_from_plugin_options(Some("config=/first;config=/second"))
            .unwrap()
            .path,
        "/first"
    );
}

// load_config_or_explain_escaping =====================================================================================

#[skuld::test]
fn load_config_names_the_escaping_when_a_mangled_path_fails_to_load() {
    let config = ConfigPath {
        path: "C:Usersxchain.yaml".to_string(), // nonexistent, mangled
        mangled_from: Some(MangledPath {
            doubled: r"C:\\Users\\x\\chain.yaml".to_string(),
            forward_slashes: Some("C:/Users/x/chain.yaml".to_string()),
        }),
    };
    let err = load_config_or_explain_escaping(&config).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unescaped"),
        "expected the error to name escaping as the cause: {msg}"
    );
    assert!(
        msg.contains(r"C:\\Users\\x\\chain.yaml"),
        "expected the doubled-backslash suggestion: {msg}"
    );
    assert!(
        msg.contains("C:/Users/x/chain.yaml"),
        "expected the forward-slash suggestion: {msg}"
    );
}

// Off Windows (`forward_slashes: None`), only the doubled-backslash
// suggestion is offered — no misleading second spelling that would name a
// different path on that platform.
#[skuld::test]
fn load_config_offers_only_the_doubled_suggestion_when_forward_slashes_is_none() {
    let config = ConfigPath {
        path: "C:Usersxchain.yaml".to_string(), // nonexistent, mangled
        mangled_from: Some(MangledPath {
            doubled: r"C:\\Users\\x\\chain.yaml".to_string(),
            forward_slashes: None,
        }),
    };
    let err = load_config_or_explain_escaping(&config).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains(r"C:\\Users\\x\\chain.yaml"),
        "expected the doubled-backslash suggestion: {msg}"
    );
    assert!(
        !msg.contains(" or config="),
        "must not offer a second suggestion when forward_slashes is None: {msg}"
    );
}

#[skuld::test]
fn load_config_names_the_escaping_on_a_non_not_found_io_error() {
    // A directory, not a file: `read_to_string` fails with an OS-specific IO
    // error that is NOT `NotFound` (e.g. `IsADirectory`/`PermissionDenied`)
    // on every platform. The escaping explanation must still fire — it
    // covers any IO-layer failure on a known-mangled path, not just
    // "file not found".
    let dir_path = std::env::temp_dir();
    let config = ConfigPath {
        path: dir_path.to_string_lossy().into_owned(),
        mangled_from: Some(MangledPath {
            doubled: r"C:\\Users\\x\\chain.yaml".to_string(),
            forward_slashes: Some("C:/Users/x/chain.yaml".to_string()),
        }),
    };
    let err = load_config_or_explain_escaping(&config).unwrap_err();
    assert!(
        err.to_string().contains("unescaped"),
        "expected the error to name escaping as the cause for a non-NotFound IO error: {err}"
    );
}

#[skuld::test]
fn load_config_plain_error_when_the_path_was_not_mangled() {
    let config = ConfigPath {
        path: "/nonexistent/chain.yaml".to_string(),
        mangled_from: None,
    };
    let err = load_config_or_explain_escaping(&config).unwrap_err();
    assert!(
        !err.to_string().contains("unescaped"),
        "a legitimately doubled/clean path must not trigger the escaping explanation: {err}"
    );
}

#[skuld::test]
fn load_config_does_not_blame_escaping_for_a_yaml_parse_failure() {
    // A mangled path that coincidentally resolves to a REAL file with bad
    // YAML must not get the escaping explanation — that's not what went
    // wrong, and blaming it anyway sends the operator chasing the wrong fix.
    let path = std::env::temp_dir().join(format!(
        "garter-bin-escaping-test-{}-{}.yaml",
        std::process::id(),
        line!()
    ));
    std::fs::write(&path, "not: [valid: yaml").unwrap();
    let config = ConfigPath {
        path: path.to_string_lossy().into_owned(),
        mangled_from: Some(MangledPath {
            doubled: "unused".to_string(),
            forward_slashes: Some("unused".to_string()),
        }),
    };
    let err = load_config_or_explain_escaping(&config).unwrap_err();
    std::fs::remove_file(&path).ok();
    assert!(
        !err.to_string().contains("unescaped"),
        "a YAML-parse failure must not be blamed on escaping: {err}"
    );
}

// value_was_mangled_by_unescaping =====================================================================================

// The pure detector behind the escape warning, tested directly rather than
// via captured log output — see its doc comment for the false positive it
// avoids.
#[skuld::test]
fn value_was_mangled_by_unescaping_detects_only_the_defect() {
    let seg = |raw: &'static str| garter::split_plugin_options(raw).unwrap().into_iter().next().unwrap();
    // Mangled: a backslash escaping a byte with no SIP003 meaning.
    assert!(value_was_mangled_by_unescaping(&seg(r"config=C:\Users\x\chain.yaml")));
    // Correctly escaped backslash: legitimate, not mangled.
    assert!(!value_was_mangled_by_unescaping(&seg(
        r"config=C:\\Users\\x\\chain.yaml"
    )));
    // No backslash at all.
    assert!(!value_was_mangled_by_unescaping(&seg("config=/etc/chain.yaml")));
    // An escaped KEY spelling with a clean value is not a value defect.
    assert!(!value_was_mangled_by_unescaping(&seg(r"\config=/etc/chain.yaml")));
    // A correctly escaped `;` or `=` inside the value is legitimate too —
    // NOT the same as an unescaped literal backslash.
    assert!(!value_was_mangled_by_unescaping(&seg(r"config=/etc/a\;b.yaml")));
    assert!(!value_was_mangled_by_unescaping(&seg(r"config=/etc/a\=b.yaml")));
    // A bare key (no `=` at all) has no value to mangle.
    assert!(!value_was_mangled_by_unescaping(&seg("config")));
}

// reconstruct_intended ================================================================================================

#[skuld::test]
fn reconstruct_intended_leaves_a_correctly_escaped_value_unchanged_and_unflagged() {
    assert_eq!(
        reconstruct_intended(r"C:\\Users\\x\\chain.yaml").unwrap(),
        (r"C:\Users\x\chain.yaml".to_string(), false)
    );
}

#[skuld::test]
fn reconstruct_intended_detects_and_repairs_an_unescaped_backslash() {
    assert_eq!(
        reconstruct_intended(r"C:\Users\x\chain.yaml").unwrap(),
        (r"C:\Users\x\chain.yaml".to_string(), true)
    );
}

#[skuld::test]
fn reconstruct_intended_errors_on_a_dangling_trailing_escape() {
    assert_eq!(
        reconstruct_intended(r"C:\Users\x\chain.yaml\"),
        Err(garter::MalformedOptions::DanglingEscape)
    );
}

// The leading-pair ambiguity rule — see reconstruct_intended's doc comment.
#[skuld::test]
fn reconstruct_intended_leading_pair_is_literal_but_not_alone_mangled() {
    assert_eq!(
        reconstruct_intended(r"\\file.yaml").unwrap(),
        (r"\\file.yaml".to_string(), false)
    );
    // A defect ELSEWHERE in the same value still flags it, and the leading
    // pair is still reconstructed as literal.
    assert_eq!(
        reconstruct_intended(r"\\fileserver\share\chain.yaml").unwrap(),
        (r"\\fileserver\share\chain.yaml".to_string(), true)
    );
}

// Four-plus leading backslashes: normal per-pair detection, not the
// ambiguity rule — see reconstruct_intended's doc comment.
#[skuld::test]
fn reconstruct_intended_four_leading_backslashes_use_normal_detection() {
    assert_eq!(
        reconstruct_intended(r"\\\\server\\share\\file.yaml").unwrap(),
        (r"\\server\share\file.yaml".to_string(), false)
    );
}
