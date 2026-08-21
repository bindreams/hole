use std::cell::Cell;

use super::CoverHolder;

#[skuld::test]
fn cover_holder_reports_at_most_one_engaged_cover_kind() {
    let all = [
        CoverHolder::Nobody,
        CoverHolder::PendingStart,
        CoverHolder::Session { standing: false },
        CoverHolder::Session { standing: true },
    ];
    for holder in all {
        assert!(
            !(holder.standing_engaged() && holder.transient_engaged()),
            "standing_engaged and transient_engaged must never both be true: {holder:?}"
        );
    }
    assert!(!CoverHolder::Nobody.standing_engaged());
    assert!(!CoverHolder::Nobody.transient_engaged());
    assert!(!CoverHolder::Session { standing: false }.standing_engaged());
    assert!(!CoverHolder::Session { standing: false }.transient_engaged());
}

#[skuld::test]
fn cover_holder_probe_suppression_truth_table() {
    // Formula (the authority): suppresses = standing_engaged() ||
    // transient_engaged() || lockdown_intent(). The probe runs on exactly
    // the two rows where the holder engages no cover and the intent is off.
    let rows: [(CoverHolder, bool, bool); 8] = [
        (CoverHolder::Nobody, false, false),
        (CoverHolder::Nobody, true, true),
        (CoverHolder::PendingStart, false, true),
        (CoverHolder::PendingStart, true, true),
        (CoverHolder::Session { standing: false }, false, false),
        (CoverHolder::Session { standing: false }, true, true),
        (CoverHolder::Session { standing: true }, false, true),
        (CoverHolder::Session { standing: true }, true, true),
    ];
    for (holder, intent, expected) in rows {
        let actual = holder.suppresses_reachability_probe(|| intent);
        assert_eq!(
            actual, expected,
            "holder={holder:?} intent={intent} expected suppression={expected}, got {actual}"
        );
    }
}

#[skuld::test]
fn cover_holder_probe_suppression_does_not_read_the_intent_when_a_cover_is_held() {
    for (holder, expected_reads) in [
        (CoverHolder::Nobody, 1),
        (CoverHolder::PendingStart, 0),
        (CoverHolder::Session { standing: false }, 1),
        (CoverHolder::Session { standing: true }, 0),
    ] {
        let reads = Cell::new(0u32);
        let _ = holder.suppresses_reachability_probe(|| {
            reads.set(reads.get() + 1);
            false
        });
        assert_eq!(
            reads.get(),
            expected_reads,
            "holder={holder:?} must read the intent thunk exactly {expected_reads} time(s) when short-circuiting"
        );
    }
}

/// Structural guard, not a proof: it asserts there is exactly one `.field`-
/// access reader (`\.lockdown\b`) of the session's standing-cover field in
/// non-test bridge sources, and that the one reader is `Posture::cover_
/// holder`. Two evasions it does NOT catch: an added accessor that reads
/// the field under a different name, and a pattern-destructuring read
/// (`let RunningState { lockdown, .. } = state;` — the exact shape
/// `stop_with` already uses to CONSUME, not derive ownership from, this
/// same field) — neither has a leading `.` before `lockdown`, so the regex
/// is blind to both. Value-agreement tests cannot close either gap: a
/// second, independent derivation that agrees at every state they visit
/// still passes them.
#[skuld::test]
fn the_standing_cover_field_has_exactly_one_reader() {
    let pattern = regex::Regex::new(r"\.lockdown\b").unwrap();
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    let mut matches: Vec<(String, usize, String)> = Vec::new();
    for entry in walkdir::WalkDir::new(&src_root) {
        let entry = entry.expect("failed to walk crates/bridge/src");
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name.ends_with("_tests.rs") {
            continue;
        }
        if path.components().any(|c| c.as_os_str() == "test_support") {
            continue;
        }
        let text = std::fs::read_to_string(path).expect("failed to read a walked source file");
        for (line_no, line) in text.lines().enumerate() {
            if pattern.is_match(line) {
                matches.push((path.display().to_string(), line_no + 1, line.trim().to_string()));
            }
        }
    }

    let diagnostic = || {
        let mut msg = format!(
            "the_standing_cover_field_has_exactly_one_reader: pattern `{}` must match exactly once \
             in non-test bridge sources (skipping *_tests.rs and src/test_support/).\n\
             Matches found ({}):\n",
            pattern.as_str(),
            matches.len()
        );
        for (file, line_no, line) in &matches {
            msg.push_str(&format!("  {file}:{line_no}: {line}\n"));
        }
        msg.push_str(
            "A failure here means one of two things: either a second, independent derivation of \
             cover ownership was added somewhere (the real defect — the one sanctioned reader is \
             Posture::cover_holder), or a comment/doc string in a walked file now quotes the \
             pattern, which is a false positive and should be reworded. This regex only catches \
             `.field` access — a pattern-destructuring read (`let RunningState { lockdown, .. } \
             = ...;`) is invisible to it and would evade this guard entirely.",
        );
        msg
    };

    assert_eq!(matches.len(), 1, "{}", diagnostic());
    let (file, _, _) = &matches[0];
    assert!(
        file.ends_with("proxy_manager.rs"),
        "the one reader must be in proxy_manager.rs:\n{}",
        diagnostic()
    );
}
