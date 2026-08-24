/// Structural guard, not a proof: it asserts `routing::recover_routes(` appears
/// exactly once in non-test bridge sources, and that the one call is in
/// `route_recovery.rs`. Three entry points (`foreground`, `platform::windows`,
/// `platform::macos`) used to call it independently and discard its verdict;
/// the escape's visibility now depends on that verdict being recorded, so a
/// fourth ungated caller would be a silent regression rather than a
/// duplication.
///
/// Two evasions it does NOT catch, both by construction: a rename of
/// `recover_routes`, and a call routed through an alias or a re-export under a
/// different path. Modeled on `proxy_manager/cover_tests.rs`'s
/// `the_standing_cover_field_has_exactly_one_reader`, which documents the same
/// class of limitation.
#[skuld::test]
fn recover_routes_has_exactly_one_bridge_caller() {
    let pattern = regex::Regex::new(r"routing::recover_routes\(").unwrap();
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
            "recover_routes_has_exactly_one_bridge_caller: pattern `{}` must match exactly once \
             in non-test bridge sources (skipping *_tests.rs and src/test_support/).\n\
             Matches found ({}):\n",
            pattern.as_str(),
            matches.len()
        );
        for (file, line_no, line) in &matches {
            msg.push_str(&format!("  {file}:{line_no}: {line}\n"));
        }
        msg.push_str(
            "A failure here means a caller runs startup recovery without recording its verdict \
             on the ProxyManager, so an adopted standing cover would leave the tray's Unblock \
             item hidden and the connect path unaware that a live cover names the previous run's \
             TUN. The one sanctioned caller is route_recovery::recover_and_record. A comment \
             quoting the pattern is a false positive and should be reworded.",
        );
        msg
    };

    assert_eq!(matches.len(), 1, "{}", diagnostic());
    let (file, _, _) = &matches[0];
    assert!(
        file.ends_with("route_recovery.rs"),
        "the one caller must be in route_recovery.rs:\n{}",
        diagnostic()
    );
}
