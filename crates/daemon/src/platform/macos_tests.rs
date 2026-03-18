use super::*;

#[skuld::test]
fn plist_contains_label() {
    let plist = generate_plist("/usr/local/bin/hole-daemon");
    assert!(plist.contains("com.hole.daemon"), "missing label in plist");
}

#[skuld::test]
fn plist_contains_binary_path() {
    let plist = generate_plist("/opt/hole/hole-daemon");
    assert!(plist.contains("/opt/hole/hole-daemon"), "missing binary path in plist");
}

#[skuld::test]
fn plist_has_run_at_load() {
    let plist = generate_plist("/usr/local/bin/hole-daemon");
    assert!(plist.contains("<key>RunAtLoad</key>"), "missing RunAtLoad");
    // RunAtLoad should be true
    assert!(plist.contains("<true/>"), "RunAtLoad should be true");
}

#[skuld::test]
fn plist_has_keep_alive() {
    let plist = generate_plist("/usr/local/bin/hole-daemon");
    assert!(plist.contains("<key>KeepAlive</key>"), "missing KeepAlive");
}
