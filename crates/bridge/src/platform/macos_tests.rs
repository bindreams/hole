use super::*;

#[skuld::test]
fn plist_contains_label() {
    let plist = generate_plist("/usr/local/bin/hole");
    assert!(plist.contains("com.hole.bridge"), "missing label in plist");
}

#[skuld::test]
fn plist_contains_binary_path() {
    let plist = generate_plist("/opt/hole/hole");
    assert!(plist.contains("/opt/hole/hole"), "missing binary path in plist");
}

#[skuld::test]
fn plist_has_bridge_run_args() {
    let plist = generate_plist("/usr/local/bin/hole");
    // ProgramArguments should include "bridge" and "run" as separate entries
    assert!(plist.contains("<string>bridge</string>"), "missing 'bridge' arg");
    assert!(plist.contains("<string>run</string>"), "missing 'run' arg");
}

#[skuld::test]
fn plist_has_run_at_load() {
    let plist = generate_plist("/usr/local/bin/hole");
    assert!(plist.contains("<key>RunAtLoad</key>"), "missing RunAtLoad");
    assert!(plist.contains("<true/>"), "RunAtLoad should be true");
}

#[skuld::test]
fn plist_has_keep_alive() {
    let plist = generate_plist("/usr/local/bin/hole");
    assert!(plist.contains("<key>KeepAlive</key>"), "missing KeepAlive");
}

#[skuld::test]
fn helper_path_is_stable() {
    assert_eq!(HELPER_PATH, "/Library/PrivilegedHelperTools/com.hole.bridge");
}
