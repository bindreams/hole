use super::*;

#[skuld::test]
fn recover_when_no_state_file_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    // Should not panic, should not create any files.
    recover_dns_config(dir.path());
    assert!(!dir.path().join(dns_state::STATE_FILE_NAME).exists());
}

#[skuld::test]
fn recover_clears_state_file_after_restore() {
    let dir = tempfile::tempdir().unwrap();
    let state = dns_state::DnsState {
        version: dns_state::SCHEMA_VERSION,
        chosen_loopback: std::net::SocketAddr::from(([127, 0, 0, 1], 53)),
        // Empty adapters list — restore_all is a no-op so no platform
        // commands get invoked (safe in CI).
        adapters: Vec::new(),
    };
    dns_state::save(dir.path(), &state).unwrap();
    assert!(dir.path().join(dns_state::STATE_FILE_NAME).exists());
    recover_dns_config(dir.path());
    assert!(!dir.path().join(dns_state::STATE_FILE_NAME).exists());
}

#[skuld::test]
fn recover_wrong_version_leaves_state_file_alone() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 99,
        "chosen_loopback": "127.0.0.1:53",
        "adapters": [],
    });
    std::fs::write(dir.path().join(dns_state::STATE_FILE_NAME), json.to_string()).unwrap();
    recover_dns_config(dir.path());
    // load() returns None for wrong version → early exit → file intact.
    assert!(dir.path().join(dns_state::STATE_FILE_NAME).exists());
}
