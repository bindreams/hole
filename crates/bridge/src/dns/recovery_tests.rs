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
        advertised: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))],
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
        "advertised": ["1.1.1.1"],
        "adapters": [],
    });
    std::fs::write(dir.path().join(dns_state::STATE_FILE_NAME), json.to_string()).unwrap();
    recover_dns_config(dir.path());
    // load() returns None for wrong version → early exit → file intact.
    assert!(dir.path().join(dns_state::STATE_FILE_NAME).exists());
}

/// Backward-compat: a `bridge-dns.json` persisted by a pre-Phase-4 binary
/// could contain a TUN adapter entry (old code captured both TUN and
/// upstream; Phase 4 captures upstream only). On recovery after an upgrade,
/// the TUN adapter from the crashed run no longer exists — `restore_all`
/// must log-and-continue per-adapter rather than crashing. This test pins
/// that behavior so a future refactor doesn't regress it.
#[cfg(any(target_os = "windows", target_os = "macos"))]
#[skuld::test]
fn recover_tolerates_legacy_state_file_with_tun_entry() {
    use crate::dns_state::{AdapterId, DnsPrior, DnsPriorAdapter, DnsState, SCHEMA_VERSION};

    let dir = tempfile::tempdir().unwrap();

    // Adapter id uses the platform shape. `hole-tun` on Windows,
    // `hole-tun-service` stand-in on macOS — the test only exercises
    // the "load + iterate + log-continue" shape, not the platform
    // restore payload itself.
    #[cfg(target_os = "windows")]
    let tun_id = AdapterId::WindowsAlias {
        value: "hole-tun".into(),
    };
    #[cfg(target_os = "macos")]
    let tun_id = AdapterId::MacosServiceName {
        value: "hole-tun-service".into(),
    };

    let legacy_state = DnsState {
        version: SCHEMA_VERSION,
        advertised: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))],
        adapters: vec![DnsPriorAdapter {
            id: tun_id,
            name_at_capture: "hole-tun".into(),
            v4: DnsPrior::None,
            v6: DnsPrior::None,
        }],
    };
    dns_state::save(dir.path(), &legacy_state).unwrap();

    // Should not panic; should clear the file regardless of whether the
    // TUN restore succeeded (it won't — there's no TUN adapter to
    // restore onto, but `restore_all` logs-and-continues).
    recover_dns_config(dir.path());

    assert!(
        !dir.path().join(dns_state::STATE_FILE_NAME).exists(),
        "state file should be cleared even when TUN restore fails"
    );
}

/// crash+upgrade recovery: a `bridge-dns.json` left by a crashed older
/// binary uses the OLD shape (`version: 1`, scalar `chosen_loopback`,
/// no `advertised`). The new binary MUST still load it and restore
/// the user's OS DNS from `adapters` — otherwise the user is stranded with
/// OS DNS stuck at a dead `127.0.0.1`. This pins that `DnsState` stays
/// version 1 + tolerant (no `deny_unknown_fields`, `advertised` defaults),
/// so a naive version bump that rejects the v1 file is caught here.
#[cfg(any(target_os = "windows", target_os = "macos"))]
#[skuld::test]
fn recover_v1_state_file_restores_adapters_after_upgrade() {
    let dir = tempfile::tempdir().unwrap();

    // Platform-shaped adapter id, mirroring
    // `recover_tolerates_legacy_state_file_with_tun_entry`. The adapter
    // won't exist on the CI host, so `restore_all` log-and-continues — the
    // test exercises "load v1 file + iterate adapters + clear file", not a
    // real OS restore payload.
    #[cfg(target_os = "windows")]
    let id = serde_json::json!({ "kind": "windows_alias", "value": "hole-recover-test-xyz" });
    #[cfg(target_os = "macos")]
    let id = serde_json::json!({ "kind": "macos_service_name", "value": "hole-recover-test-xyz" });

    // OLD v1 on-disk shape — what an older binary wrote.
    let v1_json = serde_json::json!({
        "version": 1,
        "chosen_loopback": "127.0.0.1:53",
        "adapters": [{
            "id": id,
            "name_at_capture": "hole-recover-test-xyz",
            "v4": { "kind": "dhcp" },
            "v6": { "kind": "none" },
        }],
    });
    std::fs::write(dir.path().join(dns_state::STATE_FILE_NAME), v1_json.to_string()).unwrap();

    // Sanity: the v1 file loads despite the obsolete `chosen_loopback` key
    // and missing `advertised`, with `adapters` intact (recovery's input).
    let loaded = dns_state::load(dir.path()).expect("v1 file must load post-upgrade");
    assert!(
        loaded.advertised.is_empty(),
        "advertised defaults to empty for a v1 file"
    );
    assert_eq!(loaded.adapters.len(), 1, "the adapter to restore must survive the load");

    // Recovery restores from `adapters` and clears the file on success.
    recover_dns_config(dir.path());
    assert!(
        !dir.path().join(dns_state::STATE_FILE_NAME).exists(),
        "v1 leaked state must be recovered (loaded + restored + cleared), not discarded"
    );
}
