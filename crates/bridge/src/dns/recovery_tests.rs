use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Mutex;

use super::*;
use crate::dns_state::{DnsPrior, DnsPriorAdapter, DnsState, SCHEMA_VERSION};

fn write_state(dir: &std::path::Path, state: &DnsState) {
    let json = serde_json::to_vec_pretty(state).unwrap();
    std::fs::write(dir.join(dns_state::STATE_FILE_NAME), json).unwrap();
}

// MockBackend (Windows) ===============================================================================================

#[cfg(target_os = "windows")]
mod win {
    use super::*;
    use crate::dns::system::windows::WinDnsBackend;

    /// A recording, fully-controllable `WinDnsBackend` for the upgrade
    /// sweep. `get_settings` returns whatever `live` says for the alias;
    /// `restore_family` records the call and can be told to fail.
    pub(super) struct MockBackend {
        pub(super) live: Mutex<std::collections::HashMap<String, DnsPriorAdapter>>,
        pub(super) restore_family_calls: AtomicUsize,
        pub(super) get_settings_calls: AtomicUsize,
        pub(super) fail_restore: std::sync::atomic::AtomicBool,
    }

    impl MockBackend {
        pub(super) fn new() -> Self {
            Self {
                live: Mutex::new(std::collections::HashMap::new()),
                restore_family_calls: AtomicUsize::new(0),
                get_settings_calls: AtomicUsize::new(0),
                fail_restore: std::sync::atomic::AtomicBool::new(false),
            }
        }

        pub(super) fn seed(&self, alias: &str, adapter: DnsPriorAdapter) {
            self.live.lock().unwrap().insert(alias.to_string(), adapter);
        }
    }

    impl WinDnsBackend for MockBackend {
        fn get_settings(&self, alias: &str) -> std::io::Result<Option<DnsPriorAdapter>> {
            self.get_settings_calls.fetch_add(1, SeqCst);
            Ok(self.live.lock().unwrap().get(alias).cloned())
        }

        fn set_servers(&self, _alias: &str, _servers: &[IpAddr]) -> std::io::Result<()> {
            unreachable!("the upgrade sweep never calls set_servers")
        }

        fn restore(&self, _adapter: &DnsPriorAdapter) -> std::io::Result<()> {
            unreachable!("the upgrade sweep restores per-family, never both at once")
        }

        fn restore_family(&self, alias: &str, ipv6: bool, prior: &DnsPrior) -> std::io::Result<()> {
            self.restore_family_calls.fetch_add(1, SeqCst);
            if self.fail_restore.load(SeqCst) {
                return Err(std::io::Error::other("mock restore_family failure"));
            }
            let mut live = self.live.lock().unwrap();
            if let Some(adapter) = live.get_mut(alias) {
                if ipv6 {
                    adapter.v6 = prior.clone();
                } else {
                    adapter.v4 = prior.clone();
                }
            }
            Ok(())
        }

        fn flush(&self) -> std::io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(target_os = "windows")]
use win::MockBackend;

fn v4(ip: (u8, u8, u8, u8)) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(ip.0, ip.1, ip.2, ip.3))
}

// Tests ===============================================================================================================

#[skuld::test]
fn recover_when_no_state_file_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    recover_dns_config(dir.path());
    assert!(!dir.path().join(dns_state::STATE_FILE_NAME).exists());
    assert!(!dir.path().join(dns_state::SUPERSEDED_FILE_NAME).exists());
}

#[skuld::test]
fn recover_clears_state_file_with_no_adapters() {
    // Empty adapters list is vacuously "every adapter settled" — matches
    // the pre-#846 behavior of clearing on a no-op restore.
    let dir = tempfile::tempdir().unwrap();
    let state = DnsState {
        version: SCHEMA_VERSION,
        advertised: vec![v4((1, 1, 1, 1))],
        adapters: Vec::new(),
    };
    write_state(dir.path(), &state);
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

#[cfg(target_os = "windows")]
#[skuld::test]
fn recover_dns_config_restores_a_pre_846_file() {
    let dir = tempfile::tempdir().unwrap();
    let advertised = vec![v4((1, 1, 1, 1)), v4((1, 0, 0, 1))];
    let prior = DnsPriorAdapter {
        id: AdapterId::WindowsAlias {
            value: "Ethernet".into(),
        },
        name_at_capture: "Ethernet".into(),
        v4: DnsPrior::Dhcp,
        v6: DnsPrior::None,
    };
    let state = DnsState {
        version: SCHEMA_VERSION,
        advertised: advertised.clone(),
        adapters: vec![prior.clone()],
    };
    write_state(dir.path(), &state);

    let backend = MockBackend::new();
    // Live v4 still equals `advertised` — the setting is still Hole's.
    backend.seed(
        "Ethernet",
        DnsPriorAdapter {
            id: prior.id.clone(),
            name_at_capture: "Ethernet".into(),
            v4: DnsPrior::Static { servers: advertised },
            v6: DnsPrior::None,
        },
    );

    recover_dns_config_with(dir.path(), &backend);

    assert_eq!(
        backend.restore_family_calls.load(SeqCst),
        1,
        "v4 must be restored once (v6 was already None == None, AlreadyCorrect, no write)"
    );
    assert!(
        !dir.path().join(dns_state::STATE_FILE_NAME).exists(),
        "a fully-confirmed restore must delete the file"
    );
    assert!(!dir.path().join(dns_state::SUPERSEDED_FILE_NAME).exists());
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn recover_dns_config_skips_an_adapter_that_moved_on() {
    let dir = tempfile::tempdir().unwrap();
    let advertised = vec![v4((1, 1, 1, 1))];
    let prior = DnsPriorAdapter {
        id: AdapterId::WindowsAlias {
            value: "Ethernet".into(),
        },
        name_at_capture: "Ethernet".into(),
        v4: DnsPrior::Static {
            servers: vec![v4((10, 0, 0, 1))],
        },
        v6: DnsPrior::None,
    };
    let state = DnsState {
        version: SCHEMA_VERSION,
        advertised: advertised.clone(),
        adapters: vec![prior.clone()],
    };
    write_state(dir.path(), &state);

    let backend = MockBackend::new();
    // Live v4 is neither `advertised` nor the recorded prior — a
    // different network entirely. Must not be touched.
    backend.seed(
        "Ethernet",
        DnsPriorAdapter {
            id: prior.id.clone(),
            name_at_capture: "Ethernet".into(),
            v4: DnsPrior::Static {
                servers: vec![v4((192, 168, 50, 1))],
            },
            v6: DnsPrior::None,
        },
    );

    recover_dns_config_with(dir.path(), &backend);

    assert_eq!(
        backend.restore_family_calls.load(SeqCst),
        0,
        "an adapter that moved on must never be written to"
    );
    assert!(
        dir.path().join(dns_state::STATE_FILE_NAME).exists()
            || dir.path().join(dns_state::SUPERSEDED_FILE_NAME).exists(),
        "the file must survive one way or the other — it is network-reset.py's only input"
    );
    assert!(
        !dir.path().join(dns_state::STATE_FILE_NAME).exists(),
        "an unconfirmed restore must not leave the un-suffixed name — it would be re-evaluated"
    );
    assert!(dir.path().join(dns_state::SUPERSEDED_FILE_NAME).exists());
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn recover_dns_config_preserves_a_file_with_no_advertised_evidence() {
    let dir = tempfile::tempdir().unwrap();
    // A file with NO `advertised` key loads as `[]` — no sound evidence.
    let json = serde_json::json!({
        "version": SCHEMA_VERSION,
        "adapters": [{
            "id": { "kind": "windows_alias", "value": "Ethernet" },
            "name_at_capture": "Ethernet",
            "v4": { "kind": "dhcp" },
            "v6": { "kind": "none" },
        }],
    });
    std::fs::write(dir.path().join(dns_state::STATE_FILE_NAME), json.to_string()).unwrap();

    let backend = MockBackend::new();
    backend.seed(
        "Ethernet",
        DnsPriorAdapter {
            id: AdapterId::WindowsAlias {
                value: "Ethernet".into(),
            },
            name_at_capture: "Ethernet".into(),
            v4: DnsPrior::Static {
                servers: vec![v4((1, 1, 1, 1))],
            },
            v6: DnsPrior::None,
        },
    );

    recover_dns_config_with(dir.path(), &backend);

    assert_eq!(
        backend.restore_family_calls.load(SeqCst),
        0,
        "no evidence means no write, regardless of what the live setting happens to be"
    );
    assert!(
        !dir.path().join(dns_state::STATE_FILE_NAME).exists(),
        "must not leave the un-suffixed name — R0-2: the inverted gate manufactured a lockout here"
    );
    assert!(
        dir.path().join(dns_state::SUPERSEDED_FILE_NAME).exists(),
        "must preserve the file (renamed) — it is still network-reset.py's only input"
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn recover_dns_config_never_evaluates_the_same_file_twice() {
    let dir = tempfile::tempdir().unwrap();
    let advertised = vec![v4((1, 1, 1, 1))];
    let prior = DnsPriorAdapter {
        id: AdapterId::WindowsAlias {
            value: "Ethernet".into(),
        },
        name_at_capture: "Ethernet".into(),
        v4: DnsPrior::Dhcp,
        v6: DnsPrior::None,
    };
    let state = DnsState {
        version: SCHEMA_VERSION,
        advertised: advertised.clone(),
        adapters: vec![prior],
    };
    write_state(dir.path(), &state);

    let backend = MockBackend::new();
    // Live v4 does NOT match `advertised` — first run preserves the file
    // (superseded), second run must not touch it again at all.
    backend.seed(
        "Ethernet",
        DnsPriorAdapter {
            id: AdapterId::WindowsAlias {
                value: "Ethernet".into(),
            },
            name_at_capture: "Ethernet".into(),
            v4: DnsPrior::Static {
                servers: vec![v4((8, 8, 8, 8))],
            },
            v6: DnsPrior::None,
        },
    );

    recover_dns_config_with(dir.path(), &backend);
    let get_calls_after_first = backend.get_settings_calls.load(SeqCst);
    assert!(get_calls_after_first > 0);

    // Second run: the un-suffixed name is gone, so `load` (which only ever
    // reads that name) must see nothing.
    recover_dns_config_with(dir.path(), &backend);
    assert_eq!(
        backend.get_settings_calls.load(SeqCst),
        get_calls_after_first,
        "a second run must not re-read the foreign adapter at all — the file was already evaluated once"
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn restore_gate_is_per_family() {
    // v4 matches the evidence and must restore; v6 holds the user's own
    // (never-Hole's) resolvers and must be left alone — and must not veto
    // the v4 restore.
    let dir = tempfile::tempdir().unwrap();
    let advertised = vec![v4((1, 1, 1, 1))]; // v4-only advertised (the shipped default shape)
    let prior = DnsPriorAdapter {
        id: AdapterId::WindowsAlias {
            value: "Ethernet".into(),
        },
        name_at_capture: "Ethernet".into(),
        v4: DnsPrior::Dhcp,
        v6: DnsPrior::Static {
            servers: vec!["2001:db8::1".parse().unwrap()],
        },
    };
    let state = DnsState {
        version: SCHEMA_VERSION,
        advertised,
        adapters: vec![prior.clone()],
    };
    write_state(dir.path(), &state);

    let backend = MockBackend::new();
    backend.seed(
        "Ethernet",
        DnsPriorAdapter {
            id: prior.id.clone(),
            name_at_capture: "Ethernet".into(),
            v4: DnsPrior::Static {
                servers: vec![v4((1, 1, 1, 1))],
            },
            // The user's OWN v6 resolver — Hole never advertised any v6,
            // so this family has no evidence and must not be touched.
            v6: DnsPrior::Static {
                servers: vec!["2001:db8::dead".parse().unwrap()],
            },
        },
    );

    recover_dns_config_with(dir.path(), &backend);

    assert_eq!(
        backend.restore_family_calls.load(SeqCst),
        1,
        "exactly the v4 family must be restored"
    );
    let live = backend.live.lock().unwrap();
    let adapter = live.get("Ethernet").unwrap();
    assert_eq!(adapter.v4, DnsPrior::Dhcp, "v4 must be restored to its recorded prior");
    assert_eq!(
        adapter.v6,
        DnsPrior::Static {
            servers: vec!["2001:db8::dead".parse().unwrap()]
        },
        "v6 (no evidence) must be left exactly as it was — never overwritten by the v4 verdict"
    );
}
