use super::*;
use hole_common::config::ServerEntry;
use hole_common::protocol::{ProxyConfig, TunnelMode};

use crate::plugin_state;
use crate::proxy_manager::proxy_manager_tests::{MockProxy, MockRouting};
use crate::proxy_manager::ProxyState;
use crate::target::{self, Target};
use crate::test_support::reap_child::EchoChild;
use crate::test_support::rt;

fn connectable() -> Target {
    Target::Connected {
        config: Box::new(ProxyConfig {
            server: ServerEntry {
                id: "test-id".into(),
                name: "test-server".into(),
                server: "127.0.0.1".into(),
                server_port: 8388,
                password: "super-secret-password".into(),
                method: "aes-256-gcm".into(),
                plugin: None,
                plugin_opts: None,
                validation: None,
            },
            local_port: 1080,
            tunnel_mode: TunnelMode::Full,
            filters: Vec::new(),
            dns: hole_common::config::DnsConfig {
                enabled: false,
                ..hole_common::config::DnsConfig::default()
            },
            proxy_socks5: true,
            proxy_http: false,
            local_port_http: 4074,
            diagnostic_plugin_tap: false,
        }),
    }
}

/// A boot whose persisted target auto-connects with a plugin must reap the
/// plugin a PREVIOUS bridge left recorded and spare the one the boot's own
/// session just started. The mock proxy records `session`'s identity where
/// production records a plugin's, as the session starts.
#[skuld::test]
fn the_boot_reap_spares_the_plugin_of_the_boot_auto_connect() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        target::save(dir.path(), &connectable(), None).unwrap();

        let mut leftover = EchoChild::spawn();
        plugin_state::append_record(dir.path(), leftover.record(), None).unwrap();

        let mut session = EchoChild::spawn();
        let session_record = session.record();
        let record_dir = dir.path().to_path_buf();
        let record = session_record.clone();
        let mock = MockProxy::new().with_start_hook(move || {
            plugin_state::append_record(&record_dir, record.clone(), None).unwrap();
        });
        let routing = MockRouting::new(dir.path().to_path_buf());
        let pm = ProxyManager::new(mock, routing).with_state_dir(dir.path().to_path_buf());
        let proxy = Arc::new(Mutex::new(pm));
        #[allow(clippy::disallowed_methods)]
        // Test-side root token; production roots live at the three entry points.
        let cancel = CancellationToken::new();

        recover_then_reconcile(dir.path(), None, &proxy, &cancel).await;

        assert_eq!(
            proxy.lock().await.state(),
            ProxyState::Running,
            "the persisted Connected target must have auto-connected"
        );
        assert!(!leftover.echoes(), "the previous bridge's plugin must be reaped");
        assert!(
            session.echoes(),
            "the plugin of the session this boot started must survive the boot reap"
        );
        match plugin_state::load(dir.path()) {
            plugin_state::Loaded::State(state) => assert_eq!(
                state.plugins,
                vec![session_record],
                "the state file must hold exactly the live session's record, so its stop can reap it"
            ),
            other => panic!("the live session's record must still be on file, got {other:?}"),
        }
    });
}

/// Structural guard: the three boot steps are called from `boot.rs` and nowhere
/// else, so an entry point cannot hand-write its own order. `reap_recorded_plugins`
/// has one further sanctioned caller, the chain-stop path
/// (`PluginChain::kill_tracked`). Lexical, like
/// `recover_routes_has_exactly_one_bridge_caller`: a rename or a re-export
/// under another path evades it, and comment lines are skipped.
#[skuld::test]
fn the_boot_steps_are_called_only_from_the_boot_sequence() {
    let steps: [(&str, &[&str]); 3] = [
        ("route_recovery::recover_and_record(", &["boot.rs"]),
        ("reconciler::reconcile_once(", &["boot.rs"]),
        ("plugin_recovery::reap_recorded_plugins(", &["boot.rs", "plugin.rs"]),
    ];
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");

    for entry in walkdir::WalkDir::new(&src_root) {
        let entry = entry.expect("failed to walk crates/bridge/src");
        let path = entry.path();
        if !entry.file_type().is_file() || path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file_name.ends_with("_tests.rs") || path.components().any(|c| c.as_os_str() == "test_support") {
            continue;
        }
        let text = std::fs::read_to_string(path).expect("failed to read a walked source file");
        for (line_no, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for (call, allowed) in steps {
                assert!(
                    !line.contains(call) || allowed.contains(&file_name),
                    "{}:{}: `{call}` may be called only from {allowed:?}; boot::recover_then_reconcile \
                     owns the order of the boot steps",
                    path.display(),
                    line_no + 1,
                );
            }
        }
    }
}
