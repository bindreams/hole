use super::*;
use hole_common::config::ServerEntry;
use hole_common::protocol::{ProxyConfig, TunnelMode};

use crate::plugin_state;
use crate::proxy_manager::proxy_manager_tests::{MockProxy, MockRouting};
use crate::proxy_manager::ProxyState;
use crate::target::{self, Target};
use crate::test_support::reap_child::EchoChild;
use crate::test_support::rt;
use std::sync::atomic::Ordering;
use tun_engine::routing::{CoverPresence, CoverRecovery, Recovery};

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

/// The boot reconcile must see the standing cover route recovery adopted. No
/// lockdown intent is on file (`Unset`), so only the adopted claim stops the
/// reconcile from releasing the live cover; recovery that runs after the
/// reconcile, or not at all, lets it release a cover the host still needs.
/// The real `recover_routes` needs elevation to find a live cover, so the
/// recovery verdict is injected; everything downstream of it is real.
#[skuld::test]
fn the_boot_reconcile_sees_the_cover_route_recovery_adopted() {
    rt().block_on(async {
        let dir = tempfile::tempdir().unwrap();
        target::save(dir.path(), &connectable(), None).unwrap();

        let routing = MockRouting::new(dir.path().to_path_buf());
        let routing_state = routing.state();
        *routing_state.cover_presence.lock().unwrap() = CoverPresence::Live;
        let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
        let proxy = Arc::new(Mutex::new(pm));
        #[allow(clippy::disallowed_methods)]
        // Test-side root token; production roots live at the three entry points.
        let cancel = CancellationToken::new();

        recover_then_reconcile_with(dir.path(), None, &proxy, &cancel, |_, _| Recovery {
            action: CoverRecovery::Adopt,
            record_intent_on: false,
            presence: CoverPresence::Live,
        })
        .await;

        assert_eq!(
            routing_state.release_all_calls.load(Ordering::SeqCst),
            0,
            "the reconcile released a live cover: route recovery's adopted claim was not recorded before it ran"
        );
        assert_eq!(proxy.lock().await.state(), ProxyState::Running);
    });
}

/// Every non-comment line of the production sources under `crates/bridge/src`
/// (not `*_tests.rs`, not `test_support/`), as (path relative to `src/` with
/// `/` separators, 1-based line number, line).
fn production_source_lines() -> Vec<(String, usize, String)> {
    let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut lines = Vec::new();
    for entry in walkdir::WalkDir::new(&src_root) {
        let entry = entry.expect("failed to walk crates/bridge/src");
        let path = entry.path();
        if !entry.file_type().is_file() || path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let rel = path
            .strip_prefix(&src_root)
            .expect("a walked file is under src")
            .to_string_lossy()
            .replace('\\', "/");
        if rel.ends_with("_tests.rs") || rel.starts_with("test_support/") {
            continue;
        }
        let text = std::fs::read_to_string(path).expect("failed to read a walked source file");
        for (i, line) in text.lines().enumerate() {
            if !line.trim_start().starts_with("//") {
                lines.push((rel.clone(), i + 1, line.to_owned()));
            }
        }
    }
    lines
}

/// Structural guard: the boot steps and the boot sequence itself are named
/// outside their sanctioned files by no call, bare or qualified, and no `use`
/// line, so an entry point cannot hand-write its own order.
/// `reap_recorded_plugins` is also called by `PluginChain::kill_tracked`.
/// Lexical: comment lines are skipped and a renamed path evades it.
#[skuld::test]
fn the_boot_steps_are_called_only_from_the_boot_sequence() {
    let entry_points = ["foreground.rs", "platform/macos.rs", "platform/windows.rs"];
    let steps: [(&str, Vec<&str>); 5] = [
        ("recover_and_record", vec!["boot.rs"]),
        ("reconcile_once", vec!["boot.rs"]),
        ("reap_recorded_plugins", vec!["boot.rs", "proxy/plugin.rs"]),
        ("recover_then_reconcile_with", vec!["boot.rs"]),
        (
            "recover_then_reconcile",
            vec!["boot.rs", entry_points[0], entry_points[1], entry_points[2]],
        ),
    ];
    let lines = production_source_lines();

    for (name, allowed) in steps {
        // A call (qualified or bare) or any `use` line naming the step; `\b`
        // keeps `recover_then_reconcile` apart from `recover_then_reconcile_with`.
        let pattern = regex::Regex::new(&format!(
            r"(\b{name}\b\s*\()|(^\s*(pub(\([a-z]+\))?\s+)?use\s.*\b{name}\b)"
        ))
        .expect("the step pattern is a valid regex");
        let definition = regex::Regex::new(&format!(r"\bfn\s+{name}\b")).expect("the definition pattern is valid");
        for (path, line_no, line) in &lines {
            let defines = definition.is_match(line);
            assert!(
                defines || !pattern.is_match(line) || allowed.contains(&path.as_str()),
                "{path}:{line_no}: `{name}` may be named only in {allowed:?}; boot::recover_then_reconcile \
                 owns the order of the boot steps"
            );
        }
    }
}

/// Structural guard: every bridge entry point runs the boot sequence exactly
/// once, as `boot::recover_then_reconcile(`, and names it no other way (a
/// `use` import or a bare call would hide it from the count). Lexical, like
/// the guard above.
#[skuld::test]
fn every_entry_point_runs_the_boot_sequence_once() {
    let name = regex::Regex::new(r"\brecover_then_reconcile\b").unwrap();
    let lines = production_source_lines();
    for entry_point in ["foreground.rs", "platform/macos.rs", "platform/windows.rs"] {
        let mentions: Vec<_> = lines
            .iter()
            .filter(|(path, _, line)| path == entry_point && name.is_match(line))
            .collect();
        for (path, line_no, line) in &mentions {
            assert!(
                line.contains("boot::recover_then_reconcile("),
                "{path}:{line_no}: the boot sequence may be named only as a `boot::recover_then_reconcile(` call"
            );
        }
        assert_eq!(
            mentions.len(),
            1,
            "{entry_point} must call boot::recover_then_reconcile exactly once"
        );
    }
}
