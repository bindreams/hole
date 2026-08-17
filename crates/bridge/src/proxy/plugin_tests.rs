// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per clippy.toml's "Bridge cancellation contract" sanctioned-
// test-file exception.
#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;

use tokio_util::sync::CancellationToken;

use super::{proxy_err_to_io_err, start_plugin_chain};
use crate::proxy::ProxyError;

#[skuld::test]
async fn start_with_nonexistent_binary_returns_plugin_error() {
    let cancel = CancellationToken::new();
    let result = start_plugin_chain(
        "v2ray-plugin",
        "/nonexistent/binary",
        None,
        "127.0.0.1",
        12345,
        None,
        None,
        false,
        &cancel,
        None,
    )
    .await;

    let err = result.unwrap_err();
    assert!(
        matches!(err, ProxyError::Plugin(_)),
        "expected ProxyError::Plugin, got: {err:?}"
    );
}

// Bind-race classification (#414) =====================================================================================
//
// The load-bearing guarantee: a plugin-reported `StartError::BindConflict`
// (mapped to `ProxyError::BindRace` in `spawn_plugin_runner_at`) must be
// retryable on EVERY OS. `proxy_err_to_io_err` synthesizes an
// `AddrInUse`-kind `io::Error` directly (NOT via `from_raw_os_error`,
// which is platform-fragile), and `bind_ephemeral` retries when
// `util::retry::is_bind_race` returns true. These tests pin both
// halves: BindRace IS a bind race; Plugin / Cancelled are NOT.

fn dummy_addr() -> SocketAddr {
    "127.0.0.1:5300".parse().unwrap()
}

#[skuld::test]
fn bind_race_maps_to_retryable_addr_in_use_io_error() {
    // errno 0 (unknown) is the worst case — even with no host-native errno
    // the synthesized ErrorKind must still classify as a bind race.
    let io_err = proxy_err_to_io_err(ProxyError::BindRace {
        errno: 0,
        addr: dummy_addr(),
    });
    assert_eq!(
        io_err.kind(),
        std::io::ErrorKind::AddrInUse,
        "BindRace must synthesize an AddrInUse-kind io::Error"
    );
    assert!(
        util::retry::is_bind_race(&io_err),
        "BindRace io::Error must classify as a retryable bind race on every OS"
    );
}

#[skuld::test]
fn bind_race_with_nonzero_errno_still_retryable() {
    // A host-native errno (e.g. macOS 48, Windows 10048, Linux 98) must
    // not change the classification — it keys on ErrorKind, not errno.
    let io_err = proxy_err_to_io_err(ProxyError::BindRace {
        errno: 10048,
        addr: dummy_addr(),
    });
    assert!(util::retry::is_bind_race(&io_err));
    // The errno is preserved in the message for bridge.log diagnostics.
    assert!(
        io_err.to_string().contains("10048"),
        "errno should be preserved in the io::Error message, got: {io_err}"
    );
}

#[skuld::test]
fn plugin_error_is_not_a_bind_race() {
    let io_err = proxy_err_to_io_err(ProxyError::Plugin("upstream dial failed".into()));
    assert!(
        !util::retry::is_bind_race(&io_err),
        "ProxyError::Plugin must NOT classify as a bind race (terminal failure)"
    );
}

#[skuld::test]
fn cancelled_is_not_a_bind_race() {
    let io_err = proxy_err_to_io_err(ProxyError::Cancelled);
    assert!(
        !util::retry::is_bind_race(&io_err),
        "ProxyError::Cancelled must NOT classify as a bind race"
    );
}

// Plugin identity: spawn-time record, stop-time reap ==================================================================

mod identity {
    use super::super::{record_plugin_pid, PluginChain};
    use crate::plugin_state::{self, Loaded, STATE_FILE_NAME};
    use crate::test_support::reap_child::EchoChild;
    use tokio_util::sync::CancellationToken;

    fn synthetic_record() -> cosca::identity::ProcessIdRecord {
        cosca::identity::ProcessIdRecord {
            version: cosca::identity::RECORD_VERSION,
            platform: cosca::identity::Platform::Windows,
            pid: 4242,
            token: 133_700_000_000_000_000,
            boot_id: None,
            pid_ns: None,
        }
    }

    fn chain_over(dir: &std::path::Path) -> PluginChain {
        PluginChain::for_test(
            crate::proxy::plugin_log::PluginLog::new(),
            CancellationToken::new(),
            Some(dir.to_path_buf()),
        )
    }

    #[skuld::test]
    fn pid_sink_appends_a_resolved_childs_record() {
        let dir = tempfile::tempdir().unwrap();
        let child = EchoChild::spawn();

        record_plugin_pid(dir.path(), child.pid(), None);

        let Loaded::State(state) = plugin_state::load(dir.path()) else {
            panic!("the sink must have written a loadable state file");
        };
        assert_eq!(state.plugins.len(), 1, "one spawn, one record");
        let restored = cosca::identity::ProcessId::try_from(&state.plugins[0]).expect("the record must restore");
        assert_eq!(
            restored,
            child.identity(),
            "the record must be built from the child's resolved identity"
        );
    }

    #[skuld::test]
    fn pid_sink_appends_nothing_for_an_unresolvable_pid() {
        let dir = tempfile::tempdir().unwrap();

        record_plugin_pid(dir.path(), 999_999_999, None);

        assert!(
            !dir.path().join(STATE_FILE_NAME).exists(),
            "a pid that names nothing must not be recorded"
        );
    }

    #[skuld::test]
    async fn kill_tracked_kills_by_exact_identity() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = EchoChild::spawn();
        plugin_state::append_record(dir.path(), child.record(), None).unwrap();

        chain_over(dir.path()).kill_tracked();

        assert!(
            !child.echoes(),
            "the tracked process must not answer after kill_tracked"
        );
        assert!(
            !dir.path().join(STATE_FILE_NAME).exists(),
            "a reap that accounted for every record must clear the state file"
        );
    }

    #[skuld::test]
    async fn kill_tracked_spares_a_token_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let mut child = EchoChild::spawn();
        let mut record = child.record();
        record.token ^= 1;
        plugin_state::append_record(dir.path(), record, None).unwrap();

        chain_over(dir.path()).kill_tracked();

        assert!(
            child.echoes(),
            "a recycled pid must survive kill_tracked: the child stopped answering"
        );
    }

    #[skuld::test]
    async fn dropping_a_chain_does_not_delete_the_state_file() {
        let dir = tempfile::tempdir().unwrap();
        plugin_state::append_record(dir.path(), synthetic_record(), None).unwrap();

        drop(chain_over(dir.path()));

        assert!(
            dir.path().join(STATE_FILE_NAME).exists(),
            "Drop never accounted for these records, so it must not delete them"
        );
    }
}
