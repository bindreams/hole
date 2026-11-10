// `CancellationToken::new` is the cancel-test harness root; module-level
// allow per clippy.toml's "Bridge cancellation contract" sanctioned-
// test-file exception.
#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;

use tokio_util::sync::CancellationToken;

use super::{proxy_err_to_io_err, start_plugin_chain, ChainTask};
use crate::proxy::ProxyError;

/// A plugin that cannot be spawned fails the start, and the text a user reads names the plugin and not where it was
/// looked for: `user_message` shows garter's `Display`, and a directory under a person's tree is for the log. The
/// chain reports the hop's own spawn error (see `ChainRunner::run`), except on macOS, which cannot tell a failed `exec`
/// from a child that may run, so the stop is unconfirmed there.
#[skuld::test]
async fn start_with_nonexistent_binary_names_the_plugin_and_not_where_it_was_looked_for() {
    let dir = tempfile::Builder::new()
        .prefix("a-recognisable-dir-")
        .tempdir()
        .unwrap();
    let dir_name = dir.path().file_name().unwrap().to_string_lossy().into_owned();
    let path = dir.path().join("no-such-plugin");
    let cancel = CancellationToken::new();
    let result = start_plugin_chain(
        "v2ray-plugin",
        path.to_str().unwrap(),
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
    let expected = match cfg!(target_os = "macos") {
        // cosca reports a failed spawn on macOS as `Running { id: None }`, which is not proof the child is gone
        // (https://github.com/bindreams/cosca/issues/964).
        true => {
            assert!(matches!(err, ProxyError::PluginStopUnconfirmed(_)), "got: {err:?}");
            "plugin 'no-such-plugin' could not be confirmed stopped"
        }
        false => {
            assert!(matches!(err, ProxyError::PluginStartFailed(_)), "got: {err:?}");
            "could not spawn plugin 'no-such-plugin'"
        }
    };
    let message = err.user_message();
    assert!(message.ends_with(expected), "{message}");
    assert!(!message.contains(&dir_name), "{message}");
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

// ChainTask ownership =================================================================================================

/// Dropping a `ChainTask` signals shutdown and aborts the task, with no clock:
/// the token is read back, and a current-thread runtime processes the abort
/// before the test task resumes from one `yield_now`.
///
/// This is the cause the `tests/plugin_chain.rs` Drop tests guard end to end;
/// those go red only by taking ~a minute (a leaked chain ends on garter's own
/// bounds), this one fails by assertion.
#[skuld::test]
async fn dropping_a_chain_task_cancels_its_token_and_aborts_its_task() {
    let cancel = CancellationToken::new();
    let handle = tokio::spawn(std::future::pending::<garter::Result<()>>());
    let abort = handle.abort_handle();
    let task = ChainTask {
        handle,
        cancel: cancel.clone(),
    };
    assert!(!cancel.is_cancelled(), "the token starts unsignalled");
    assert!(!abort.is_finished(), "the task starts running");

    drop(task);
    tokio::task::yield_now().await;

    assert!(cancel.is_cancelled(), "Drop must signal the chain's shutdown token");
    assert!(abort.is_finished(), "Drop must abort the chain's task");
}

// Plugin identity: spawn-time record, stop-time reap ==================================================================

mod identity {
    use super::super::{record_plugin_pid, PluginChain};
    use crate::plugin_state::{self, STATE_FILE_NAME};
    use crate::proxy::UnrecordedCause;
    use crate::test_support::reap_child::EchoChild;
    use tokio_util::sync::CancellationToken;
    use util::versioned_file::Loaded;

    /// The identity of the test process itself: always alive, always resolvable.
    pub(super) fn own_identity() -> cosca::identity::ProcessId {
        match cosca::identity::ProcessId::of(std::process::id()) {
            cosca::identity::Resolved::Found(id) => id,
            other => panic!("the test process must resolve, got {other:?}"),
        }
    }

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

        record_plugin_pid(dir.path(), child.identity(), None).expect("a resolvable child is recorded");

        let Loaded::Current { value: state, .. } = plugin_state::load(dir.path()) else {
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
    fn an_unreadable_record_is_a_failure_and_is_left_as_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let corrupt = b"not json";
        std::fs::write(dir.path().join(STATE_FILE_NAME), corrupt).unwrap();

        let result = record_plugin_pid(dir.path(), own_identity(), None);

        assert!(matches!(result, Err(UnrecordedCause::Persist(_))), "got: {result:?}");
        assert_eq!(std::fs::read(dir.path().join(STATE_FILE_NAME)).unwrap(), corrupt);
    }

    #[skuld::test]
    fn a_record_that_cannot_be_written_is_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        // A state dir under a file: `create_dir_all` cannot succeed, so no write can land.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();

        let result = record_plugin_pid(&blocker.join("state"), own_identity(), None);

        assert!(matches!(result, Err(UnrecordedCause::Persist(_))), "got: {result:?}");
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

// Recording sink ======================================================================================================

mod recording_sink {
    use super::super::recording_sink;
    use crate::proxy::UnrecordedCause;

    fn unwritable_state_dir(dir: &std::path::Path) -> std::path::PathBuf {
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        blocker.join("state")
    }

    /// A child that cannot be recorded can never be reaped after a crash, so the sink refuses it: garter takes the
    /// child down. The sink's error carries the reason.
    #[skuld::test]
    fn a_failed_record_refuses_the_child_and_carries_the_cause() {
        let dir = tempfile::tempdir().unwrap();
        let sink = recording_sink(unwritable_state_dir(dir.path()), None);

        let refused = sink(super::identity::own_identity()).expect_err("an unwritable record must refuse");

        assert!(
            matches!(
                util::error::find::<UnrecordedCause>(&*refused),
                Some(UnrecordedCause::Persist(_))
            ),
            "got: {refused:?}"
        );
    }

    #[skuld::test]
    fn a_recorded_child_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let child = crate::test_support::reap_child::EchoChild::spawn();
        let sink = recording_sink(dir.path().to_path_buf(), None);

        sink(child.identity()).expect("a resolvable child is recorded");
    }
}

// Ending a chain ======================================================================================================

mod stopping {
    use super::super::{start_failure_of, stopped_by_start, ChainTask};
    use crate::proxy::plugin_log::PluginLog;
    use crate::proxy::ProxyError;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    fn task_over(
        cancel: CancellationToken,
        run: impl std::future::Future<Output = garter::Result<()>> + Send + 'static,
    ) -> ChainTask {
        ChainTask {
            handle: tokio::spawn(run),
            cancel,
        }
    }

    /// A chain that ends with `result` once it is cancelled.
    fn chain_ending_with(result: garter::Result<()>) -> ChainTask {
        let cancel = CancellationToken::new();
        task_over(cancel.clone(), {
            let cancel = cancel.clone();
            async move {
                cancel.cancelled().await;
                result
            }
        })
    }

    fn unconfirmed() -> garter::Error {
        garter::Error::StopUnconfirmed {
            plugins: vec!["p".into()],
            cause: "test: the root kill was refused".into(),
        }
    }

    /// `stop` returns what the chain returned, and only once the chain's own task has ended: nothing the chain does
    /// is still to happen, and nothing was cut short.
    #[skuld::test]
    async fn stop_cancels_the_chain_and_returns_what_it_returned_once_it_ended() {
        let cancel = CancellationToken::new();
        let ended = Arc::new(AtomicBool::new(false));
        let task = task_over(cancel.clone(), {
            let cancel = cancel.clone();
            let ended = ended.clone();
            async move {
                cancel.cancelled().await;
                // A turn of the scheduler an abort would not have waited for.
                tokio::task::yield_now().await;
                ended.store(true, Ordering::SeqCst);
                Err(garter::Error::Chain("the chain's own result".into()))
            }
        });

        let result = task.stop().await;

        assert!(ended.load(Ordering::SeqCst), "the chain was not allowed to finish");
        assert!(matches!(result, Err(garter::Error::Chain(msg)) if msg == "the chain's own result"));
    }

    /// A panic in `ChainRunner::run` is garter's bug: it is not reported as a start failure.
    #[skuld::test]
    async fn stop_resumes_the_panic_of_a_chain_that_panicked() {
        let cancel = CancellationToken::new();
        let task = task_over(cancel.clone(), async move {
            cancel.cancelled().await;
            panic!("the chain panicked");
        });

        let joined = tokio::spawn(task.stop()).await;

        assert!(joined.is_err_and(|e| e.is_panic()), "the panic must be resumed");
    }

    // The error a failed chain becomes --------------------------------------------------------------------------------

    fn start_failed(cause: garter::StartError) -> garter::Error {
        garter::Error::StartFailed {
            plugin: "ex-ray".into(),
            cause,
        }
    }

    /// A chain result, the start failure it must map to, and whether the plugin's last lines follow it.
    type Row = (&'static str, garter::Result<()>, fn(&ProxyError) -> bool, bool);

    /// Every garter error has exactly one start failure, and only a bind race says nothing of the plugin's output
    /// (it is retried). A chain that ended `Ok` without readying exited before it was ready.
    #[skuld::test]
    fn each_chain_result_maps_to_one_start_failure() {
        use tracing_subscriber::layer::{Layer, SubscriberExt};

        let fatal = || garter::StartError::Fatal {
            detail: "the dial failed".into(),
            errno: None,
        };
        let bind_conflict = || garter::StartError::BindConflict {
            errno: 98,
            addr: super::dummy_addr(),
        };
        let table: Vec<Row> = vec![
            (
                "bind conflict",
                Err(start_failed(bind_conflict())),
                |e| matches!(e, ProxyError::BindRace { errno: 98, .. }),
                false,
            ),
            (
                "fatal start",
                Err(start_failed(fatal())),
                |e| {
                    matches!(
                        e,
                        ProxyError::PluginStartFailed(garter::Error::StartFailed {
                            cause: garter::StartError::Fatal { detail, .. },
                            ..
                        }) if detail == "the dial failed"
                    )
                },
                true,
            ),
            (
                "refused pid sink",
                Err(garter::Error::PidSink {
                    plugin: "ex-ray".into(),
                    cause: "no".into(),
                }),
                |e| matches!(e, ProxyError::PluginUnrecorded(garter::Error::PidSink { .. })),
                true,
            ),
            (
                "unconfirmed stop",
                Err(unconfirmed()),
                |e| {
                    matches!(
                        e,
                        ProxyError::PluginStopUnconfirmed(garter::Error::StopUnconfirmed { .. })
                    )
                },
                true,
            ),
            (
                "spawn failure",
                Err(garter::Error::Spawn {
                    plugin: "ex-ray".into(),
                    cause: "no".into(),
                }),
                |e| matches!(e, ProxyError::PluginStartFailed(garter::Error::Spawn { plugin, .. }) if plugin == "ex-ray"),
                true,
            ),
            (
                "tap failure",
                Err(garter::Error::Tap {
                    plugin: "ex-ray".into(),
                    step: garter::TapStep::BindListener,
                    cause: std::io::Error::other("no"),
                }),
                |e| matches!(e, ProxyError::PluginStartFailed(garter::Error::Tap { plugin, .. }) if plugin == "ex-ray"),
                true,
            ),
            (
                "resolve failure",
                Err(garter::Error::Resolve {
                    server: "example.com:443".into(),
                    cause: None,
                }),
                |e| matches!(e, ProxyError::PluginStartFailed(garter::Error::Resolve { server, .. }) if server == "example.com:443"),
                true,
            ),
            (
                "another chain error",
                Err(garter::Error::Chain("failed to spawn".into())),
                |e| matches!(e, ProxyError::PluginStartFailed(garter::Error::Chain(msg)) if msg == "failed to spawn"),
                true,
            ),
            (
                "no error",
                Ok(()),
                |e| matches!(e, ProxyError::Plugin(msg) if msg == "plugin exited before becoming ready"),
                true,
            ),
        ];
        for (label, ended, is_expected, says_lines) in table {
            let log = PluginLog::new();
            let writer = crate::test_support::log_capture::VecWriter::new();
            let subscriber = tracing_subscriber::registry().with(
                tracing_subscriber::fmt::layer()
                    .with_writer(writer.clone())
                    .with_ansi(false)
                    .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
            );
            let error = {
                let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
                start_failure_of(ended, &log)
            };

            assert!(is_expected(&error), "{label}: got {error:?}");
            let said = !writer.snapshot_string().is_empty();
            assert_eq!(said, says_lines, "{label}: {}", writer.snapshot_string());
        }
    }

    /// Hole gave the start up: a stop garter confirms leaves hole's own error, built only then.
    #[skuld::test]
    async fn a_start_hole_gave_up_reports_its_own_error_when_the_stop_is_confirmed() {
        let log = PluginLog::new();
        let outcomes = [
            Ok(()),
            Err(garter::Error::PluginKilled { name: "p".into() }),
            Err(garter::Error::Cosca(cosca::error::Error::Io(
                std::io::ErrorKind::PermissionDenied.into(),
            ))),
        ];
        for outcome in outcomes {
            let label = format!("{outcome:?}");

            let error = stopped_by_start(chain_ending_with(outcome), || ProxyError::Cancelled, &log).await;

            assert!(matches!(error, ProxyError::Cancelled), "{label}: got {error:?}");
        }
    }

    /// An unconfirmed stop and a refused pid sink are louder than the reason hole gave up, and hole's error is then
    /// never built.
    #[skuld::test]
    async fn a_start_hole_gave_up_reports_an_outranking_error_instead() {
        let log = PluginLog::new();
        type Expected = fn(&ProxyError) -> bool;
        let table: Vec<(garter::Error, Expected)> = vec![
            (unconfirmed(), |e| matches!(e, ProxyError::PluginStopUnconfirmed(_))),
            (super::pid_sink_error(), |e| {
                matches!(e, ProxyError::PluginUnrecorded(_))
            }),
        ];
        for (outranking, is_expected) in table {
            let label = format!("{outranking:?}");

            let error = stopped_by_start(
                chain_ending_with(Err(outranking)),
                || panic!("hole's own error must not be built"),
                &log,
            )
            .await;

            assert!(is_expected(&error), "{label}: got: {error:?}");
        }
    }
}

// Typed error through `bind_ephemeral` ================================================================================

fn unrecorded_cause() -> crate::proxy::UnrecordedCause {
    crate::proxy::UnrecordedCause::NotPersistable(cosca::error::Error::Io(std::io::ErrorKind::InvalidData.into()))
}

fn pid_sink_error() -> garter::Error {
    garter::Error::PidSink {
        plugin: "ex-ray".into(),
        cause: Box::new(unrecorded_cause()),
    }
}

fn stop_unconfirmed_error() -> garter::Error {
    garter::Error::StopUnconfirmed {
        plugins: vec!["ex-ray".into()],
        cause: "kill refused".into(),
    }
}

/// Every variant a start can fail with rides inside the `io::Error` `bind_ephemeral` classifies, and comes back out
/// as itself; only a bind race is retried.
#[skuld::test]
fn every_start_failure_keeps_its_type_through_the_io_error_round_trip() {
    let table: Vec<(ProxyError, bool)> = vec![
        (
            ProxyError::BindRace {
                errno: 98,
                addr: dummy_addr(),
            },
            true,
        ),
        (ProxyError::Plugin("p".into()), false),
        (ProxyError::Cancelled, false),
        (ProxyError::PluginUnrecorded(pid_sink_error()), false),
        (ProxyError::PluginStopUnconfirmed(stop_unconfirmed_error()), false),
        // A variant the start never emits still survives: no variant is special-cased.
        (ProxyError::TunnelRequiresSocks5, false),
    ];
    for (error, retried) in table {
        let label = format!("{error:?}");

        let io_err = proxy_err_to_io_err(error);

        assert_eq!(util::retry::is_bind_race(&io_err), retried, "{label}");
        let restored = super::into_typed(io_err).unwrap_or_else(|_| panic!("{label}: the ProxyError rides inside"));
        assert_eq!(format!("{restored:?}"), label, "{label}: restored as itself");
    }
}

#[skuld::test]
fn an_io_error_that_carries_no_proxy_error_is_not_restored() {
    assert!(super::into_typed(std::io::Error::other("plain")).is_err());
}

/// A typed failure is the start's failure whatever the state of the start's cancel: the mapping takes no cancel, so a
/// loud failure (a plugin that may still run) cannot be relabelled `Cancelled` by one.
#[skuld::test]
fn a_typed_start_failure_is_restored_as_itself() {
    let log = crate::proxy::plugin_log::PluginLog::new();
    let unconfirmed = ProxyError::PluginStopUnconfirmed(stop_unconfirmed_error());

    let restored = super::start_failure(proxy_err_to_io_err(unconfirmed), &log);

    assert!(
        matches!(restored, ProxyError::PluginStopUnconfirmed(_)),
        "got: {restored:?}"
    );
    let cancelled = super::start_failure(proxy_err_to_io_err(ProxyError::Cancelled), &log);
    assert!(matches!(cancelled, ProxyError::Cancelled), "got: {cancelled:?}");
}

/// An error `bind_ephemeral` raised itself (the port probe, not the plugin) is carried as the `io::Error` it is.
#[skuld::test]
fn a_failure_with_no_proxy_error_is_carried_as_its_io_error() {
    let log = crate::proxy::plugin_log::PluginLog::new();

    let err = super::start_failure(std::io::Error::other("probe failed"), &log);

    assert!(
        matches!(&err, ProxyError::PluginPort(io) if io.to_string() == "probe failed"),
        "got: {err:?}"
    );
}

// Error chains ========================================================================================================

/// The type rule: a variant's `Display` never formats its `source()`, and everything it holds is reachable from it. A
/// consumer finds the sink's own error type from the start failure.
#[skuld::test]
fn a_start_failure_displays_its_own_text_and_chains_its_causes() {
    let unrecorded = ProxyError::PluginUnrecorded(garter::Error::PidSink {
        plugin: "ex-ray".into(),
        cause: Box::new(crate::proxy::UnrecordedCause::NotPersistable(cosca::error::Error::Io(
            std::io::Error::other("the-os-text"),
        ))),
    });
    assert_eq!(
        unrecorded.to_string(),
        "a plugin process could not be recorded, so it was stopped"
    );
    assert!(
        util::error::chain(&unrecorded).any(|link| link.to_string().contains("the-os-text")),
        "the cause is in the chain"
    );
    assert!(
        util::error::find::<crate::proxy::UnrecordedCause>(&unrecorded).is_some(),
        "the sink's error type is found through the chain"
    );

    let running = ProxyError::PluginStopUnconfirmed(garter::Error::StopUnconfirmed {
        plugins: vec!["p".into()],
        cause: Box::new(garter::Error::Chain("kill refused".into())),
    });
    assert!(
        !running.to_string().contains("kill refused"),
        "the stop is not in the text: {running}"
    );
    assert!(
        util::error::chain(&running).any(|link| link.to_string().contains("kill refused")),
        "the stop is in the chain"
    );
}
