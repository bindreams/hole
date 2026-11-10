use crate::error::{Error, TapStep};

#[skuld::test]
fn io_error_converts_and_keeps_the_io_error_as_its_source() {
    use std::error::Error as _;

    let io_err = std::io::Error::new(std::io::ErrorKind::AddrInUse, "port taken");
    let err: Error = io_err.into();
    assert!(matches!(err, Error::Io(_)));
    assert_eq!(err.to_string(), "an I/O operation of the plugin chain failed");
    assert_eq!(
        err.source().expect("the io error is the source").to_string(),
        "port taken"
    );
}

#[skuld::test]
fn plugin_exit_error_displays_name_and_code() {
    let err = Error::PluginExit {
        name: "v2ray-plugin".into(),
        code: 42,
    };
    assert_eq!(err.to_string(), "plugin 'v2ray-plugin' exited with code 42");
}

#[skuld::test]
fn plugin_killed_error_displays_name() {
    let err = Error::PluginKilled { name: "yamux".into() };
    assert_eq!(err.to_string(), "plugin 'yamux' was killed by signal");
}

#[skuld::test]
fn chain_error_displays_message() {
    let err = Error::Chain("port allocation failed".into());
    assert_eq!(err.to_string(), "port allocation failed");
}

#[skuld::test]
fn env_error_displays_var_and_reason() {
    let err = Error::Env {
        var: "SS_LOCAL_PORT".into(),
        reason: "not set".into(),
        cause: None,
    };
    assert_eq!(
        err.to_string(),
        "environment variable 'SS_LOCAL_PORT' missing or invalid: not set"
    );
}

#[skuld::test]
fn start_failed_error_displays_plugin_and_cause() {
    let err = Error::StartFailed {
        plugin: "v2ray-plugin".into(),
        cause: crate::StartError::BindConflict {
            errno: 98,
            addr: "127.0.0.1:1080".parse().unwrap(),
        },
    };
    assert_eq!(
        err.to_string(),
        "plugin 'v2ray-plugin' failed to start: bind conflict on 127.0.0.1:1080 (errno 98)"
    );
}

/// `Display` is what a user reads, so no error prints its `source()`, which is where paths and other crates' text live.
#[skuld::test]
fn display_never_prints_a_source() {
    use std::error::Error as _;

    const MARKER: &str = "C:/Users/someone/a-path-marker";
    let source = || std::io::Error::other(MARKER);
    let errors = [
        Error::Io(source()),
        Error::Cosca(cosca::error::Error::Io(source())),
        Error::Spawn {
            plugin: "p".into(),
            cause: Box::new(source()),
        },
        Error::PidSink {
            plugin: "p".into(),
            cause: Box::new(source()),
        },
        Error::StopUnconfirmed {
            plugins: vec!["p".into()],
            cause: Box::new(source()),
        },
        Error::Tap {
            plugin: "p".into(),
            step: TapStep::BindListener,
            cause: source(),
        },
        Error::Env {
            var: "V".into(),
            reason: "could not be parsed".into(),
            cause: Some(Box::new(source())),
        },
        Error::Resolve {
            server: "example.com:443".into(),
            cause: Some(source()),
        },
    ];
    for error in errors {
        assert!(!error.to_string().contains(MARKER), "{error:?}: {error}");
        assert!(
            error.source().is_some_and(|s| s.to_string().contains(MARKER)),
            "{error:?} lost its source"
        );
    }
}

/// Each step of a tap's start reads as a sentence naming the plugin; the OS error is the source.
#[skuld::test]
fn a_tap_failure_names_its_plugin_and_its_step() {
    use std::error::Error as _;

    for (step, text) in [
        (TapStep::AllocateInnerPort, "allocate an inner port"),
        (TapStep::BindListener, "bind its listener"),
        (TapStep::ReadListenerAddress, "read its listener's address"),
        (TapStep::AcceptConnection, "accept a connection"),
    ] {
        let err = Error::Tap {
            plugin: "ex-ray".into(),
            step,
            cause: std::io::Error::other("os said no"),
        };

        assert_eq!(err.to_string(), format!("the tap of plugin 'ex-ray' could not {text}"));
        assert_eq!(err.source().expect("the cause is the source").to_string(), "os said no");
        assert!(err.stop_confirmed());
    }
}

/// A failed lookup and an empty one both name the server, and only the lookup has a cause.
#[skuld::test]
fn a_resolve_failure_names_the_server() {
    use std::error::Error as _;

    let lookup = Error::Resolve {
        server: "example.com:443".into(),
        cause: Some(std::io::Error::other("dns said no")),
    };
    let empty = Error::Resolve {
        server: "example.com:443".into(),
        cause: None,
    };

    assert_eq!(lookup.to_string(), "could not resolve the server example.com:443");
    assert_eq!(empty.to_string(), "could not resolve the server example.com:443");
    assert_eq!(lookup.source().unwrap().to_string(), "dns said no");
    assert!(empty.source().is_none());
    assert!(lookup.stop_confirmed());
}

#[skuld::test]
fn a_spawn_failure_names_its_plugin_and_chains_its_cause() {
    use std::error::Error as _;

    let err = Error::Spawn {
        plugin: "ex-ray".into(),
        cause: "no such file".into(),
    };

    assert_eq!(err.to_string(), "could not spawn plugin 'ex-ray'");
    assert_eq!(
        err.source().expect("the cause is the source").to_string(),
        "no such file"
    );
    assert!(err.stop_confirmed());
}

// Stop confirmation ===================================================================================================

fn stop_unconfirmed(plugins: &[&str], cause: Error) -> Error {
    Error::StopUnconfirmed {
        plugins: plugins.iter().map(|p| (*p).to_owned()).collect(),
        cause: Box::new(cause),
    }
}

fn pid_sink(plugin: &str) -> Error {
    Error::PidSink {
        plugin: plugin.into(),
        cause: "the sink said no".into(),
    }
}

/// Every error but `StopUnconfirmed` is either raised before a plugin runs or says how a plugin ended, so no plugin
/// is left running behind it. A refused pid sink took its plugin down first.
#[skuld::test]
fn an_error_confirms_the_stop_unless_it_says_it_did_not() {
    let confirmed = [
        Error::Io(std::io::ErrorKind::NotFound.into()),
        Error::PluginExit {
            name: "p".into(),
            code: 1,
        },
        Error::PluginKilled { name: "p".into() },
        Error::Chain("failed to resolve".into()),
        Error::StartFailed {
            plugin: "p".into(),
            cause: crate::StartError::Fatal {
                detail: "d".into(),
                errno: None,
            },
        },
        Error::Env {
            var: "V".into(),
            reason: "r".into(),
            cause: None,
        },
        Error::Tap {
            plugin: "p".into(),
            step: TapStep::AcceptConnection,
            cause: std::io::ErrorKind::NotFound.into(),
        },
        Error::Resolve {
            server: "example.com:443".into(),
            cause: None,
        },
        Error::MalformedOptions(crate::sip003::MalformedOptions::EmptyKey { index: 0 }),
        Error::Cosca(cosca::error::Error::Io(std::io::ErrorKind::PermissionDenied.into())),
        pid_sink("p"),
        Error::Spawn {
            plugin: "p".into(),
            cause: "c".into(),
        },
    ];
    for error in confirmed {
        assert!(error.stop_confirmed(), "{error:?}");
    }
    assert!(!stop_unconfirmed(&["p"], Error::Chain("x".into())).stop_confirmed());
}

/// The cause is the error's source, not part of its text: a reader that prints the chain would otherwise print it twice.
#[skuld::test]
fn an_unconfirmed_stop_names_its_plugins_and_chains_its_cause() {
    use std::error::Error as _;

    let err = stop_unconfirmed(&["a", "b"], Error::Chain("the cause".into()));

    assert_eq!(err.to_string(), "plugin 'a', 'b' could not be confirmed stopped");
    assert_eq!(err.source().expect("the cause is the source").to_string(), "the cause");
}

#[skuld::test]
fn a_refused_pid_sink_names_its_plugin_and_chains_the_sinks_error() {
    use std::error::Error as _;

    let err = pid_sink("ex-ray");

    assert_eq!(err.to_string(), "the pid sink refused plugin 'ex-ray'");
    assert_eq!(
        err.source().expect("the cause is the source").to_string(),
        "the sink said no"
    );
}

/// An unconfirmed stop outranks an earlier error and keeps its own cause: the error it
/// outranks was logged when it happened.
#[skuld::test]
fn an_unconfirmed_stop_outranks_every_other_error_in_either_order() {
    use std::error::Error as _;

    let others = [
        Error::PluginExit {
            name: "a".into(),
            code: 3,
        },
        pid_sink("a"),
    ];
    for other in others {
        let label = format!("{other:?}");
        let ranked = other.then(stop_unconfirmed(&["b"], Error::Chain("kill refused".into())));
        let Error::StopUnconfirmed { plugins, .. } = &ranked else {
            panic!("{label}: got {ranked:?}")
        };
        assert_eq!(plugins, &["b"], "{label}");
        assert_eq!(ranked.source().unwrap().to_string(), "kill refused", "{label}");
    }
}

#[skuld::test]
fn an_earlier_unconfirmed_stop_outlasts_a_later_error() {
    for later in [Error::PluginKilled { name: "b".into() }, pid_sink("b")] {
        let ranked = stop_unconfirmed(&["a"], Error::Chain("c".into())).then(later);

        assert!(
            matches!(&ranked, Error::StopUnconfirmed { plugins, .. } if plugins == &["a"]),
            "got {ranked:?}"
        );
    }
}

#[skuld::test]
fn two_unconfirmed_stops_name_every_plugin_and_keep_the_first_cause() {
    let ranked = stop_unconfirmed(&["a"], Error::Chain("first".into()))
        .then(stop_unconfirmed(&["b"], Error::Chain("second".into())));

    match &ranked {
        Error::StopUnconfirmed { plugins, cause } => {
            assert_eq!(plugins, &["a", "b"]);
            assert_eq!(cause.to_string(), "first");
        }
        other => panic!("got {other:?}"),
    }
}

/// A refused pid sink outranks a start failure and an exit, whichever came first.
#[skuld::test]
fn a_refused_pid_sink_outranks_a_start_failure_and_an_exit() {
    let start_failed = || Error::StartFailed {
        plugin: "a".into(),
        cause: crate::StartError::Fatal {
            detail: "plugin exited before becoming ready".into(),
            errno: None,
        },
    };
    for ranked in [
        start_failed().then(pid_sink("b")),
        pid_sink("b").then(start_failed()),
        Error::PluginExit {
            name: "a".into(),
            code: 1,
        }
        .then(pid_sink("b")),
    ] {
        assert!(
            matches!(&ranked, Error::PidSink { plugin, .. } if plugin == "b"),
            "got {ranked:?}"
        );
    }
}

#[skuld::test]
fn an_earlier_error_stands_over_a_later_confirmed_one() {
    let ranked = Error::PluginExit {
        name: "a".into(),
        code: 1,
    }
    .then(Error::PluginKilled { name: "b".into() });

    assert!(matches!(ranked, Error::PluginExit { .. }), "got {ranked:?}");
}

/// An error is logged where it arises or is taken, so ranking one against another logs nothing, whichever loses, and a
/// merged stop drops its later cause without a word.
#[skuld::test]
fn ranking_logs_nothing() {
    let (subscriber, writer) = crate::tap_tests::make_debug_subscriber();
    let _g = crate::tracing_test::set_default_in_current_thread(subscriber);

    let _ = Error::PluginExit {
        name: "first".into(),
        code: 7,
    }
    .then(pid_sink("second"));
    let _ = pid_sink("third").then(Error::PluginKilled { name: "fourth".into() });
    let _ = stop_unconfirmed(&["fifth"], Error::Chain("a".into()))
        .then(stop_unconfirmed(&["sixth"], Error::Chain("b".into())));

    assert_eq!(writer.snapshot(), "");
}

/// The caller's own error (a cancel, a readiness timeout) yields to exactly the errors `then` ranks above an ordinary
/// one.
#[skuld::test]
fn only_a_stop_that_cannot_be_confirmed_or_a_refused_pid_sink_outranks_a_callers_own_error() {
    assert!(stop_unconfirmed(&["p"], Error::Chain("x".into())).outranks_a_callers_own_error());
    assert!(pid_sink("p").outranks_a_callers_own_error());
    for ordinary in [
        Error::Chain("x".into()),
        Error::PluginKilled { name: "p".into() },
        Error::Io(std::io::ErrorKind::NotFound.into()),
    ] {
        assert!(!ordinary.outranks_a_callers_own_error(), "{ordinary:?}");
    }
}

/// A panicked plugin task is an unconfirmed stop of that plugin, with the panic itself as the cause.
#[skuld::test]
async fn a_panicked_plugin_task_is_an_unconfirmed_stop_caused_by_the_panic() {
    let join = tokio::spawn(async { panic!("the plugin broke") }).await;

    let err = Error::task_lost("p", join.expect_err("the task panicked"));

    match &err {
        Error::StopUnconfirmed { plugins, cause } => {
            assert_eq!(plugins, &["p"]);
            assert!(cause
                .downcast_ref::<tokio::task::JoinError>()
                .is_some_and(tokio::task::JoinError::is_panic));
        }
        other => panic!("got {other:?}"),
    }
}
