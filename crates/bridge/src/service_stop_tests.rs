use super::*;

use std::sync::{Arc, Mutex};

use crate::test_support::log_capture::VecWriter;
use tracing_subscriber::layer::{Layer, SubscriberExt};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Reported(StopPhase),
    Step(&'static str),
}

/// A reporter and a step recorder that write to one shared log, so a test can
/// assert the interleaving of reports and the work they bracket.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<Event>>>);

impl Log {
    fn push(&self, e: Event) {
        self.0.lock().unwrap().push(e);
    }
    fn step(&self, name: &'static str) {
        self.push(Event::Step(name));
    }
    fn events(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }
    fn progress(&self) -> StopProgress<impl Fn(StopPhase) -> std::io::Result<()>> {
        let log = self.clone();
        StopProgress::new(move |p| {
            log.push(Event::Reported(p));
            Ok(())
        })
    }
}

fn block_on<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

#[skuld::test]
fn all_lists_every_phase_in_teardown_order() {
    // Exhaustive match: adding a variant breaks the build here until it is
    // placed in `ALL` too.
    fn position(p: StopPhase) -> usize {
        match p {
            StopPhase::StopRequested => 0,
            StopPhase::AcquireProxy => 1,
            StopPhase::PersistTarget => 2,
            StopPhase::RestoreDns => 3,
            StopPhase::StopEngine => 4,
            StopPhase::ReapPlugins => 5,
            StopPhase::StopProxy => 6,
            StopPhase::TearDownRoutes => 7,
            StopPhase::SettleCover => 8,
            StopPhase::CloseEtw => 9,
            StopPhase::DropResources => 10,
            StopPhase::ShutdownRuntime => 11,
        }
    }
    let positions: Vec<usize> = StopPhase::ALL.iter().map(|p| position(*p)).collect();
    assert_eq!(positions, (0..12).collect::<Vec<_>>());
}

#[skuld::test]
fn checkpoints_strictly_increase_and_are_never_zero() {
    // A repeated checkpoint is indistinguishable from no progress.
    let cps: Vec<u32> = StopPhase::ALL.iter().map(|p| p.checkpoint()).collect();
    assert!(cps[0] >= 1, "checkpoint 0 reads as not-pending: {cps:?}");
    assert!(cps.windows(2).all(|w| w[0] < w[1]), "not strictly increasing: {cps:?}");
}

#[skuld::test]
fn every_phase_carries_a_nonzero_wait_hint() {
    for p in StopPhase::ALL {
        assert!(!p.wait_hint().is_zero(), "{p:?} has no wait hint");
    }
}

#[skuld::test]
fn enter_reports_each_phase_once_in_the_order_entered() {
    let log = Log::default();
    let progress = log.progress();
    for p in StopPhase::ALL {
        progress.enter(p);
    }
    let expected: Vec<Event> = StopPhase::ALL.iter().map(|p| Event::Reported(*p)).collect();
    assert_eq!(log.events(), expected);
}

#[skuld::test]
fn nothing_is_reported_until_a_phase_is_entered() {
    let log = Log::default();
    let _progress = log.progress();
    assert_eq!(log.events(), vec![]);
}

#[skuld::test]
fn a_failed_report_does_not_stop_teardown_or_later_reports() {
    let attempts = Mutex::new(Vec::new());
    let progress = StopProgress::new(|p| {
        attempts.lock().unwrap().push(p);
        if p == StopPhase::StopRequested {
            Err(std::io::Error::other("SCM refused"))
        } else {
            Ok(())
        }
    });
    for p in StopPhase::ALL {
        progress.enter(p);
    }
    assert_eq!(*attempts.lock().unwrap(), StopPhase::ALL.to_vec());
}

#[skuld::test]
fn an_entry_that_would_not_advance_the_checkpoint_is_not_reported() {
    // The control handler and the main task both enter phases; whichever loses
    // the race must not move the checkpoint back or repeat it.
    let log = Log::default();
    let progress = log.progress();
    progress.enter(StopPhase::CloseEtw);
    progress.enter(StopPhase::StopProxy);
    progress.enter(StopPhase::CloseEtw);
    assert_eq!(log.events(), vec![Event::Reported(StopPhase::CloseEtw)]);
}

#[skuld::test]
fn entering_a_phase_logs_it_with_its_checkpoint_at_info() {
    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
    );
    let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);

    let progress = StopProgress::new(|_| Ok(()));
    progress.enter(StopPhase::CloseEtw);

    let out = writer.snapshot_string();
    assert!(out.contains("INFO"), "not logged at info:\n{out}");
    assert!(out.contains("service stop phase"), "no phase line:\n{out}");
    assert!(out.contains("CloseEtw"), "phase not named:\n{out}");
    assert!(
        out.contains(&format!("checkpoint={}", StopPhase::CloseEtw.checkpoint())),
        "checkpoint not logged:\n{out}"
    );
}

#[skuld::test]
fn a_stop_control_is_reported_before_the_main_task_is_signalled() {
    // The report must land before the shutdown signal, or the SCM sees `Running`
    // while the main task is still unwinding the awaits it cannot cancel.
    let log = Log::default();
    let progress = log.progress();
    request_stop(&progress, || log.step("signal"));
    assert_eq!(
        log.events(),
        vec![Event::Reported(StopPhase::StopRequested), Event::Step("signal")]
    );
}

#[skuld::test]
fn teardown_enters_the_proxy_phases_through_the_progress_it_hands_the_stop_work() {
    // The proxy stop reports its own sub-phases; `tear_down` only brackets them
    // with AcquireProxy before and CloseEtw / DropResources after.
    let log = Log::default();
    let progress = Arc::new(log.progress());
    block_on(tear_down(
        &progress,
        |progress| {
            let log = log.clone();
            async move {
                log.step("stop_proxy_begin");
                progress.enter(StopPhase::RestoreDns);
                log.step("stop_proxy_end");
            }
        },
        Some(()),
        |()| log.step("close_etw"),
        || log.step("drop_resources"),
    ));
    assert_eq!(
        log.events(),
        vec![
            Event::Reported(StopPhase::AcquireProxy),
            Event::Step("stop_proxy_begin"),
            Event::Reported(StopPhase::RestoreDns),
            Event::Step("stop_proxy_end"),
            Event::Reported(StopPhase::CloseEtw),
            Event::Step("close_etw"),
            Event::Reported(StopPhase::DropResources),
            Event::Step("drop_resources"),
        ]
    );
}

#[skuld::test]
fn stopped_is_reported_only_after_the_runtime_is_dropped() {
    let log = Log::default();
    let progress = log.progress();
    finish_stop(
        &progress,
        || log.step("drop_runtime"),
        || {
            log.step("stopped");
            Ok(())
        },
    );
    assert_eq!(
        log.events(),
        vec![
            Event::Reported(StopPhase::ShutdownRuntime),
            Event::Step("drop_runtime"),
            Event::Step("stopped"),
        ]
    );
}

/// Subscriber capturing `service stop phase` lines into `writer`, for tests that
/// assert where the log write falls relative to the report and the signal.
fn capture_info(writer: &VecWriter) -> impl tracing::Subscriber + Send + Sync {
    capture_at(writer, tracing_subscriber::filter::LevelFilter::INFO)
}

fn capture_at(
    writer: &VecWriter,
    level: tracing_subscriber::filter::LevelFilter,
) -> impl tracing::Subscriber + Send + Sync {
    tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(level),
    )
}

#[skuld::test]
fn a_phase_is_reported_to_the_scm_before_it_is_logged() {
    // A log writer that back-pressures (`lossy(false)` on a wedged disk) must not
    // stand between a phase and its StopPending report.
    let writer = VecWriter::new();
    let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
    let seen_at_report = Mutex::new(None);
    let progress = StopProgress::new(|_| {
        *seen_at_report.lock().unwrap() = Some(writer.snapshot_string());
        Ok(())
    });
    progress.enter(StopPhase::CloseEtw);
    let seen = seen_at_report.lock().unwrap().clone().expect("no report");
    assert!(
        !seen.contains("service stop phase"),
        "logged before the report:\n{seen}"
    );
    assert!(writer.snapshot_string().contains("service stop phase"));
}

#[skuld::test]
fn a_failed_report_is_logged_as_a_warning() {
    let writer = VecWriter::new();
    let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
    let progress = StopProgress::new(|_| Err(std::io::Error::other("SCM refused")));
    progress.enter(StopPhase::CloseEtw);
    let out = writer.snapshot_string();
    assert!(
        out.contains("failed to report StopPending"),
        "failure not logged:\n{out}"
    );
}

#[skuld::test]
fn a_stop_control_does_not_wait_for_a_report_in_flight_on_another_thread() {
    // The main task is mid-report for a later phase (an SCM call that has not
    // returned). The control handler must still signal shutdown: whatever that
    // thread is reporting is later than StopRequested, so the handler's own
    // report is superseded and there is nothing to wait for.
    let in_report = std::sync::mpsc::channel::<()>();
    let release = std::sync::mpsc::channel::<()>();
    let release_rx = Mutex::new(release.1);
    let reported = Arc::new(Mutex::new(Vec::new()));
    let progress = {
        let reported = Arc::clone(&reported);
        Arc::new(StopProgress::new(move |p| {
            if p == StopPhase::StopProxy {
                in_report.0.send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
            }
            reported.lock().unwrap().push(p);
            Ok(())
        }))
    };
    let writer = VecWriter::new();
    let main_task = {
        let progress = Arc::clone(&progress);
        let writer = writer.clone();
        std::thread::spawn(move || {
            let _guard = garter::tracing_test::set_default_in_current_thread(capture_at(
                &writer,
                tracing_subscriber::filter::LevelFilter::DEBUG,
            ));
            progress.enter(StopPhase::StopProxy)
        })
    };
    in_report.1.recv().unwrap();

    let signalled = std::cell::Cell::new(false);
    request_stop(&progress, || signalled.set(true));
    assert!(signalled.get(), "shutdown was not signalled");

    release.0.send(()).unwrap();
    main_task.join().unwrap();
    assert_eq!(*reported.lock().unwrap(), vec![StopPhase::StopProxy]);
    // The skipped report is not silent: the main task logs it at debug.
    let out = writer.snapshot_string();
    assert!(
        out.contains("DEBUG") && out.contains("superseded") && out.contains("StopRequested"),
        "skipped StopRequested not logged at debug:\n{out}"
    );
}

#[skuld::test]
fn a_stop_control_writes_no_log_line_on_the_control_handler_thread() {
    // The SCM gives HandlerEx 30 s. The file appender is non-lossy, so a log
    // write on the handler thread can block past that and fail the caller's
    // ControlService. The outcome is logged by the main task instead.
    let writer = VecWriter::new();
    let log = Log::default();
    let progress = Arc::new(log.progress());
    let handler = {
        let progress = Arc::clone(&progress);
        let writer = writer.clone();
        std::thread::spawn(move || {
            let _guard = garter::tracing_test::set_default_in_current_thread(capture_at(
                &writer,
                tracing_subscriber::filter::LevelFilter::TRACE,
            ));
            request_stop(&progress, || {});
        })
    };
    handler.join().unwrap();
    assert_eq!(writer.snapshot_string(), "", "the handler thread wrote a log line");
    assert_eq!(log.events(), vec![Event::Reported(StopPhase::StopRequested)]);

    // The main task's next entry carries the hand-off, ahead of its own line.
    let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
    progress.enter(StopPhase::AcquireProxy);
    let out = writer.snapshot_string();
    let stop_requested = out.find("StopRequested").expect("hand-off not logged");
    let acquire = out.find("AcquireProxy").expect("own phase not logged");
    assert!(stop_requested < acquire, "hand-off not logged first:\n{out}");
}

#[skuld::test]
fn a_failed_stop_control_report_is_logged_as_a_warning_by_the_main_task() {
    let writer = VecWriter::new();
    let progress = StopProgress::new(|_| Err(std::io::Error::other("SCM refused")));
    request_stop(&progress, || {});
    assert_eq!(writer.snapshot_string(), "");

    let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
    progress.enter(StopPhase::AcquireProxy);
    let out = writer.snapshot_string();
    assert!(
        out.contains("WARN") && out.contains("failed to report StopPending") && out.contains("StopRequested"),
        "failed hand-off not logged as a warning:\n{out}"
    );
}

#[skuld::test]
fn a_stop_control_arriving_after_a_later_phase_is_logged_as_superseded() {
    let writer = VecWriter::new();
    let log = Log::default();
    let progress = log.progress();
    progress.enter(StopPhase::AcquireProxy);
    request_stop(&progress, || log.step("signal"));
    assert_eq!(
        log.events(),
        vec![Event::Reported(StopPhase::AcquireProxy), Event::Step("signal")]
    );

    let _guard = garter::tracing_test::set_default_in_current_thread(capture_at(
        &writer,
        tracing_subscriber::filter::LevelFilter::DEBUG,
    ));
    progress.enter(StopPhase::PersistTarget);
    let out = writer.snapshot_string();
    assert!(
        out.contains("DEBUG") && out.contains("superseded") && out.contains("StopRequested"),
        "superseded stop control not logged at debug:\n{out}"
    );
}

/// A reporter that refuses only `StopRequested`, so a hand-off that was
/// reported and failed is told apart from one that never reached the SCM.
fn refuse_stop_requested(p: StopPhase) -> std::io::Result<()> {
    if p == StopPhase::StopRequested {
        Err(std::io::Error::other("SCM refused"))
    } else {
        Ok(())
    }
}

fn assert_stop_requested_trail(out: &str) {
    assert!(
        out.lines()
            .any(|l| l.contains("INFO") && l.contains("service stop phase") && l.contains("StopRequested")),
        "no StopRequested phase line:\n{out}"
    );
    assert!(
        out.lines()
            .any(|l| l.contains("WARN") && l.contains("failed to report StopPending") && l.contains("StopRequested")),
        "no failed-report warning for StopRequested:\n{out}"
    );
}

#[skuld::test]
fn a_second_stop_control_does_not_replace_the_first_ones_unlogged_report() {
    // Stop then Shutdown (or Stop twice) can both reach the handler before the
    // first StopPending takes effect. The second is superseded, but the first
    // reported and failed, and its trail must survive.
    // Guarded for completeness, not exercised end to end: windows-service frees
    // the handler closure after the first Stop/Shutdown, so a second control may
    // never reach it. The same holds for the
    // second-control tests below.
    let writer = VecWriter::new();
    let progress = StopProgress::new(refuse_stop_requested);
    request_stop(&progress, || {});
    request_stop(&progress, || {});

    let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
    progress.enter(StopPhase::AcquireProxy);
    assert_stop_requested_trail(&writer.snapshot_string());
}

#[skuld::test]
fn a_stop_control_that_loses_the_report_lock_does_not_replace_the_first_ones_unlogged_report() {
    // The same loss through the other superseding path: the second control finds
    // another thread mid-report, so it never reaches `report_if_advancing`.
    let in_report = std::sync::mpsc::channel::<()>();
    let release = std::sync::mpsc::channel::<()>();
    let release_rx = Mutex::new(release.1);
    let progress = Arc::new(StopProgress::new(move |p| {
        if p == StopPhase::StopProxy {
            in_report.0.send(()).unwrap();
            release_rx.lock().unwrap().recv().unwrap();
        }
        refuse_stop_requested(p)
    }));
    request_stop(&progress, || {});

    let writer = VecWriter::new();
    let main_task = {
        let progress = Arc::clone(&progress);
        let writer = writer.clone();
        std::thread::spawn(move || {
            let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
            progress.enter(StopPhase::StopProxy)
        })
    };
    in_report.1.recv().unwrap();
    request_stop(&progress, || {});

    release.0.send(()).unwrap();
    main_task.join().unwrap();
    assert_stop_requested_trail(&writer.snapshot_string());
}

#[skuld::test]
fn a_stop_control_whose_report_panics_returns_normally_signals_and_is_logged_by_the_main_task() {
    // The control handler runs inside windows-service's `extern "system"`
    // trampoline, which aborts the process on an unwinding panic. The handler
    // thread must therefore return from `request_stop` normally, still signal
    // the main task, and write no log line; the main task logs the panic.
    let writer = VecWriter::new();
    let signalled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let progress = Arc::new(StopProgress::new(|p| -> std::io::Result<()> {
        if p == StopPhase::StopRequested {
            panic!("report closure panicked");
        }
        Ok(())
    }));
    let handler = {
        let progress = Arc::clone(&progress);
        let signalled = Arc::clone(&signalled);
        let writer = writer.clone();
        std::thread::spawn(move || {
            let _guard = garter::tracing_test::set_default_in_current_thread(capture_at(
                &writer,
                tracing_subscriber::filter::LevelFilter::TRACE,
            ));
            request_stop(&progress, || {
                signalled.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
        })
    };
    handler.join().expect("the panic unwound out of the control handler");
    assert_eq!(signalled.load(std::sync::atomic::Ordering::SeqCst), 1);
    // The process-wide panic hook logs the panic itself on the handler thread;
    // the stop path adds nothing of its own.
    assert!(
        !writer.snapshot_string().contains("StopRequested"),
        "the handler thread logged the stop control"
    );

    let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
    progress.enter(StopPhase::AcquireProxy);
    let out = writer.snapshot_string();
    assert!(
        out.lines().any(|l| l.contains("ERROR")
            && l.contains("StopRequested")
            && l.contains("report closure panicked")
            && l.contains("reported_ms_ago")),
        "the panic was not logged by the main task:\n{out}"
    );
    assert!(
        out.contains("AcquireProxy"),
        "the main task's own phase is missing:\n{out}"
    );
}

#[skuld::test]
fn a_second_stop_control_does_not_replace_a_panicked_report() {
    let writer = VecWriter::new();
    let progress = StopProgress::new(|p| -> std::io::Result<()> {
        if p == StopPhase::StopRequested {
            panic!("report closure panicked");
        }
        Ok(())
    });
    request_stop(&progress, || {});
    request_stop(&progress, || {});

    let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
    progress.enter(StopPhase::AcquireProxy);
    let out = writer.snapshot_string();
    assert!(
        out.lines()
            .any(|l| l.contains("ERROR") && l.contains("StopRequested") && l.contains("reported_ms_ago")),
        "the panicked report's trail was lost:\n{out}"
    );
}

#[skuld::test]
fn waking_from_the_stop_signal_cancels_then_logs_the_hand_off_before_any_phase_is_entered() {
    // The main task may wedge in the connection-task join or the marker probe
    // right after it wakes, before it enters AcquireProxy. The StopRequested
    // line must already be in the log by then. Cancelling comes first so a log
    // write that blocks cannot delay the shutdown it reports.
    let writer = VecWriter::new();
    let progress = StopProgress::new(refuse_stop_requested);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    request_stop(&progress, || {
        tx.send(()).unwrap();
    });

    let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
    let seen_at_cancel = Mutex::new(None);
    block_on(forward_stop(&progress, rx, || {
        *seen_at_cancel.lock().unwrap() = Some(writer.snapshot_string());
    }));

    let seen = seen_at_cancel
        .lock()
        .unwrap()
        .clone()
        .expect("shutdown was not cancelled");
    assert_eq!(seen, "", "the hand-off was logged before the shutdown was cancelled");
    let out = writer.snapshot_string();
    assert_stop_requested_trail(&out);
    assert!(out.contains("reported_ms_ago"), "no report-time field:\n{out}");
    assert!(!out.contains("AcquireProxy"), "a later phase was entered:\n{out}");
}

#[skuld::test]
fn a_dropped_stop_sender_still_cancels_the_shutdown() {
    let progress = StopProgress::new(|_| Ok(()));
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    drop(tx);
    let cancelled = std::cell::Cell::new(false);
    block_on(forward_stop(&progress, rx, || cancelled.set(true)));
    assert!(cancelled.get());
}

#[skuld::test]
fn a_hand_off_is_logged_once() {
    let writer = VecWriter::new();
    let progress = StopProgress::new(|_| Ok(()));
    request_stop(&progress, || {});
    let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
    progress.enter(StopPhase::AcquireProxy);
    progress.enter(StopPhase::PersistTarget);
    assert_eq!(writer.snapshot_string().matches("StopRequested").count(), 1);
}

#[skuld::test]
fn a_panicking_report_poisons_nothing_the_stop_path_depends_on() {
    // The report closure panics while the report lock is held. The control
    // handler (try_lock, Poisoned arm) and the main task (enter) must both
    // recover the lock: a panic on an SCM thread, or a skipped report, would
    // lose the stop.
    let log = Log::default();
    let panic_once = std::sync::atomic::AtomicBool::new(true);
    let progress = {
        let log = log.clone();
        StopProgress::new(move |p| {
            log.push(Event::Reported(p));
            if panic_once.swap(false, std::sync::atomic::Ordering::SeqCst) {
                panic!("report closure panicked");
            }
            Ok(())
        })
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        progress.enter(StopPhase::StopRequested)
    }));
    assert!(result.is_err(), "the report closure did not panic");

    request_stop(&progress, || log.step("signal"));
    progress.enter(StopPhase::AcquireProxy);
    assert_eq!(
        log.events(),
        vec![
            Event::Reported(StopPhase::StopRequested),
            Event::Step("signal"),
            Event::Reported(StopPhase::AcquireProxy),
        ]
    );
}

#[skuld::test]
fn a_phase_with_work_is_entered_before_the_work_and_returns_its_output() {
    let log = Log::default();
    let mut entered = Vec::new();
    let out = block_on(run_phase(
        &mut |p| {
            log.push(Event::Reported(p));
            entered.push(p);
        },
        StopPhase::ReapPlugins,
        Some(7u32),
        |n| {
            let log = log.clone();
            async move {
                log.step("work");
                n + 1
            }
        },
    ));
    assert_eq!(out, Some(8));
    assert_eq!(
        log.events(),
        vec![Event::Reported(StopPhase::ReapPlugins), Event::Step("work")]
    );
}

#[skuld::test]
fn a_phase_without_work_is_not_entered() {
    let log = Log::default();
    let out = block_on(run_phase(
        &mut |p| log.push(Event::Reported(p)),
        StopPhase::StopEngine,
        None::<u32>,
        |_| {
            let log = log.clone();
            async move { log.step("work") }
        },
    ));
    assert_eq!(out, None);
    assert_eq!(log.events(), vec![]);
}

#[skuld::test]
fn the_scm_reporter_fails_until_the_status_handle_is_registered() {
    // A Stop can land between `register` returning and the handle being stored.
    let cell: Arc<std::sync::OnceLock<&'static str>> = Arc::new(std::sync::OnceLock::new());
    let sent = Mutex::new(Vec::new());
    let progress = StopProgress::new(scm_reporter(Arc::clone(&cell), |handle, phase| {
        sent.lock().unwrap().push((*handle, phase));
        Ok(())
    }));

    request_stop(&progress, || {});
    assert_eq!(*sent.lock().unwrap(), vec![]);

    cell.set("handle").unwrap();
    progress.enter(StopPhase::AcquireProxy);
    assert_eq!(*sent.lock().unwrap(), vec![("handle", StopPhase::AcquireProxy)]);
}

#[skuld::test]
fn the_stop_control_reports_before_it_signals_the_main_task_and_signals_once() {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = Mutex::new(Some(tx));
    let rx = Mutex::new(rx);
    let signalled_at_report = Mutex::new(Vec::new());
    let progress = StopProgress::new(|_| {
        signalled_at_report
            .lock()
            .unwrap()
            .push(rx.lock().unwrap().try_recv().is_ok());
        Ok(())
    });

    stop_control(&progress, &shutdown_tx);
    assert_eq!(
        *signalled_at_report.lock().unwrap(),
        vec![false],
        "signalled before the report"
    );
    assert!(rx.lock().unwrap().try_recv().is_ok(), "main task not signalled");

    // A second control (Stop then Shutdown) finds the sender gone.
    stop_control(&progress, &shutdown_tx);
}

#[skuld::test]
fn a_failed_stopped_report_is_logged_as_a_warning() {
    let writer = VecWriter::new();
    let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
    let progress = StopProgress::new(|_| Ok(()));
    finish_stop(&progress, || {}, || Err(std::io::Error::other("SCM refused")));
    let out = writer.snapshot_string();
    assert!(
        out.contains("WARN") && out.contains("failed to report Stopped"),
        "failed Stopped report not logged:\n{out}"
    );
}

struct DropFlag(Arc<Mutex<Vec<&'static str>>>, &'static str);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.lock().unwrap().push(self.1);
    }
}

#[skuld::test]
fn the_last_handle_is_dropped_by_drop_last_handle() {
    let drops = Arc::new(Mutex::new(Vec::new()));
    let handle = Arc::new(DropFlag(Arc::clone(&drops), "value"));
    drop_last_handle(handle);
    assert_eq!(*drops.lock().unwrap(), vec!["value"]);
}

#[skuld::test]
fn a_sole_owner_is_dropped_without_a_log_line() {
    let writer = VecWriter::new();
    let _guard = garter::tracing_test::set_default_in_current_thread(capture_at(
        &writer,
        tracing_subscriber::filter::LevelFilter::TRACE,
    ));
    drop_last_handle(Arc::new(DropFlag(Arc::default(), "value")));
    assert_eq!(writer.snapshot_string(), "");
}

#[skuld::test]
fn a_surviving_clone_is_logged_and_keeps_the_value_alive() {
    let writer = VecWriter::new();
    let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
    let drops = Arc::new(Mutex::new(Vec::new()));
    let handle = Arc::new(DropFlag(Arc::clone(&drops), "value"));
    let survivor = Arc::clone(&handle);
    drop_last_handle(handle);
    assert_eq!(*drops.lock().unwrap(), Vec::<&str>::new());
    assert!(
        writer.snapshot_string().contains("outlived the teardown"),
        "survivor not logged:\n{}",
        writer.snapshot_string()
    );
    drop(survivor);
    assert_eq!(*drops.lock().unwrap(), vec!["value"]);
}

// tear_down_service ---------------------------------------------------------------------------------------------------

use crate::proxy_manager::proxy_manager_tests::{MockProxy, MockRouting};
use crate::proxy_manager::ProxyManager;
use crate::target::SessionEvent;

/// Records its own drop as a step in the shared log.
struct StepOnDrop(Log, &'static str);

impl Drop for StepOnDrop {
    fn drop(&mut self) {
        self.0.step(self.1);
    }
}

fn idle_manager_with_state_dir() -> (
    Arc<tokio::sync::Mutex<ProxyManager<MockProxy, MockRouting>>>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let routing = MockRouting::new(dir.path().to_path_buf());
    let pm = ProxyManager::new(MockProxy::new(), routing).with_state_dir(dir.path().to_path_buf());
    (Arc::new(tokio::sync::Mutex::new(pm)), dir)
}

#[skuld::test]
fn service_teardown_probes_the_event_before_waiting_on_the_proxy_and_drops_in_phase_order() {
    let log = Log::default();
    let progress = Arc::new(log.progress());
    let (proxy, _dir) = idle_manager_with_state_dir();
    let weak = Arc::downgrade(&proxy);
    block_on(tear_down_service(
        &progress,
        proxy,
        || {
            log.step("event");
            SessionEvent::ProcessExiting
        },
        Some(StepOnDrop(log.clone(), "etw dropped")),
        StepOnDrop(log.clone(), "held dropped"),
    ));
    assert_eq!(
        log.events(),
        vec![
            Event::Step("event"),
            Event::Reported(StopPhase::AcquireProxy),
            Event::Reported(StopPhase::PersistTarget),
            Event::Reported(StopPhase::CloseEtw),
            Event::Step("etw dropped"),
            Event::Reported(StopPhase::DropResources),
            Event::Step("held dropped"),
        ]
    );
    assert!(weak.upgrade().is_none(), "the proxy manager outlived the teardown");
}

#[skuld::test]
fn service_teardown_without_an_etw_consumer_does_not_enter_close_etw() {
    // The ETW consumer can fail to start; CloseEtw names work that then does not exist.
    let log = Log::default();
    let progress = Arc::new(log.progress());
    let (proxy, _dir) = idle_manager_with_state_dir();
    block_on(tear_down_service(
        &progress,
        proxy,
        || SessionEvent::ProcessExiting,
        None::<()>,
        (),
    ));
    assert_eq!(
        log.events(),
        vec![
            Event::Reported(StopPhase::AcquireProxy),
            Event::Reported(StopPhase::PersistTarget),
            Event::Reported(StopPhase::DropResources),
        ]
    );
}

#[skuld::test]
fn service_teardown_names_a_proxy_handle_that_outlives_it() {
    // A connection task still holding a router clone would drop the manager on
    // whatever thread released it, outside DropResources.
    let writer = VecWriter::new();
    let _guard = garter::tracing_test::set_default_in_current_thread(capture_info(&writer));
    let log = Log::default();
    let progress = Arc::new(log.progress());
    let (proxy, _dir) = idle_manager_with_state_dir();
    let straggler = Arc::clone(&proxy);
    block_on(tear_down_service(
        &progress,
        proxy,
        || SessionEvent::ProcessExiting,
        Some(()),
        (),
    ));
    assert!(writer.snapshot_string().contains("outlived the teardown"));
    assert_eq!(Arc::strong_count(&straggler), 1);
}
