use super::*;

use std::sync::{Arc, Barrier, Mutex};

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
            StopPhase::StopProxy => 1,
            StopPhase::CloseEtw => 2,
            StopPhase::ShutdownRuntime => 3,
        }
    }
    let positions: Vec<usize> = StopPhase::ALL.iter().map(|p| position(*p)).collect();
    assert_eq!(positions, vec![0, 1, 2, 3]);
}

#[skuld::test]
fn checkpoints_strictly_increase_and_are_never_zero() {
    // SCM: checkpoint 0 means "no pending operation"; a repeated value is
    // indistinguishable from no progress.
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
    // Checkpoints are progress-driven: constructing the reporter emits nothing.
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
fn racing_entries_from_two_threads_never_move_the_checkpoint_back() {
    let log = Log::default();
    let progress = Arc::new(log.progress());
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [StopPhase::StopRequested, StopPhase::StopProxy]
        .into_iter()
        .map(|phase| {
            let progress = Arc::clone(&progress);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                progress.enter(phase);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let reported: Vec<u32> = log
        .events()
        .iter()
        .map(|e| match e {
            Event::Reported(p) => p.checkpoint(),
            Event::Step(_) => unreachable!(),
        })
        .collect();
    assert!(!reported.is_empty());
    assert!(
        reported.windows(2).all(|w| w[0] < w[1]),
        "checkpoints reported out of order: {reported:?}"
    );
    // StopProxy is the later phase, so it is reported whichever thread got there first.
    assert_eq!(reported.last(), Some(&StopPhase::StopProxy.checkpoint()));
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
fn proxy_stop_is_bracketed_by_its_own_report_and_etw_close_follows_its_own() {
    let log = Log::default();
    let progress = log.progress();
    block_on(tear_down(
        &progress,
        async {
            log.step("stop_proxy");
        },
        || log.step("close_etw"),
    ));
    assert_eq!(
        log.events(),
        vec![
            Event::Reported(StopPhase::StopProxy),
            Event::Step("stop_proxy"),
            Event::Reported(StopPhase::CloseEtw),
            Event::Step("close_etw"),
        ]
    );
}

#[skuld::test]
fn stopped_is_reported_only_after_the_runtime_is_dropped() {
    let log = Log::default();
    let progress = log.progress();
    finish_stop(&progress, || log.step("drop_runtime"), || log.step("stopped"));
    assert_eq!(
        log.events(),
        vec![
            Event::Reported(StopPhase::ShutdownRuntime),
            Event::Step("drop_runtime"),
            Event::Step("stopped"),
        ]
    );
}
