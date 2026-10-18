use super::*;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

struct Probe {
    settled: AtomicBool,
    drops: Arc<AtomicUsize>,
}

impl Probe {
    fn new(settled: bool, drops: &Arc<AtomicUsize>) -> Self {
        Self {
            settled: AtomicBool::new(settled),
            drops: Arc::clone(drops),
        }
    }
}

// SAFETY: `settled` is only ever set by the test, once it holds no reader.
unsafe impl Settle for Probe {
    fn is_settled(&self) -> bool {
        self.settled.load(Ordering::Acquire)
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[skuld::test]
fn an_unsettled_value_is_never_freed() {
    let drops = Arc::new(AtomicUsize::new(0));
    drop(Registration::new(Probe::new(false, &drops)));
    assert_eq!(drops.load(Ordering::SeqCst), 0);
}

#[skuld::test]
fn a_settled_value_is_freed_exactly_once() {
    let drops = Arc::new(AtomicUsize::new(0));
    drop(Registration::new(Probe::new(true, &drops)));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[skuld::test]
fn settling_after_creation_makes_the_value_freeable() {
    let drops = Arc::new(AtomicUsize::new(0));
    let registration = Registration::new(Probe::new(false, &drops));
    registration.get().settled.store(true, Ordering::Release);
    drop(registration);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[skuld::test]
fn replacing_a_registration_retires_the_old_one_by_the_same_rule() {
    struct Owner {
        slot: Option<Registration<Probe>>,
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let mut owner = Owner {
        slot: Some(Registration::new(Probe::new(false, &drops))),
    };
    owner.slot = Some(Registration::new(Probe::new(true, &drops)));
    assert_eq!(drops.load(Ordering::SeqCst), 0, "an unsettled predecessor is kept");
    owner.slot = Some(Registration::new(Probe::new(false, &drops)));
    assert_eq!(drops.load(Ordering::SeqCst), 1, "a settled predecessor is freed");
}

/// Runs `f` under a per-test subscriber and returns what it logged.
fn logged_during(f: impl FnOnce()) -> String {
    use garter::test_utils::WaitableWriter;
    use garter::tracing_test::set_default_in_current_thread;

    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = set_default_in_current_thread(subscriber);
    f();
    writer.snapshot()
}

#[skuld::test]
fn dropping_an_unsettled_registration_logs_the_leak() {
    let drops = Arc::new(AtomicUsize::new(0));
    let log = logged_during(|| drop(Registration::new(Probe::new(false, &drops))));
    assert!(log.contains("leak"), "no leak logged: {log:?}");
    assert!(log.contains("Probe"), "the leaked type is not named: {log:?}");
}

#[skuld::test]
fn dropping_a_settled_registration_logs_nothing() {
    let drops = Arc::new(AtomicUsize::new(0));
    let log = logged_during(|| drop(Registration::new(Probe::new(true, &drops))));
    assert_eq!(log, "");
}

#[skuld::test]
fn a_fresh_arming_has_nothing_to_wait_on() {
    let arming = Arming::<Probe>::Idle;
    assert!(arming.confirmed().is_none());
}

#[skuld::test]
fn a_begun_arming_is_not_confirmed_until_the_call_is_known_to_have_succeeded() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut arming = Arming::Idle;
    arming.begin(Registration::new(Probe::new(false, &drops)));
    assert!(arming.confirmed().is_none(), "a call not known to have succeeded");
    arming.confirm();
    assert!(arming.confirmed().is_some());
}

/// A call that failed may still have registered, so un-confirming keeps the
/// registration owned: nothing is dropped, and nothing waits on it.
#[skuld::test]
fn unconfirming_withdraws_the_wait_and_keeps_the_registration() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut arming = Arming::Idle;
    arming.begin(Registration::new(Probe::new(false, &drops)));
    arming.confirm();
    arming.unconfirm();
    assert!(arming.confirmed().is_none());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(arming);
    assert_eq!(drops.load(Ordering::SeqCst), 0, "an unsettled value is still leaked");
}

#[skuld::test]
fn unconfirming_an_idle_arming_changes_nothing() {
    let mut arming = Arming::<Probe>::Idle;
    arming.unconfirm();
    assert!(arming.confirmed().is_none());
}

#[skuld::test]
fn beginning_over_a_confirmed_arming_retires_it_by_the_registration_rule() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut arming = Arming::Idle;
    arming.begin(Registration::new(Probe::new(true, &drops)));
    arming.confirm();
    arming.begin(Registration::new(Probe::new(false, &drops)));
    assert_eq!(drops.load(Ordering::SeqCst), 1, "a settled predecessor is freed");
    assert!(
        arming.confirmed().is_none(),
        "the new call is not yet known to have succeeded"
    );
}
