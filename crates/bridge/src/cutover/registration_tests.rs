use super::*;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// Counts its own drops into a counter the test keeps.
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

impl Settle for Probe {
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

/// The state is read when the owner goes, not when the value was made.
#[skuld::test]
fn settling_after_creation_makes_the_value_freeable() {
    let drops = Arc::new(AtomicUsize::new(0));
    let registration = Registration::new(Probe::new(false, &drops));
    registration.get().settled.store(true, Ordering::Release);
    drop(registration);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

/// Replacing a registration (the actor's re-arm) retires the old one by the
/// same rule as dropping it.
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
