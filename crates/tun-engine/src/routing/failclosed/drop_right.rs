//! The right to drop a cover's pf enable token: one party at a time, per token.
//!
//! A token is dropped (`pfctl -X`) before the record that names it is cleared,
//! so that a failed drop leaves the record for a retry. Between the drop and the
//! clear the record still names a token that is gone, and a second party that
//! read it then would drop it again. The right closes that window: a party that
//! cannot [`take`] it leaves the token to whoever holds it.
//!
//! [`take`] never waits. A release must not block on anything a wedged start can
//! hold, and the holder's section is a `pfctl` call.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::pf_claim::Record;
use crate::exclusive::RecordLock;

type Key = (PathBuf, Record, String);

/// Leaf lock over the keys held: only the set lives under it.
static HELD: RecordLock<BTreeSet<Key>> = RecordLock::new(BTreeSet::new());

/// The right to settle one token; released when dropped.
#[must_use = "the right is held only while this guard is alive"]
pub struct DropRight {
    key: Option<Key>,
}

/// Take the right to settle `token` under `record` in `state_dir`, or `None`
/// while another party holds it.
pub fn take(state_dir: &Path, record: Record, token: &str) -> Option<DropRight> {
    let key = (state_dir.to_owned(), record, token.to_owned());
    if !HELD.acquire().insert(key.clone()) {
        return None;
    }
    Some(DropRight { key: Some(key) })
}

impl DropRight {
    /// A right that excludes nobody, for a test double that has no state dir.
    #[cfg(test)]
    pub(crate) fn detached() -> Self {
        Self { key: None }
    }
}

impl Drop for DropRight {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            #[cfg(test)]
            before_release(&key);
            HELD.acquire().remove(&key);
        }
    }
}

#[cfg(test)]
type ReleaseHook = Box<dyn Fn(&Path, Record, &str)>;

#[cfg(test)]
thread_local! {
    static BEFORE_RELEASE: std::cell::RefCell<Option<ReleaseHook>> = const { std::cell::RefCell::new(None) };
}

/// Run this thread's hook just before a right is released: the step boundary an
/// interleaving test schedules around. Not while unwinding, when the scheduler
/// is gone.
#[cfg(test)]
fn before_release((dir, record, token): &Key) {
    if std::thread::panicking() {
        return;
    }
    BEFORE_RELEASE.with(|hook| {
        if let Some(hook) = hook.borrow().as_ref() {
            hook(dir, *record, token);
        }
    });
}

/// Install (or clear) the calling thread's [`before_release`] hook.
#[cfg(test)]
pub(crate) fn set_before_release(hook: Option<ReleaseHook>) {
    BEFORE_RELEASE.with(|slot| *slot.borrow_mut() = hook);
}

#[cfg(test)]
#[path = "drop_right_tests.rs"]
mod drop_right_tests;
