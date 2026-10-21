//! Test-only: a value a stub plugin hands over on its single run.

use std::sync::Mutex;

/// A value moved out of a `&self` on the first [`take`](Once::take). A [`ChainPlugin`](crate::ChainPlugin) is run
/// through `&self`, so a stub that consumes a field in `run` holds it here, and a second run is a test bug.
pub(crate) struct Once<T>(Mutex<Option<T>>);

impl<T> Once<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(Mutex::new(Some(value)))
    }

    pub(crate) fn take(&self) -> T {
        self.0
            .lock()
            .unwrap()
            .take()
            .expect("this stub's value is handed over once, and it was run again")
    }
}
