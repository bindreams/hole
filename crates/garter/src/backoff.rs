//! The pause between retries, shared by every retry loop in the crate.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Exponential pause between retries: `start`, doubling up to `max`.
pub(crate) struct Backoff {
    delay: Duration,
    max: Duration,
}

impl Backoff {
    pub(crate) fn new(start: Duration, max: Duration) -> Self {
        Self { delay: start, max }
    }

    /// Whether the next pause is the longest this backoff makes.
    pub(crate) fn at_max(&self) -> bool {
        self.delay >= self.max
    }

    /// Waits one step. Returns `false`, without waiting out the step, if
    /// `shutdown` fires first.
    pub(crate) async fn pause(&mut self, shutdown: &CancellationToken) -> bool {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => false,
            () = tokio::time::sleep(self.delay) => {
                self.delay = (self.delay * 2).min(self.max);
                true
            }
        }
    }
}
