// `CancellationToken::new` is the test root of the shutdown signal.
#![allow(clippy::disallowed_methods)]

use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::backoff::Backoff;

const fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// Paused clock: an idle runtime jumps to the next timer, whose deadline is rounded up to the next millisecond.
const TIMER_SLACK: Duration = ms(1);

#[skuld::test]
async fn each_pause_doubles_the_delay_up_to_the_maximum() {
    tokio::time::pause();
    let shutdown = CancellationToken::new();
    let mut backoff = Backoff::new(ms(5), ms(50));

    // 5, 10, 20, 40, then the cap: 50, 50.
    for expected in [5, 10, 20, 40, 50, 50] {
        let before = Instant::now();
        assert!(backoff.pause(&shutdown).await);
        let waited = before.elapsed();
        assert!(
            (ms(expected)..=ms(expected) + TIMER_SLACK).contains(&waited),
            "want a {expected}ms pause, waited {waited:?}"
        );
    }
}

#[skuld::test]
async fn at_max_turns_true_once_the_delay_reaches_the_maximum() {
    tokio::time::pause();
    let shutdown = CancellationToken::new();
    let mut backoff = Backoff::new(ms(10), ms(1000));

    // 10 -> 20 -> 40 -> 80 -> 160 -> 320 -> 640 -> 1000 (capped): the 7th pause is the first to leave the delay at the cap.
    for pauses in 1..=7 {
        assert!(!backoff.at_max(), "at the cap before pause {pauses}");
        backoff.pause(&shutdown).await;
    }
    assert!(backoff.at_max());
}

#[skuld::test]
async fn a_pause_cut_short_by_shutdown_reports_it_without_waiting() {
    tokio::time::pause();
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let mut backoff = Backoff::new(ms(5), ms(50));

    let before = Instant::now();
    assert!(!backoff.pause(&shutdown).await);
    assert_eq!(before.elapsed(), Duration::ZERO);
}
