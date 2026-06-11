use crate::interrupts::Interrupts;

/// A signal raised BETWEEN recv() calls (here: before the first one) must
/// not be lost — install() registers persistent streams eagerly, and the
/// watch channel buffers the edge. (The old fresh-ctrl_c()-per-recv design
/// provably lost these; see the PR discussion.) Unix-gated like the bridge's
/// sigterm_resolves_shutdown_signal precedent: nextest isolates each test in
/// its own process, so the raise cannot disturb siblings.
#[cfg(unix)]
#[skuld::test]
async fn signal_before_first_recv_is_buffered() {
    let mut interrupts = Interrupts::install();
    // SAFETY: raising a signal to our own process is sound; the persistent
    // SIGINT stream was registered by install(), replacing the default
    // disposition before the raise.
    assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
    // Resolves via the buffered event; bounded by the per-test timeout
    // (class-2 failure-to-human bound).
    interrupts.recv().await;
}

/// recv() is re-usable: a second signal after a completed recv() resolves a
/// second recv() (stream persistence across calls).
#[cfg(unix)]
#[skuld::test]
async fn recv_is_reusable_across_signals() {
    let mut interrupts = Interrupts::install();
    assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
    interrupts.recv().await;
    assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
    interrupts.recv().await;
}
