#![allow(clippy::disallowed_methods)] // fixtures build their own root CancellationToken; see clippy.toml

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use super::*;

/// Answers every request with a fixed reply.
struct AnsweringInterceptor {
    reply: Vec<u8>,
}

#[async_trait]
impl DnsInterceptor for AnsweringInterceptor {
    async fn intercept(&self, _request: &[u8]) -> Option<Vec<u8>> {
        Some(self.reply.clone())
    }
}

/// Declines every request, counting how many times it was called.
struct DecliningInterceptor {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl DnsInterceptor for DecliningInterceptor {
    async fn intercept(&self, _request: &[u8]) -> Option<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        None
    }
}

/// Never completes. Signals `polled` the first time its future is polled,
/// which is the rendezvous proving it is really in flight.
struct HangingInterceptor {
    polled: Arc<std::sync::Mutex<Option<oneshot::Sender<()>>>>,
}

#[async_trait]
impl DnsInterceptor for HangingInterceptor {
    async fn intercept(&self, _request: &[u8]) -> Option<Vec<u8>> {
        if let Some(tx) = self.polled.lock().unwrap().take() {
            let _ = tx.send(());
        }
        std::future::pending::<()>().await;
        unreachable!("pending future never resolves");
    }
}

#[skuld::test]
async fn intercept_returns_the_interceptors_reply() {
    let interceptor = AnsweringInterceptor { reply: vec![1, 2, 3] };
    let cancel = CancellationToken::new();

    let result = intercept(&interceptor, b"request", &cancel).await;

    match result {
        Intercepted::Reply(bytes) => assert_eq!(bytes, vec![1, 2, 3]),
        other => panic!("expected Reply, got {other:?}"),
    }
}

#[skuld::test]
async fn intercept_declines_when_the_interceptor_returns_none() {
    let calls = Arc::new(AtomicUsize::new(0));
    let interceptor = DecliningInterceptor { calls: calls.clone() };
    let cancel = CancellationToken::new();

    let result = intercept(&interceptor, b"request", &cancel).await;

    assert!(matches!(result, Intercepted::Declined));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[skuld::test]
async fn a_hanging_interceptor_is_abandoned_when_the_driver_is_cancelled() {
    let (polled_tx, polled_rx) = oneshot::channel();
    let interceptor = HangingInterceptor {
        polled: Arc::new(std::sync::Mutex::new(Some(polled_tx))),
    };
    let cancel = CancellationToken::new();

    let fut = intercept(&interceptor, b"request", &cancel);
    tokio::pin!(fut);

    // Poll the intercept future exactly once, proven by the interceptor
    // signalling it was polled. The interceptor's own arm resolving is
    // the failure — it never completes.
    tokio::select! {
        biased;
        _ = polled_rx => {}
        _ = &mut fut => panic!("interceptor future resolved; it must hang forever"),
    }

    cancel.cancel();
    let result = fut.await;

    assert!(matches!(result, Intercepted::Cancelled));
}

#[skuld::test]
async fn an_already_cancelled_driver_never_calls_the_interceptor() {
    let calls = Arc::new(AtomicUsize::new(0));
    let interceptor = DecliningInterceptor { calls: calls.clone() };
    let cancel = CancellationToken::new();
    cancel.cancel();

    let result = intercept(&interceptor, b"request", &cancel).await;

    assert!(matches!(result, Intercepted::Cancelled));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
