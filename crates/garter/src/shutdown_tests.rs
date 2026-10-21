// `CancellationToken::new` is the test root of the embedder's cancel scope.
#![allow(clippy::disallowed_methods)]

use tokio_util::sync::CancellationToken;

use crate::chain_tests::{test_env, InstantPlugin};
use crate::shutdown::registrations_on_this_thread;
use crate::ChainRunner;

#[skuld::test]
async fn a_runner_with_no_embedder_token_answers_process_signals_itself() {
    let before = registrations_on_this_thread();

    let _ = ChainRunner::new()
        .add(Box::new(InstantPlugin { name: "only".into() }))
        .run(test_env())
        .await;

    assert_eq!(registrations_on_this_thread() - before, 1);
}

#[skuld::test]
async fn a_runner_with_an_embedder_token_leaves_process_signals_to_the_embedder() {
    let before = registrations_on_this_thread();

    let _ = ChainRunner::new()
        .add(Box::new(InstantPlugin { name: "only".into() }))
        .cancel_token(CancellationToken::new())
        .run(test_env())
        .await;

    assert_eq!(registrations_on_this_thread() - before, 0);
}
