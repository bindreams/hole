use super::*;

fn offer(version: &str) -> UpdateInfo {
    UpdateInfo {
        version: ReleaseVersion::parse(version).unwrap(),
        asset_url: format!("https://example.com/{version}/asset"),
        asset_name: "asset".to_string(),
        sha256sums_url: "https://example.com/SHA256SUMS".to_string(),
        sha256sums_minisig_url: "https://example.com/SHA256SUMS.minisig".to_string(),
        html_url: Some(format!("https://example.com/releases/{version}")),
    }
}

fn checked(offer: Option<UpdateInfo>) -> UpdateCheck {
    UpdateCheck {
        offer,
        running_withdrawn: None,
    }
}

#[skuld::test]
fn the_offered_version_is_installed_when_the_check_still_returns_it() {
    let outcome = recheck_offer(&ReleaseVersion::parse("0.8.0").unwrap(), checked(Some(offer("0.8.0"))));

    assert_eq!(outcome, StaleOffer::Install(offer("0.8.0")));
}

#[skuld::test]
fn an_offer_the_check_no_longer_returns_is_not_installed() {
    let now = checked(None);

    let outcome = recheck_offer(&ReleaseVersion::parse("0.8.0").unwrap(), now.clone());

    assert_eq!(
        outcome,
        StaleOffer::Replaced {
            offered: ReleaseVersion::parse("0.8.0").unwrap(),
            now,
        }
    );
}

#[skuld::test]
fn a_newer_offer_replaces_the_stale_one_without_installing() {
    let now = checked(Some(offer("0.8.1")));

    let outcome = recheck_offer(&ReleaseVersion::parse("0.8.0").unwrap(), now.clone());

    assert_eq!(
        outcome,
        StaleOffer::Replaced {
            offered: ReleaseVersion::parse("0.8.0").unwrap(),
            now,
        }
    );
}

#[skuld::test]
fn checks_are_stored_in_the_order_they_ran() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let state = std::sync::Arc::new(UpdateState::default());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        // The first check runs until the test releases it.
        let first = tokio::spawn({
            let state = state.clone();
            async move {
                state
                    .check_and_store(move || {
                        started_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok(checked(Some(offer("0.8.0"))))
                    })
                    .await
            }
        });
        started_rx.await.unwrap();

        // While it runs, no other check may start.
        assert!(state.check_lock.try_lock().is_err(), "a check is running");

        // The second check starts only once the first one's result is stored.
        let seen_by_second = std::sync::Arc::new(std::sync::Mutex::new(None));
        let second = tokio::spawn({
            let state = state.clone();
            let for_check = state.clone();
            let seen = seen_by_second.clone();
            async move {
                state
                    .check_and_store(move || {
                        *seen.lock().unwrap() = Some(state_of(&for_check));
                        Ok(checked(Some(offer("0.8.1"))))
                    })
                    .await
            }
        });
        release_tx.send(()).unwrap();

        let first = first.await.unwrap().unwrap();
        let second = second.await.unwrap().unwrap();

        assert!(first.changed && second.changed);
        assert_eq!(
            seen_by_second.lock().unwrap().clone(),
            Some(checked(Some(offer("0.8.0")))),
            "what the second check found stored when it started"
        );
        assert_eq!(state_of(&state), checked(Some(offer("0.8.1"))));
    });
}

fn state_of(state: &UpdateState) -> UpdateCheck {
    state.rx.borrow().clone()
}
