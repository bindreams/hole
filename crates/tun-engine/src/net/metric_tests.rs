use super::*;

#[skuld::test]
fn absent_interface_row_is_an_outcome_not_an_error() {
    let result = classify_metric_status(ERROR_NOT_FOUND.0);
    assert!(
        matches!(result, Ok(MetricOutcome::NoInterfaceRow)),
        "ERROR_NOT_FOUND must classify as Ok(NoInterfaceRow), not Err — the caller must be able to \
         distinguish 'no IPv6 stack yet' from 'the call failed'; got {result:?}"
    );
}

#[skuld::test]
fn other_errors_propagate() {
    // ERROR_ACCESS_DENIED (5) — any status that isn't SUCCESS or NOT_FOUND
    // must propagate as Err, never be silently swallowed.
    let result = classify_metric_status(5);
    assert!(
        result.is_err(),
        "a non-NOT_FOUND failure status must propagate as Err, got {result:?}"
    );
}

#[skuld::test]
fn success_status_applies() {
    let result = classify_metric_status(ERROR_SUCCESS.0);
    assert!(
        matches!(result, Ok(MetricOutcome::Applied)),
        "ERROR_SUCCESS must classify as Ok(Applied), got {result:?}"
    );
}

#[skuld::test]
fn tunnel_metric_is_the_minimum() {
    assert_eq!(
        TUNNEL_INTERFACE_METRIC, 1,
        "the tunnel's metric must be the minimum possible value"
    );
}
