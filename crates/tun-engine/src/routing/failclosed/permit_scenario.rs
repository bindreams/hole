//! Runs a privileged test's engage-probe-teardown scenario under the egress [`Window`] bracket.
//!
//! [`Window`]: hole_test_observability::egress::Window

use std::path::Path;

use super::cover_oracle::held_covers;

/// Run `scenario` (engage a cover, probe while it is engaged, drop the cover) until it holds. It returns
/// `Err(why)` AFTER dropping its cover when a permit probe failed; whether that is the network or the
/// cover is decided by [`hole_test_observability::egress::rerun_until_network_holds`], with `control`
/// probed outside the cover. Panics with `why` when the permit really failed.
#[track_caller]
pub(crate) fn permit_scenario<T>(
    what: &str,
    state_dir: &Path,
    control: &str,
    scenario: impl FnMut() -> Result<T, String>,
) -> T {
    hole_test_observability::egress::rerun_until_network_holds(what, control, &|| held_covers(state_dir), scenario)
        .unwrap_or_else(|why| panic!("{why}"))
}
