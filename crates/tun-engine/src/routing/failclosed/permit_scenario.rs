//! Runs a privileged test's engage-probe-teardown scenario under the egress window.

use std::path::Path;

use hole_test_observability::egress::{rerun_until_network_holds, Failure};

use super::cover_oracle::held_covers;

/// [`rerun_until_network_holds`] over `held_covers(state_dir)`; panics with `why` on a defect. The
/// scenario returns its [`Failure`] after dropping its cover.
#[track_caller]
pub(crate) fn permit_scenario<T>(
    what: &str,
    state_dir: &Path,
    control: &str,
    scenario: impl FnMut() -> Result<T, Failure>,
) -> T {
    rerun_until_network_holds(what, control, &|| held_covers(state_dir), scenario).unwrap_or_else(|why| panic!("{why}"))
}
