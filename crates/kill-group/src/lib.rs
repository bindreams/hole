//! Process-tree kill-groups: spawn a child as the root of a group (Windows
//! Job Object with `KILL_ON_JOB_CLOSE` / Unix process group) whose whole
//! descendant tree can be signalled and killed as a unit, and is reaped as a
//! unit when the guard drops.
//!
//! Extracted from garter's `proc_group` (bindreams/hole#197, #448); see the
//! module docs in `grouped_child.rs` for the full design.

pub mod grouped_child;

pub use grouped_child::{GroupedChild, Nesting};

#[cfg(test)]
#[path = "grouped_child_tests.rs"]
mod grouped_child_tests;

#[cfg(test)]
pub mod test_child;

#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    test_child::maybe_run(); // takes over (never returns) in child mode
    skuld::run_all();
}
