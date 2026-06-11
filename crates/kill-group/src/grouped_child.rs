//! Placeholder — replaced in full by the extraction task.
use tokio::process::Child;

/// See the extraction task; full docs arrive with the implementation.
pub struct GroupedChild {
    pub child: Child,
}

/// Whether descendants of this spawn are marked as inside the kill-group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nesting {
    Mark,
    Opaque,
}
