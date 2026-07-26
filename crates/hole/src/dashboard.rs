//! Tracks the single dashboard window's identity so the tray, menu, and
//! single-instance paths can reveal a live window or build a fresh one
//! without racing Tauri's destroy-on-close teardown (#466).

use std::sync::Mutex;

/// At most one dashboard window is open at a time. Each built window gets a
/// unique, monotonic label (`dashboard-{n}`) so a new window never collides
/// with a still-closing one. Tauri-managed. The `Mutex` is load-bearing:
/// writes come from the main thread, while the self-heal path reads
/// `current_label` from the tokio runtime.
pub struct DashboardWindow {
    inner: Mutex<Inner>,
}

struct Inner {
    /// Generation of the live dashboard, or `None` when none is open.
    current: Option<u64>,
    /// Next generation to hand out.
    next: u64,
}

impl Default for DashboardWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl DashboardWindow {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner { current: None, next: 0 }),
        }
    }

    /// Label of the live dashboard, or `None` if none is open.
    pub fn current_label(&self) -> Option<String> {
        self.inner.lock().unwrap().current.map(label_for)
    }

    /// Allocate a fresh generation, mark it the current dashboard, and return
    /// `(generation, label)`. On build failure the caller calls
    /// [`forget`](Self::forget) with `generation`.
    pub fn allocate(&self) -> (u64, String) {
        let mut inner = self.inner.lock().unwrap();
        let generation = inner.next;
        inner.next += 1;
        inner.current = Some(generation);
        (generation, label_for(generation))
    }

    /// The window of `generation` is going away. Clears the current dashboard
    /// iff it still points at `generation`, so a stale window's close can
    /// never forget a newer dashboard.
    pub fn forget(&self, generation: u64) {
        let mut inner = self.inner.lock().unwrap();
        if inner.current == Some(generation) {
            inner.current = None;
        }
    }
}

/// Window label for a dashboard generation. Must match the capability glob
/// `dashboard-*` in `capabilities/default.json`.
fn label_for(generation: u64) -> String {
    format!("dashboard-{generation}")
}

#[cfg(test)]
#[path = "dashboard_tests.rs"]
mod dashboard_tests;
