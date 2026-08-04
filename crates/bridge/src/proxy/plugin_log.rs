//! The plugin chain's most recent log lines, kept in memory so a start failure
//! can quote what the plugin itself reported.
//!
//! `bridge.log` already carries the line — seconds before the DNS self-test
//! gives up, and diluted by everything in between.
//!
//! Lines are raw, exactly as the child wrote them, including the sitrep JSON
//! frames garter parses. Nothing here classifies them.
//!
//! These are the plugin's own words and can name the server host, so they reach
//! `bridge.log` ONLY. Nothing here may be folded into a `ProxyError`: that
//! crosses IPC into `gui.log` and the toast.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Lines kept. Sized to span one full dial cycle at the `loglevel=debug` the
/// bridge injects, without holding an unbounded slice of a chatty plugin.
pub(crate) const RECENT_LINES: usize = 40;

pub(crate) const PLUGIN_OUTPUT_HEADER: &str =
    "the plugin chain's most recent output follows — the plugin's own account of why its transport failed";
pub(crate) const NO_PLUGIN_OUTPUT: &str = "the plugin chain logged nothing before the DNS self-test failed";
pub(crate) const NO_PLUGIN_CONFIGURED: &str =
    "no plugin chain is configured, so there is no plugin output to quote for this failure";

/// A bounded ring of the plugin chain's log lines, newest last.
#[derive(Debug, Default)]
pub struct PluginLog {
    lines: Mutex<VecDeque<String>>,
}

impl PluginLog {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The [`garter::LogSink`] that feeds this ring. The chain owns the ring and
    /// outlives the plugin process, so the sink holds a strong clone.
    pub fn sink(self: &Arc<Self>) -> garter::LogSink {
        let log = Arc::clone(self);
        Arc::new(move |line: &str| log.push_line(line))
    }

    pub(crate) fn push_line(&self, line: &str) {
        let mut lines = self.lines.lock().expect("poisoned");
        if lines.len() == RECENT_LINES {
            lines.pop_front();
        }
        lines.push_back(line.to_string());
    }

    /// The kept lines, oldest first.
    pub fn recent(&self) -> Vec<String> {
        self.lines.lock().expect("poisoned").iter().cloned().collect()
    }
}

/// Emit the plugin's kept lines at WARN, next to the failure they explain.
/// `bridge.log` only — see the module doc.
pub fn warn_recent(log: &PluginLog) {
    let lines = log.recent();
    if lines.is_empty() {
        tracing::warn!("{NO_PLUGIN_OUTPUT}");
        return;
    }
    tracing::warn!(count = lines.len(), "{PLUGIN_OUTPUT_HEADER}");
    for line in lines {
        tracing::warn!("plugin: {line}");
    }
}

#[cfg(test)]
#[path = "plugin_log_tests.rs"]
mod plugin_log_tests;
