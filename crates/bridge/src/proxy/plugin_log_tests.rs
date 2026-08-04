use super::*;
use crate::test_support::log_capture::VecWriter;
use tracing_subscriber::layer::{Layer, SubscriberExt};

/// Capture the WARNs `warn_recent` emits for this log.
fn emitted_for(log: &PluginLog) -> String {
    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        warn_recent(log);
    }
    writer.snapshot_string()
}

#[skuld::test]
fn the_ring_keeps_the_newest_lines() {
    let log = PluginLog::new();
    for i in 0..RECENT_LINES + 5 {
        log.push_line(&format!("line {i}"));
    }
    let recent = log.recent();
    assert_eq!(recent.len(), RECENT_LINES);
    assert_eq!(recent.first().unwrap(), "line 5");
    assert_eq!(recent.last().unwrap(), &format!("line {}", RECENT_LINES + 4));
}

#[skuld::test]
fn the_sink_feeds_the_ring() {
    let log = PluginLog::new();
    let sink = log.sink();
    sink("transport/internet/tls: ECH required but no ECH config could be obtained");
    assert_eq!(
        log.recent(),
        vec!["transport/internet/tls: ECH required but no ECH config could be obtained".to_string()]
    );
}

/// The plugin's own explanation is emitted next to the failure it explains.
#[skuld::test]
fn warn_recent_emits_the_header_and_every_line() {
    let log = PluginLog::new();
    log.push_line("transport/internet/tls: ECH required but no ECH config could be obtained");
    log.push_line("v2ray.com/core/transport/internet/websocket: failed to dial WebSocket");
    let output = emitted_for(&log);
    assert!(output.contains(PLUGIN_OUTPUT_HEADER), "got:\n{output}");
    assert!(output.contains("ECH required"), "got:\n{output}");
    assert!(output.contains("failed to dial WebSocket"), "got:\n{output}");
}

/// An empty ring reports what was CAPTURED, never that the plugin said nothing:
/// garter relays from a detached task, so the two are not the same claim.
#[skuld::test]
fn warn_recent_says_so_when_nothing_was_captured() {
    let output = emitted_for(&PluginLog::new());
    assert!(output.contains(NO_PLUGIN_OUTPUT), "got:\n{output}");
    assert!(!output.contains(PLUGIN_OUTPUT_HEADER), "got:\n{output}");
}
