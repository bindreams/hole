#[cfg(target_os = "macos")]
use crate::dns_state::DnsPrior;
#[cfg(target_os = "macos")]
use std::net::{IpAddr, Ipv4Addr};

// Timing-log instrumentation tests ====================================================================================
//
// These tests verify the per-operation diagnostic timing logs fire. They
// live outside the `macos_parsers` module because they invoke real OS
// commands (networksetup), which the parser tests deliberately avoid.

#[cfg(target_os = "windows")]
mod windows_timing_logs {
    use crate::dns::system::windows::flush_dns_cache;
    use crate::test_support::log_capture::VecWriter;
    use garter::tracing_test::set_default_in_current_thread;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    /// `flush_dns_cache` calls the `DnsFlushResolverCache` FFI inline
    /// (ms-scale). This test guards that it stays inline (no subprocess
    /// detach) by asserting it returns quickly.
    #[skuld::test]
    fn flush_dns_cache_returns_quickly() {
        let start = std::time::Instant::now();
        flush_dns_cache();
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "flush_dns_cache must complete quickly; \
             returned after {elapsed:?} — the Win32 DnsFlushResolverCache \
             FFI should be ms-scale."
        );
    }

    /// `capture_adapters` routes through `Win32Real::get_settings`, which
    /// emits per-alias DEBUG timing logs. Uses a nonexistent adapter so the
    /// test doesn't
    /// depend on host network configuration — `ConvertInterfaceAliasToLuid`
    /// returns ERROR_INVALID_PARAMETER quickly and the timing log fires.
    #[skuld::test]
    fn capture_adapters_emits_per_alias_elapsed_ms_debug_log() {
        use crate::dns::system::capture_adapters;

        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
        );
        let _guard = set_default_in_current_thread(subscriber);

        let _ = capture_adapters(&["hole-test-bogus-adapter-xyz".to_string()]);

        let output = writer.snapshot_string();
        assert!(
            output.contains("elapsed_ms"),
            "expected 'elapsed_ms' in captured log; got:\n{output}"
        );
        assert!(
            output.contains("hole-test-bogus-adapter-xyz"),
            "expected alias in log; got:\n{output}"
        );
    }
}

// macOS parser tests ==================================================================================================

#[cfg(target_os = "macos")]
mod macos_parsers {
    use super::{DnsPrior, IpAddr, Ipv4Addr};
    use crate::dns::system::macos::parse_networksetup_output;

    #[skuld::test]
    fn parse_empty_reports_dhcp() {
        let out = "There aren't any DNS Servers set on Wi-Fi.\n";
        let p = parse_networksetup_output(out);
        assert!(matches!(p, DnsPrior::Dhcp));
    }

    #[skuld::test]
    fn parse_multiple_ips() {
        let out = "1.1.1.1\n2606:4700:4700::1111\n";
        let p = parse_networksetup_output(out);
        match p {
            DnsPrior::Static { servers } => {
                assert_eq!(servers.len(), 2);
                assert!(servers.contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }
}
