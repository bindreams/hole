#[cfg(any(target_os = "windows", target_os = "macos"))]
use crate::dns_state::DnsPrior;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::net::{IpAddr, Ipv4Addr};

#[cfg(target_os = "windows")]
use std::net::Ipv6Addr;

// Timing-log instrumentation tests (#247) =============================================================================
//
// These tests verify that Phase 1 diagnostic logs fire. They live outside
// the `windows_parsers` / `macos_parsers` modules because they exercise
// real OS command invocations (netsh / networksetup), which the parser
// tests deliberately avoid.

#[cfg(target_os = "windows")]
mod windows_timing_logs {
    use crate::dns::system::windows::flush_dns_cache;
    use crate::test_support::log_capture::VecWriter;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};
    use tracing_subscriber::util::SubscriberInitExt;

    /// `flush_dns_cache` must emit a `DEBUG` log with an `elapsed_ms`
    /// field so Phase 2 observation can see how long `ipconfig /flushdns`
    /// actually takes. This is the minimum-viable timing probe — if this
    /// test regresses, the entire Phase-1 diagnostic story is broken.
    #[skuld::test]
    fn flush_dns_cache_emits_elapsed_ms_debug_log() {
        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
        );
        let _guard = subscriber.set_default();

        flush_dns_cache();

        let output = writer.snapshot_string();
        assert!(
            output.contains("elapsed_ms"),
            "expected 'elapsed_ms' field in captured log; got:\n{output}"
        );
        assert!(output.contains("DEBUG"), "expected DEBUG-level log; got:\n{output}");
        assert!(
            output.contains("flush_dns_cache"),
            "expected 'flush_dns_cache' target/message in log; got:\n{output}"
        );
    }

    /// `capture_adapters` must emit per-alias DEBUG timing logs so a slow
    /// netsh query against a freshly-created TUN adapter is visible in
    /// Phase 2 logs. Uses a nonexistent adapter name so the test doesn't
    /// depend on any specific network configuration — `netsh show` will
    /// return "not found" quickly, and the timing log fires regardless.
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
        let _guard = subscriber.set_default();

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

// Windows parser tests ================================================================================================

#[cfg(target_os = "windows")]
mod windows_parsers {
    use super::{DnsPrior, IpAddr, Ipv4Addr, Ipv6Addr};
    use crate::dns::system::windows::parse_netsh_dnsservers;

    #[skuld::test]
    fn parse_static_single() {
        let out = "
Configuration for interface \"Ethernet\"
    Statically Configured DNS Servers:  1.1.1.1
    Register with which suffix:         Primary only
";
        let p = parse_netsh_dnsservers(out);
        match p {
            DnsPrior::Static { servers } => {
                assert_eq!(servers, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[skuld::test]
    fn parse_static_multiple() {
        let out = "
Configuration for interface \"Ethernet\"
    Statically Configured DNS Servers:  1.1.1.1
                                        8.8.8.8
                                        9.9.9.9
    Register with which suffix:         Primary only
";
        let p = parse_netsh_dnsservers(out);
        match p {
            DnsPrior::Static { servers } => {
                assert_eq!(
                    servers,
                    vec![
                        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                        IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                    ]
                );
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[skuld::test]
    fn parse_dhcp_with_ip() {
        let out = "
Configuration for interface \"Ethernet\"
    DNS servers configured through DHCP:  192.168.1.1
    Register with which suffix:           Primary only
";
        let p = parse_netsh_dnsservers(out);
        assert!(matches!(p, DnsPrior::Dhcp));
    }

    #[skuld::test]
    fn parse_dhcp_none() {
        let out = "
Configuration for interface \"Wi-Fi\"
    DNS servers configured through DHCP:  None
    Register with which suffix:           Primary only
";
        let p = parse_netsh_dnsservers(out);
        assert!(matches!(p, DnsPrior::None));
    }

    #[skuld::test]
    fn parse_empty_output_returns_none() {
        let p = parse_netsh_dnsservers("");
        assert!(matches!(p, DnsPrior::None));
    }

    #[skuld::test]
    fn parse_ipv6_static() {
        let out = "
    Statically Configured DNS Servers:  2606:4700:4700::1111
";
        let p = parse_netsh_dnsservers(out);
        match p {
            DnsPrior::Static { servers } => {
                assert_eq!(
                    servers,
                    vec![IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111))]
                );
            }
            other => panic!("expected Static, got {other:?}"),
        }
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
