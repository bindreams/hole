#[cfg(target_os = "macos")]
use crate::dns_state::DnsPrior;
#[cfg(target_os = "macos")]
use std::net::{IpAddr, Ipv4Addr};

// Timing-log instrumentation tests ====================================================================================
//
// These tests verify the per-operation diagnostic timing logs fire. They
// live outside the `macos_parsers` module because they invoke real OS
// commands (networksetup) / the real Win32Real FFI wrapper, which the
// parser tests deliberately avoid.

#[cfg(target_os = "windows")]
mod windows_timing_logs {
    use crate::dns::system::windows::{Win32Real, WinDnsBackend};
    use crate::test_support::log_capture::VecWriter;
    use garter::tracing_test::set_default_in_current_thread;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    /// `Win32Real::flush` calls the `DnsFlushResolverCache` FFI inline
    /// (ms-scale). This test guards that it stays inline (no subprocess
    /// detach) by asserting it returns quickly. Calls `Win32Real` directly
    /// — production reaches this exact call through `SystemDnsApplied`'s
    /// `flush` on shutdown.
    #[skuld::test]
    fn flush_returns_quickly() {
        let start = std::time::Instant::now();
        let _ = Win32Real.flush();
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(200),
            "Win32Real::flush must complete quickly; returned after {elapsed:?} — the Win32 \
             DnsFlushResolverCache FFI should be ms-scale."
        );
    }

    /// `Win32Real::get_settings` emits a per-alias DEBUG timing log. Uses a
    /// nonexistent adapter so the test doesn't depend on host network
    /// configuration — `ConvertInterfaceAliasToLuid` returns
    /// ERROR_INVALID_PARAMETER quickly and the timing log still fires. This
    /// is the upgrade sweep's ONLY read path.
    #[skuld::test]
    fn get_settings_emits_per_alias_elapsed_ms_debug_log() {
        let writer = VecWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
        );
        let _guard = set_default_in_current_thread(subscriber);

        let _ = Win32Real.get_settings("hole-test-bogus-adapter-xyz");

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

// State-file surface ==================================================================================================

/// `Dns::apply`'s signature carries no `state_dir` — there is nothing to
/// persist: DNS confinement is a process-scoped WFP session, not a file.
/// This is a structural pin: a full apply/shutdown cycle must not leave
/// `bridge-dns.json` anywhere a test can observe, even in a directory
/// `apply` was never told about, because it has no path parameter through
/// which it COULD write one.
#[cfg(target_os = "windows")]
#[skuld::test]
#[allow(clippy::disallowed_methods)] // one-shot token: no cooperative-cancel chain to join in a leaf test
async fn dns_apply_writes_no_state_file() {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    use crate::dns::system::windows::{DnsConfiner, WinDnsBackend};
    use crate::dns::system::{Dns, DnsApplied, SystemDns};
    use crate::dns_state::{AdapterId, DnsPrior, DnsPriorAdapter};

    struct NoopBackend;
    impl WinDnsBackend for NoopBackend {
        fn get_settings(&self, alias: &str) -> std::io::Result<Option<DnsPriorAdapter>> {
            Ok(Some(DnsPriorAdapter {
                id: AdapterId::WindowsAlias {
                    value: alias.to_string(),
                },
                name_at_capture: alias.to_string(),
                v4: DnsPrior::None,
                v6: DnsPrior::None,
            }))
        }
        fn set_servers(&self, _luid: u64, _servers: &[IpAddr]) -> std::io::Result<()> {
            Ok(())
        }
        fn restore(&self, _adapter: &DnsPriorAdapter) -> std::io::Result<()> {
            Ok(())
        }
        fn restore_family(&self, _alias: &str, _ipv6: bool, _prior: &DnsPrior) -> std::io::Result<()> {
            Ok(())
        }
        fn flush(&self) -> std::io::Result<()> {
            Ok(())
        }
    }
    struct NoopConfiner;
    impl DnsConfiner for NoopConfiner {
        fn engage(
            &self,
            _tun_luid: u64,
            _server_ip: IpAddr,
        ) -> Result<Box<dyn std::any::Any + Send>, tun_engine::dns_confine::DnsConfineError> {
            Ok(Box::new(()))
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let dns = SystemDns::new_with_backend(
        Arc::new(NoopBackend) as Arc<dyn WinDnsBackend>,
        Arc::new(NoopConfiner) as Arc<dyn DnsConfiner>,
    );
    let mut applied = dns
        .apply(
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            tun_engine::TunIdentity::synthetic(0xFEED, "hole-tun"),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            CancellationToken::new(),
        )
        .await
        .expect("apply should succeed");
    applied.shutdown().await;

    assert!(
        !dir.path().join(crate::dns_state::STATE_FILE_NAME).exists(),
        "apply/shutdown must never write bridge-dns.json — it has no state_dir to write one into"
    );
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
