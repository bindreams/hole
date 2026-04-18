use super::*;

#[skuld::test]
fn default_has_sensible_values() {
    let c = MutEngineConfig::default();
    assert_eq!(c.max_connections, 4096);
    assert_eq!(c.max_sniffers, 1024);
    assert_eq!(c.tcp_rx_buf_size, 65536);
    assert_eq!(c.tcp_tx_buf_size, 65536);
    assert_eq!(c.poll_interval, std::time::Duration::from_millis(1));
    assert_eq!(c.idle_sweep_interval, std::time::Duration::from_secs(5));
    assert_eq!(c.udp_flow_idle_timeout, std::time::Duration::from_secs(30));
    assert!(c.dns_interceptor.is_none());
}

#[skuld::test]
#[allow(clippy::field_reassign_with_default)]
fn freeze_preserves_overrides() {
    let mut c = MutEngineConfig::default();
    c.max_connections = 8;
    let f = c.freeze();
    assert_eq!(f.max_connections, 8);
    assert_eq!(f.max_sniffers, 1024); // other defaults preserved
}
