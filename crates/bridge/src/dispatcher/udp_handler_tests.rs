use std::sync::atomic::AtomicBool;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::UdpReply;
use crate::dispatcher::block_log::BlockLog;
use crate::dispatcher::tcp_handler::HandlerContext;
use crate::dispatcher::udp_flow::FlowHandle;
use crate::dispatcher::upstream_dns::UpstreamResolver;
use crate::filter::rules::RuleSet;

#[skuld::test]
fn udp_reply_fields() {
    let reply = UdpReply {
        dst_ip: "10.0.0.1".parse().unwrap(),
        dst_port: 12345,
        src_ip: "8.8.8.8".parse().unwrap(),
        src_port: 443,
        payload: vec![1, 2, 3],
    };
    assert_eq!(reply.payload.len(), 3);
    assert_eq!(reply.dst_port, 12345);
    assert_eq!(reply.src_port, 443);
}

/// When `udp_proxy_available` is false (v2ray-plugin configured) and the
/// filter engine returns Proxy, the flow must be blocked, not bypassed.
#[skuld::test]
fn udp_proxy_unavailable_blocks() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let ctx = HandlerContext {
            local_port: 1080,
            iface_index: 0,
            ipv6_available: false,
            upstream_resolver: UpstreamResolver::new(&["127.0.0.1".parse().unwrap()]),
            block_log: std::sync::Mutex::new(BlockLog::new()),
            ipv6_bypass_warned: AtomicBool::new(false),
            udp_proxy_available: false,
        };

        // Empty ruleset: terminal fallback returns FilterAction::Proxy.
        let rules = RuleSet::default();
        let (reply_tx, _reply_rx) = mpsc::channel::<UdpReply>(1);
        let cancel = CancellationToken::new();

        let entry = super::create_udp_flow_inner(
            "10.0.0.1".parse().unwrap(), // src_ip
            12345,                       // src_port
            "8.8.8.8".parse().unwrap(),  // dst_ip
            443,                         // dst_port
            &None,                       // domain
            None,                        // pinned_ip
            &ctx,
            &rules,
            &None, // fake_dns
            reply_tx,
            cancel,
        )
        .await
        .expect("create_udp_flow_inner should not fail for a blocked flow");

        assert!(matches!(entry.handle, FlowHandle::Blocked));
    });
}
