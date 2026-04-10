use super::UdpReply;

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
