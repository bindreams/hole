use crate::yamux::{deframe_udp_datagram, frame_udp_datagram, StreamTag};

#[skuld::test]
fn stream_tag_tcp_roundtrip() {
    assert_eq!(StreamTag::Tcp.to_byte(), 0x01);
    assert_eq!(StreamTag::from_byte(0x01).unwrap(), StreamTag::Tcp);
}

#[skuld::test]
fn stream_tag_udp_roundtrip() {
    assert_eq!(StreamTag::Udp.to_byte(), 0x02);
    assert_eq!(StreamTag::from_byte(0x02).unwrap(), StreamTag::Udp);
}

#[skuld::test]
fn stream_tag_invalid() {
    assert!(StreamTag::from_byte(0x00).is_none());
    assert!(StreamTag::from_byte(0xFF).is_none());
}

#[skuld::test]
fn udp_frame_roundtrip() {
    let payload = b"hello udp";
    let framed = frame_udp_datagram(payload);
    assert_eq!(framed.len(), 2 + payload.len());
    let (decoded, rest) = deframe_udp_datagram(&framed).unwrap();
    assert_eq!(decoded, payload);
    assert!(rest.is_empty());
}

#[skuld::test]
fn udp_frame_max_size() {
    let payload = vec![0xABu8; 65535];
    let framed = frame_udp_datagram(&payload);
    let (decoded, _) = deframe_udp_datagram(&framed).unwrap();
    assert_eq!(decoded.len(), 65535);
}
