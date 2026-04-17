use smoltcp::phy::{Checksum, Device, RxToken, TxToken};
use smoltcp::time::Instant;

use super::VirtualTunDevice;

#[skuld::test]
fn receive_returns_none_when_empty() {
    let mut dev = VirtualTunDevice::new(1400);
    assert!(dev.receive(Instant::ZERO).is_none());
}

#[skuld::test]
fn receive_returns_queued_packet() {
    let mut dev = VirtualTunDevice::new(1400);
    dev.enqueue_rx(vec![0x45, 0x00, 0x00, 0x14]);
    let (rx, _tx) = dev.receive(Instant::ZERO).unwrap();
    let data: Vec<u8> = rx.consume(|buf: &[u8]| buf.to_vec());
    assert_eq!(data, vec![0x45, 0x00, 0x00, 0x14]);
}

#[skuld::test]
fn transmit_enqueues_packet() {
    let mut dev = VirtualTunDevice::new(1400);
    {
        let token = dev.transmit(Instant::ZERO).unwrap();
        token.consume(4, |buf: &mut [u8]| {
            buf.copy_from_slice(&[0x45, 0x00, 0x00, 0x14]);
        });
    }
    let sent = dev.dequeue_tx();
    assert_eq!(sent.len(), 1);
    assert_eq!(&sent[0], &[0x45, 0x00, 0x00, 0x14]);
}

#[skuld::test]
fn capabilities_uses_ip_medium() {
    let dev = VirtualTunDevice::new(1400);
    let caps = dev.capabilities();
    assert_eq!(caps.medium, smoltcp::phy::Medium::Ip);
    assert_eq!(caps.max_transmission_unit, 1400);
}

#[skuld::test]
fn dequeue_tx_drains_all() {
    let mut dev = VirtualTunDevice::new(1400);
    dev.transmit(Instant::ZERO).unwrap().consume(2, |buf: &mut [u8]| {
        buf.copy_from_slice(&[1, 2]);
    });
    dev.transmit(Instant::ZERO).unwrap().consume(3, |buf: &mut [u8]| {
        buf.copy_from_slice(&[3, 4, 5]);
    });
    let sent = dev.dequeue_tx();
    assert_eq!(sent.len(), 2);
    assert!(!dev.has_tx());
}

#[skuld::test]
fn capabilities_skip_rx_checksum_verification() {
    let dev = VirtualTunDevice::new(1400);
    let caps = dev.capabilities();
    assert!(matches!(caps.checksum.ipv4, Checksum::Tx));
    assert!(matches!(caps.checksum.tcp, Checksum::Tx));
    assert!(matches!(caps.checksum.udp, Checksum::Tx));
    assert!(matches!(caps.checksum.icmpv4, Checksum::Tx));
    assert!(matches!(caps.checksum.icmpv6, Checksum::Tx));
}
