//! smoltcp `Device` implementation backed by in-memory queues.
//!
//! The engine owns this shim between the real OS TUN device and the
//! smoltcp userspace stack: packets read from the TUN are enqueued into
//! `rx_queue` and smoltcp pulls them via [`receive`](VirtualTunDevice::receive);
//! packets smoltcp wants to send go into `tx_queue` and the engine drains
//! them via [`dequeue_tx`](VirtualTunDevice::dequeue_tx) into the real TUN.

use std::collections::VecDeque;

use smoltcp::phy::{self, Checksum, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

pub struct VirtualTunDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl VirtualTunDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }

    /// Enqueue a packet received from the real TUN device.
    pub fn enqueue_rx(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }

    /// Dequeue all packets smoltcp wants to send to the TUN.
    pub fn dequeue_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx_queue.drain(..).collect()
    }

    /// Check if there are packets waiting to be sent to the TUN.
    #[allow(dead_code)]
    pub fn has_tx(&self) -> bool {
        !self.tx_queue.is_empty()
    }
}

impl Device for VirtualTunDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_front()?;
        Some((
            RxToken { buffer: packet },
            TxToken {
                queue: &mut self.tx_queue,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // Don't verify checksums on received packets. TUN adapters (wintun
        // on Windows, utun on macOS) deliver packets without computing
        // transport-layer checksums — the OS relies on NIC hardware
        // offloading, which a virtual adapter lacks. Still compute checksums
        // on transmitted packets so the OS accepts them.
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;
        caps.checksum.icmpv6 = Checksum::Tx;
        caps
    }
}

pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

pub struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}

#[cfg(test)]
#[path = "virtual_device_tests.rs"]
mod virtual_device_tests;
