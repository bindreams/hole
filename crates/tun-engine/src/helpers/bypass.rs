//! Bypass-path socket helpers — interface binding + TCP/UDP connect.

use std::net::{IpAddr, SocketAddr};

use tokio::net::TcpStream;

use crate::net::{bind_to_interface_v4, bind_to_interface_v6};

// Bypass TCP connect ==================================================================================================

/// Open a TCP connection via a specific upstream interface, bypassing any
/// TUN device on the host.
pub async fn create_bypass_tcp(dst_ip: IpAddr, dst_port: u16, iface_index: u32) -> std::io::Result<TcpStream> {
    let dst = SocketAddr::new(dst_ip, dst_port);
    let tcp_socket = match dst_ip {
        IpAddr::V4(_) => {
            let sock = tokio::net::TcpSocket::new_v4()?;
            let raw = socket2::SockRef::from(&sock);
            bind_to_interface_v4(&raw, iface_index)?;
            sock
        }
        IpAddr::V6(_) => {
            let sock = tokio::net::TcpSocket::new_v6()?;
            let raw = socket2::SockRef::from(&sock);
            bind_to_interface_v6(&raw, iface_index)?;
            sock
        }
    };
    tcp_socket.connect(dst).await
}

// Bypass UDP socket ===================================================================================================

/// Create an unconnected UDP socket bound to a specific upstream interface.
pub async fn create_bypass_udp(iface_index: u32, v6: bool) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = if v6 {
        let s = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        bind_to_interface_v6(&s, iface_index)?;
        s
    } else {
        let s = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        bind_to_interface_v4(&s, iface_index)?;
        s
    };
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_socket)
}

#[cfg(test)]
#[path = "bypass_tests.rs"]
mod bypass_tests;
