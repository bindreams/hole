//! Bypass-path socket helpers — interface binding + TCP connect.

use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;

// Interface binding helpers (shared) ==================================================================================

/// Bind an IPv4 socket to the upstream interface by index.
#[cfg(target_os = "windows")]
pub(crate) fn bind_to_interface_v4(socket: &socket2::Socket, index: u32) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    // IP_UNICAST_IF expects network byte order.
    let val = index.to_be();
    let ret = unsafe {
        windows::Win32::Networking::WinSock::setsockopt(
            windows::Win32::Networking::WinSock::SOCKET(socket.as_raw_socket() as usize),
            windows::Win32::Networking::WinSock::IPPROTO_IP.0,
            windows::Win32::Networking::WinSock::IP_UNICAST_IF,
            Some(std::slice::from_raw_parts(
                &val as *const u32 as *const u8,
                std::mem::size_of::<u32>(),
            )),
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Bind an IPv6 socket to the upstream interface by index.
#[cfg(target_os = "windows")]
pub(crate) fn bind_to_interface_v6(socket: &socket2::Socket, index: u32) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    // IPV6_UNICAST_IF expects host byte order (different from v4!).
    let ret = unsafe {
        windows::Win32::Networking::WinSock::setsockopt(
            windows::Win32::Networking::WinSock::SOCKET(socket.as_raw_socket() as usize),
            windows::Win32::Networking::WinSock::IPPROTO_IPV6.0,
            windows::Win32::Networking::WinSock::IPV6_UNICAST_IF,
            Some(std::slice::from_raw_parts(
                &index as *const u32 as *const u8,
                std::mem::size_of::<u32>(),
            )),
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
const IP_BOUND_IF: libc::c_int = 25;

/// Bind an IPv4 socket to the upstream interface by index.
#[cfg(target_os = "macos")]
pub(crate) fn bind_to_interface_v4(socket: &socket2::Socket, index: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            IP_BOUND_IF,
            &index as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Bind an IPv6 socket to the upstream interface by index.
#[cfg(target_os = "macos")]
pub(crate) fn bind_to_interface_v6(socket: &socket2::Socket, index: u32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_BOUND_IF,
            &index as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// Bypass TCP connect ==================================================================================================

/// Open a TCP connection via the upstream interface, bypassing the TUN device.
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

/// Create an unconnected UDP socket bound to the upstream interface.
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
