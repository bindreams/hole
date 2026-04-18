//! Low-level networking utilities used across the crate.
//!
//! Currently holds the platform-specific socket-to-interface binding helpers
//! (`IP_UNICAST_IF` / `IPV6_UNICAST_IF` on Windows, `IP_BOUND_IF` /
//! `IPV6_BOUND_IF` on macOS). Kept here rather than in `device` because
//! gateway discovery needs them but has no other device coupling.

use socket2::Socket;

// Windows =============================================================================================================

/// Bind an IPv4 socket to an interface by index.
#[cfg(target_os = "windows")]
pub fn bind_to_interface_v4(socket: &Socket, index: u32) -> std::io::Result<()> {
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

/// Bind an IPv6 socket to an interface by index.
#[cfg(target_os = "windows")]
pub fn bind_to_interface_v6(socket: &Socket, index: u32) -> std::io::Result<()> {
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

// macOS ===============================================================================================================

#[cfg(target_os = "macos")]
const IP_BOUND_IF: libc::c_int = 25;

/// Bind an IPv4 socket to an interface by index.
#[cfg(target_os = "macos")]
pub fn bind_to_interface_v4(socket: &Socket, index: u32) -> std::io::Result<()> {
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

/// Bind an IPv6 socket to an interface by index.
#[cfg(target_os = "macos")]
pub fn bind_to_interface_v6(socket: &Socket, index: u32) -> std::io::Result<()> {
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
