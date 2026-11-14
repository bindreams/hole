package main

import "golang.org/x/sys/unix"

// setTCPKeepAlive enables SO_KEEPALIVE on the socket fd and sets the idle,
// interval and probe-count options from p. Darwin has no TCP_KEEPIDLE; its idle
// option is TCP_KEEPALIVE.
func setTCPKeepAlive(fd uintptr, p keepAliveParams) error {
	s := int(fd)
	if err := unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1); err != nil {
		return newError("failed to set SO_KEEPALIVE").Base(err)
	}
	if err := unix.SetsockoptInt(s, unix.IPPROTO_TCP, unix.TCP_KEEPALIVE, int(p.IdleSeconds)); err != nil {
		return newError("failed to set TCP_KEEPALIVE").Base(err)
	}
	if err := unix.SetsockoptInt(s, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, int(p.IntervalSeconds)); err != nil {
		return newError("failed to set TCP_KEEPINTVL").Base(err)
	}
	if err := unix.SetsockoptInt(s, unix.IPPROTO_TCP, unix.TCP_KEEPCNT, int(p.Probes)); err != nil {
		return newError("failed to set TCP_KEEPCNT").Base(err)
	}
	return nil
}
