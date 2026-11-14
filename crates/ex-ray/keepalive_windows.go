package main

import "golang.org/x/sys/windows"

// setTCPKeepAlive enables SO_KEEPALIVE on the socket fd and sets the idle,
// interval and probe-count options from p. Windows exposes the three timings as
// ordinary setsockopt options from build 10.0.16299; below that they are
// rejected (Go's stdlib falls back to SIO_KEEPALIVE_VALS) and this returns an
// error.
func setTCPKeepAlive(fd uintptr, p keepAliveParams) error {
	h := windows.Handle(fd)
	if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_KEEPALIVE, 1); err != nil {
		return newError("failed to set SO_KEEPALIVE").Base(err)
	}
	if err := windows.SetsockoptInt(h, windows.IPPROTO_TCP, windows.TCP_KEEPIDLE, int(p.IdleSeconds)); err != nil {
		return newError("failed to set TCP_KEEPIDLE").Base(err)
	}
	if err := windows.SetsockoptInt(h, windows.IPPROTO_TCP, windows.TCP_KEEPINTVL, int(p.IntervalSeconds)); err != nil {
		return newError("failed to set TCP_KEEPINTVL").Base(err)
	}
	if err := windows.SetsockoptInt(h, windows.IPPROTO_TCP, windows.TCP_KEEPCNT, int(p.Probes)); err != nil {
		return newError("failed to set TCP_KEEPCNT").Base(err)
	}
	return nil
}
