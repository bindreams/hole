package main

import "golang.org/x/sys/windows"

// Windows exposes the three timings as ordinary setsockopt options from build
// 10.0.16299; below that they are rejected and Go's stdlib falls back to
// SIO_KEEPALIVE_VALS. Hole's installer refuses anything below build 19041
// (msi-installer/src/msi_installer/hole.wxs), so no installed build can reach
// the rejection.
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
