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

func readTCPKeepAlive(fd uintptr) (keepAliveParams, bool, error) {
	h := windows.Handle(fd)
	on, err := windows.GetsockoptInt(h, windows.SOL_SOCKET, windows.SO_KEEPALIVE)
	if err != nil {
		return keepAliveParams{}, false, newError("failed to read SO_KEEPALIVE").Base(err)
	}
	idle, err := windows.GetsockoptInt(h, windows.IPPROTO_TCP, windows.TCP_KEEPIDLE)
	if err != nil {
		return keepAliveParams{}, false, newError("failed to read TCP_KEEPIDLE").Base(err)
	}
	intvl, err := windows.GetsockoptInt(h, windows.IPPROTO_TCP, windows.TCP_KEEPINTVL)
	if err != nil {
		return keepAliveParams{}, false, newError("failed to read TCP_KEEPINTVL").Base(err)
	}
	cnt, err := windows.GetsockoptInt(h, windows.IPPROTO_TCP, windows.TCP_KEEPCNT)
	if err != nil {
		return keepAliveParams{}, false, newError("failed to read TCP_KEEPCNT").Base(err)
	}
	idle32, err := sockoptInt32("TCP_KEEPIDLE", idle)
	if err != nil {
		return keepAliveParams{}, false, err
	}
	intvl32, err := sockoptInt32("TCP_KEEPINTVL", intvl)
	if err != nil {
		return keepAliveParams{}, false, err
	}
	cnt32, err := sockoptInt32("TCP_KEEPCNT", cnt)
	if err != nil {
		return keepAliveParams{}, false, err
	}
	return keepAliveParams{
		IdleSeconds:     idle32,
		IntervalSeconds: intvl32,
		Probes:          cnt32,
	}, on != 0, nil
}
