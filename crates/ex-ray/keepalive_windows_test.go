package main

import "golang.org/x/sys/windows"

// readTCPKeepAlive is test-only: production never reads these options back.
// The _windows_test.go suffix carries the same GOOS constraint as its
// production sibling, so it compiles exactly where that one does.
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
