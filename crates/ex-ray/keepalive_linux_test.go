package main

import "golang.org/x/sys/unix"

// readTCPKeepAlive is test-only: production never reads these options back.
// The _linux_test.go suffix carries the same GOOS constraint as its
// production sibling, so it compiles exactly where that one does.
func readTCPKeepAlive(fd uintptr) (keepAliveParams, bool, error) {
	s := int(fd)
	on, err := unix.GetsockoptInt(s, unix.SOL_SOCKET, unix.SO_KEEPALIVE)
	if err != nil {
		return keepAliveParams{}, false, newError("failed to read SO_KEEPALIVE").Base(err)
	}
	idle, err := unix.GetsockoptInt(s, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE)
	if err != nil {
		return keepAliveParams{}, false, newError("failed to read TCP_KEEPIDLE").Base(err)
	}
	intvl, err := unix.GetsockoptInt(s, unix.IPPROTO_TCP, unix.TCP_KEEPINTVL)
	if err != nil {
		return keepAliveParams{}, false, newError("failed to read TCP_KEEPINTVL").Base(err)
	}
	cnt, err := unix.GetsockoptInt(s, unix.IPPROTO_TCP, unix.TCP_KEEPCNT)
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
