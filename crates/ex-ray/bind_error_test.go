package main

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestClassifyBindError(t *testing.T) {
	bindAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1984}
	listen := &net.OpError{Op: "listen", Net: "tcp", Addr: bindAddr, Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	wrappedListen := newError("failed to listen TCP on 1984").Base(
		newError("failed to listen TCP on 127.0.0.1:1984").Base(listen))
	dial := &net.OpError{Op: "dial", Net: "tcp", Addr: bindAddr, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	listenNoErrno := &net.OpError{Op: "listen", Net: "tcp", Addr: bindAddr, Err: errors.New("opaque")}
	// A nil Addr yields addr "" — the case main()'s localListenAddr fallback covers.
	listenNilAddr := &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}

	cases := []struct {
		name         string
		err          error
		wantErrno    int
		wantAddr     string
		wantConflict bool
	}{
		{"wrapped listen EADDRINUSE", wrappedListen, int(syscall.EADDRINUSE), "127.0.0.1:1984", true},
		{"bare listen EADDRINUSE", listen, int(syscall.EADDRINUSE), "127.0.0.1:1984", true},
		{"dial ECONNREFUSED is not a bind conflict", dial, 0, "", false},
		{"plain config error is not a bind conflict", newError("bad config"), 0, "", false},
		{"listen without a raw errno", listenNoErrno, 0, "127.0.0.1:1984", true},
		{"listen with nil Addr yields empty addr", listenNilAddr, int(syscall.EADDRINUSE), "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errno, addr, ok := classifyBindError(c.err)
			if ok != c.wantConflict {
				t.Fatalf("classifyBindError(%v) conflict = %v, want %v", c.err, ok, c.wantConflict)
			}
			if errno != c.wantErrno {
				t.Errorf("classifyBindError(%v) errno = %d, want %d", c.err, errno, c.wantErrno)
			}
			if addr != c.wantAddr {
				t.Errorf("classifyBindError(%v) addr = %q, want %q", c.err, addr, c.wantAddr)
			}
		})
	}
}
