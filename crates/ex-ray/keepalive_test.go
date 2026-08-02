package main

import (
	"math"
	"net"
	"syscall"
	"testing"
)

// sockoptInt32 narrows a getsockopt result to the int32 keepAliveParams carries.
// The bound guard wrapping the conversion is gosec G115's recognized
// mitigation, matching uint32Opt in config.go.
func sockoptInt32(name string, v int) (int32, error) {
	if v >= 0 && v <= math.MaxInt32 {
		return int32(v), nil
	}
	return 0, newError("out-of-range ", name, " read back from the socket: ", v)
}

func testParams() keepAliveParams {
	return keepAliveParams{IdleSeconds: 15, IntervalSeconds: 15, Probes: 3}
}

// dialWithControl dials loopback with ctl on the raw fd and KeepAlive: -1 — the
// same shape DefaultSystemDialer produces once the SocketConfig keepalive
// fields are set.
func dialWithControl(t *testing.T, ctl func(network, address string, fd uintptr) error) *net.TCPConn {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	dialer := &net.Dialer{
		KeepAlive: -1,
		Control: func(network, address string, c syscall.RawConn) error {
			var ctlErr error
			if err := c.Control(func(fd uintptr) { ctlErr = ctl(network, address, fd) }); err != nil {
				return err
			}
			return ctlErr
		},
	}
	conn, err := dialer.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Rendezvous on the accept so the peer socket outlives the assertions.
	server, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = server.Close() })

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("dial returned %T, want *net.TCPConn", conn)
	}
	return tcpConn
}

func readParams(t *testing.T, conn *net.TCPConn) (keepAliveParams, bool) {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var (
		got     keepAliveParams
		enabled bool
		readErr error
	)
	if err := raw.Control(func(fd uintptr) { got, enabled, readErr = readTCPKeepAlive(fd) }); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if readErr != nil {
		t.Fatalf("readTCPKeepAlive: %v", readErr)
	}
	return got, enabled
}

// The controller is the only thing setting options here — this dials a bare
// net.Dialer, not internet.DialSystem, so nothing else can be supplying them.
// It is also the only coverage of the pre-connect setsockopt path on Windows,
// where all three timings are the controller's exclusive work.
func TestKeepAliveControllerSetsAllOptions(t *testing.T) {
	want := testParams()
	got, enabled := readParams(t, dialWithControl(t, keepAliveDialerController(want)))

	if !enabled {
		t.Error("SO_KEEPALIVE is off; the controller must enable it")
	}
	if got != want {
		t.Errorf("keepalive params = %+v, want %+v; the OS probe-count default of 9 is the ~150s bound this exists to shorten", got, want)
	}
}

func TestKeepAliveControllerIgnoresNonTCP(t *testing.T) {
	if err := keepAliveDialerController(testParams())("udp", "127.0.0.1:9", 0); err != nil {
		t.Errorf("controller on udp returned %v, want nil (fd 0 must never be touched)", err)
	}
}

func TestKeepAliveControllerNilWhenDisabled(t *testing.T) {
	if ctl := keepAliveDialerController(keepAliveParams{}); ctl != nil {
		t.Error("keepAliveDialerController with zero params returned a controller, want nil")
	}
}
