package main

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/v2fly/v2ray-core/v5/common"
	v2net "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

// Registered once for the whole binary: internet.RegisterDialerController
// appends to a process-global slice with no removal, so registering inside a
// test would leak into every later test and would double under -count=2.
// Verified safe: no other test in this package dials and then asserts on socket
// options.
func TestMain(m *testing.M) {
	common.Must(internet.RegisterDialerController(keepAliveDialerController(testParams())))
	os.Exit(m.Run())
}

// dialSystem dials loopback with the given SocketConfig, returning the client
// side. A nil dialer uses the process-global one (with TestMain's registered
// controller); pass a fresh &internet.DefaultSystemDialer{} to model a run
// where registerTCPKeepAlive installed no controller.
func dialSystem(t *testing.T, dialer *internet.DefaultSystemDialer, sockopt *internet.SocketConfig) *net.TCPConn {
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

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("ParseUint(%q): %v", portStr, err)
	}
	dest := v2net.TCPDestination(v2net.ParseAddress(host), v2net.Port(port))

	var conn net.Conn
	if dialer == nil {
		conn, err = internet.DialSystem(context.Background(), dest, sockopt)
	} else {
		conn, err = dialer.Dial(context.Background(), nil, dest, sockopt)
	}
	if err != nil {
		t.Fatalf("DialSystem: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	server, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = server.Close() })

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("DialSystem returned %T, want *net.TCPConn", conn)
	}
	return tcpConn
}

// A dial through v2ray-core's own DialSystem must come out with every keepalive
// option applied. This pins the two vendored behaviours the design leans on: a
// registered controller still reaching the fd, and SocketConfig's keepalive
// fields still producing net.Dialer.KeepAlive = -1 so Go's stdlib does not
// overwrite them after connect. A subrepo bump breaking either must fail here
// rather than silently restore the ~150s bound.
//
// Probes is the load-bearing value: on linux and darwin the vendored
// applyOutboundSocketOptions sets idle and interval from the SocketConfig
// fields, so the count is the only one that can only have come from the
// controller.
func TestDialSystemAppliesKeepAlive(t *testing.T) {
	want := testParams()
	conn := dialSystem(t, nil, &internet.SocketConfig{
		TcpKeepAliveIdle:     want.IdleSeconds,
		TcpKeepAliveInterval: want.IntervalSeconds,
	})

	got, enabled := readParams(t, conn)
	if !enabled {
		t.Error("SO_KEEPALIVE is off after DialSystem")
	}
	if got != want {
		t.Errorf("keepalive params after DialSystem = %+v, want %+v; either the controller no longer reaches the fd or Go's stdlib is overwriting it", got, want)
	}
}

// The tcp-keepalive=0 opt-out has to hold on the wire, not just in the config
// struct: the negative sentinel is what stops Go's stdlib from applying its own
// 15s/15s/9 defaults after connect. Asserting only on SocketConfig would stay
// green if that suppression ever stopped working.
//
// This dials through a fresh DefaultSystemDialer rather than the process-global
// one, because that is what production looks like at tcp-keepalive=0:
// registerTCPKeepAlive installs no controller, so nothing sets SO_KEEPALIVE and
// the sentinel is the only thing acting. TestMain's controller is registered on
// the global dialer and would otherwise re-enable keepalive here.
func TestDialSystemDisabledKeepAlive(t *testing.T) {
	conn := dialSystem(t, &internet.DefaultSystemDialer{}, &internet.SocketConfig{TcpKeepAliveIdle: -1})

	_, enabled := readParams(t, conn)
	if enabled {
		t.Error("SO_KEEPALIVE is on after a dial with the disable sentinel; tcp-keepalive=0 must leave keepalive fully off, including Go's default")
	}
}
