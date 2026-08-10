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

// Registered once for the whole binary through the real production entry point,
// so the flag-to-live-controller path main() runs is covered rather than
// re-implemented here. At this point flag defaults are assigned, so this
// registers keepAliveDialerController({15,15,3}) -- exactly testParams().
//
// Once per binary is required: internet.RegisterDialerController appends to a
// process-global slice with no removal, so registering inside a test would leak
// into every later test and would double under -count=2.
func TestMain(m *testing.M) {
	common.Must(registerTCPKeepAlive())
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

// Pins the two vendored behaviours the README's "TCP keepalive" section
// describes: a registered controller reaching the fd, and SocketConfig's fields
// suppressing Go's post-connect defaults. A subrepo bump breaking either must
// fail here.
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

// registerTCPKeepAlive's client-mode body -- validate, build, register -- is
// what main() runs at startup. TestMain covers that it runs at all; this pins
// that the controller it installs actually reaches a dial.
//
// It swaps in a scratch system dialer so the registration is isolated, then
// rebuilds the binary-wide state TestMain established. internet exposes no
// getter for the effective dialer, so restoring means reconstructing it: a
// fresh DefaultSystemDialer plus the same registerTCPKeepAlive call.
func TestRegisterTCPKeepAliveInstallsController(t *testing.T) {
	t.Cleanup(func() {
		internet.UseAlternativeSystemDialer(nil)
		common.Must(registerTCPKeepAlive())
	})

	internet.UseAlternativeSystemDialer(nil)
	if err := registerTCPKeepAlive(); err != nil {
		t.Fatalf("registerTCPKeepAlive: %v", err)
	}

	want := testParams()
	conn := dialSystem(t, nil, &internet.SocketConfig{
		TcpKeepAliveIdle:     want.IdleSeconds,
		TcpKeepAliveInterval: want.IntervalSeconds,
	})

	got, enabled := readParams(t, conn)
	if !enabled {
		t.Error("SO_KEEPALIVE is off; registerTCPKeepAlive did not install a working controller")
	}
	if got.Probes != want.Probes {
		t.Errorf("probe count = %d, want %d; the probe count is the one value only the registered controller can set", got.Probes, want.Probes)
	}
}
