package main

import (
	"net"
	"testing"
)

// TestListenerNetwork verifies the inbound-transport decision that drives the
// sitrep `transports` value (and mirrors the transport v2ray-core binds). Only
// server+quic binds a UDP listener (the quic inbound faces the remote client);
// every other combination — client mode (plain TCP dokodemo inbound) and
// server+websocket — is TCP. An unknown mode resolves to "tcp" here and is
// rejected later by generateConfig's switch default, before emitReady. See
// bindreams/hole#421.
func TestListenerNetwork(t *testing.T) {
	// Do NOT t.Parallel() this (or its subtests): it mutates the package-global
	// *server/*mode flag pointers, which are shared across the whole test binary.
	origServer, origMode := *server, *mode
	t.Cleanup(func() { *server, *mode = origServer, origMode })

	cases := []struct {
		name   string
		server bool
		mode   string
		want   string
	}{
		{"client_websocket", false, "websocket", "tcp"},
		{"client_quic", false, "quic", "tcp"},
		{"server_websocket", true, "websocket", "tcp"},
		{"server_quic", true, "quic", "udp"},
		{"server_unknown_mode", true, "grpc", "tcp"},
		{"client_unknown_mode", false, "grpc", "tcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			*server, *mode = tc.server, tc.mode
			if got := listenerNetwork(); got != tc.want {
				t.Errorf("listenerNetwork() with server=%v mode=%q = %q, want %q", tc.server, tc.mode, got, tc.want)
			}
		})
	}
}

// reserveTCPPortWithFreeUDP returns a held TCP listener whose port is also
// confirmed bindable for UDP, so the TCP bind-conflict pin test cannot flake
// on a Windows independent-excluded-port-range mismatch
// (TCP and UDP maintain separate Hyper-V/WSL/Docker reservation tables — the
// exact race hole_common::port_alloc::bind_ephemeral exists to absorb on the
// Rust side). It binds TCP on an OS-assigned port, verifies the same port binds
// for UDP, then releases only the UDP socket — leaving TCP held and the UDP
// space proven free. Unbounded retry on a per-port TCP/UDP mismatch (no
// arbitrary cap; the OS ephemeral allocator is the natural termination, same as
// port_alloc).
func reserveTCPPortWithFreeUDP(t *testing.T) (net.Listener, string) {
	t.Helper()
	for {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to bind sentinel TCP listener: %v", err)
		}
		addr := ln.Addr().String()
		pc, udpErr := net.ListenPacket("udp", addr)
		if udpErr != nil {
			// This port is reserved for UDP (excluded-range mismatch); the TCP
			// bind happened to win it anyway. Release and pick another.
			_ = ln.Close()
			continue
		}
		_ = pc.Close()
		return ln, addr
	}
}
