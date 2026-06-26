package tls_test

import (
	"net"
	"testing"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/transport/internet/security"
	. "github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

// OptionWithECHConfigOverride is the race-free retry seam: the stdlib engine
// builds via the plain (ungated) factory and forces the server's retry_configs
// onto the config. With RequireEch + unobtainable DoH the gated path would fail
// closed, but the override is provably non-empty, so Client must return a conn
// (the gate is skipped). net.Pipe never reads, so no handshake runs here.
func TestEngineClientECHOverrideSkipsGate(t *testing.T) {
	c := &Config{ServerName: "example.com", Ech_DOHserver: "https://127.0.0.1:1/dns-query", RequireEch: true}
	engine, err := NewTLSSecurityEngineFromConfig(c)
	common.Must(err)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn, err := engine.Client(client, security.OptionWithECHConfigOverride{Configs: []byte{0x01, 0x02}})
	if err != nil {
		t.Fatalf("override must bypass the require-ech gate: %v", err)
	}
	if conn == nil {
		t.Fatal("override path must return a connection")
	}
}

// An empty override is not a valid retry config; the option must not be a route
// around the gate. RequireEch + unobtainable DoH + empty override must still fail
// closed (no conn).
func TestEngineClientECHOverrideEmptyStillGates(t *testing.T) {
	c := &Config{ServerName: "example.com", Ech_DOHserver: "https://127.0.0.1:1/dns-query", RequireEch: true}
	engine, err := NewTLSSecurityEngineFromConfig(c)
	common.Must(err)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn, err := engine.Client(client, security.OptionWithECHConfigOverride{Configs: nil})
	if err == nil {
		t.Fatal("empty override must not bypass the require-ech gate")
	}
	if conn != nil {
		t.Fatal("gated Client must not return a connection")
	}
}
