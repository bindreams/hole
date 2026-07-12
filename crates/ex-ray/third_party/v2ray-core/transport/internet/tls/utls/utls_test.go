package utls_test

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls/utls"
)

// A preset whose ClientHello carries no ECH extension (edge_auto) cannot compose
// ECH, so the engine keeps the unsupported-engine path: it refuses ech=always
// before any handshake rather than hand uTLS a cleartext-SNI hello.
func TestUTLSNonECHPresetRefusesRequireEch(t *testing.T) {
	engine, err := utls.NewUTLSSecurityEngineFromConfig(&utls.Config{
		Imitate:   "edge_auto",
		TlsConfig: &tls.Config{ServerName: "example.com", RequireEch: true},
	})
	common.Must(err)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn, err := engine.Client(client)
	if conn != nil {
		conn.Close()
		t.Fatal("a refused uTLS Client must not return a connection")
	}
	if err == nil || !strings.Contains(err.Error(), "ech=always") {
		t.Fatalf("non-ECH preset must refuse ech=always, got: %v", err)
	}
}

// An ECH-capable preset (chrome_auto) routes through the fail-closed gate: with
// RequireEch set but no obtainable config, the gate refuses before any handshake.
func TestUTLSECHCapablePresetRefusesRequireEchWithoutConfig(t *testing.T) {
	engine, err := utls.NewUTLSSecurityEngineFromConfig(&utls.Config{
		Imitate:   "chrome_auto",
		TlsConfig: &tls.Config{ServerName: "example.com", RequireEch: true},
	})
	common.Must(err)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn, err := engine.Client(client)
	if conn != nil {
		conn.Close()
		t.Fatal("the gate must refuse before returning a connection")
	}
	if err == nil || !strings.Contains(err.Error(), "ECH required") {
		t.Fatalf("RequireEch without a config must refuse at the gate, got: %v", err)
	}
}

// countingConn counts bytes written so a test can assert Client() wrote none
// (deferred handshake) without a live peer.
type countingConn struct {
	mu sync.Mutex
	n  int
}

func (c *countingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.n += len(b)
	c.mu.Unlock()
	return len(b), nil
}
func (c *countingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *countingConn) written() int                     { c.mu.Lock(); defer c.mu.Unlock(); return c.n }
func (c *countingConn) Close() error                     { return nil }
func (c *countingConn) LocalAddr() net.Addr              { return nil }
func (c *countingConn) RemoteAddr() net.Addr             { return nil }
func (c *countingConn) SetDeadline(time.Time) error      { return nil }
func (c *countingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *countingConn) SetWriteDeadline(time.Time) error { return nil }

// ech=auto + no config: the gate allows it (best-effort), and Client() must not
// eagerly handshake — it writes nothing. This pins only the no-eager-write
// property; deferral-through-retry is covered e2e by TestUTLSECHRetryRejectThenAccept.
func TestUTLSClientDefersHandshake(t *testing.T) {
	engine, err := utls.NewUTLSSecurityEngineFromConfig(&utls.Config{
		Imitate:   "chrome_auto",
		TlsConfig: &tls.Config{ServerName: "example.com"},
	})
	common.Must(err)
	cc := &countingConn{}
	conn, err := engine.Client(cc)
	if err != nil {
		t.Fatalf("chrome_auto without ECH must build a connection, got: %v", err)
	}
	if conn == nil {
		t.Fatal("expected a connection")
	}
	if n := cc.written(); n != 0 {
		t.Fatalf("Client() must defer the handshake (0 bytes written), wrote %d", n)
	}
}
