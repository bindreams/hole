//go:build go1.24
// +build go1.24

package tls_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"sync"
	"testing"

	"github.com/v2fly/v2ray-core/v5/common"
	commonnet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet/security"
	. "github.com/v2fly/v2ray-core/v5/transport/internet/tls"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls/utls"
)

// recordingConn tees everything the client writes so the test can assert the
// real (inner) SNI never appears in cleartext on the wire.
type recordingConn struct {
	net.Conn
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (r recordingConn) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.buf.Write(b)
	r.mu.Unlock()
	return r.Conn.Write(b)
}

func newUTLSEngine(t *testing.T, c *Config) security.Engine {
	t.Helper()
	engine, err := utls.NewUTLSSecurityEngineFromConfig(&utls.Config{
		TlsConfig: c,
		Imitate:   "chrome_auto",
		ForceAlpn: utls.ForcedALPN_TRANSPORT_PREFERENCE_TAKE_PRIORITY,
	})
	common.Must(err)
	return engine
}

// A uTLS (Chrome-mimic) dial carrying the server's real ECH config completes the
// handshake AND never puts the real SNI (the inner name) in cleartext — the
// outer SNI is the ECH public_name.
func TestUTLSComposesECHConcealsSNI(t *testing.T) {
	srv := newECHTestServer(t)
	c := srv.engineConfig(srv.echConfigList)
	engine := newUTLSEngine(t, c)

	rawDial, _ := srv.listenAndServe(t)
	var mu sync.Mutex
	buf := &bytes.Buffer{}
	dial := func() (net.Conn, error) {
		raw, err := rawDial()
		if err != nil {
			return nil, err
		}
		return recordingConn{Conn: raw, mu: &mu, buf: buf}, nil
	}

	conn, err := DialClientWithECHRetry(engine, c, dial,
		security.OptionWithDestination{Dest: commonnet.TCPDestination(commonnet.DomainAddress(srv.secretName), 443)})
	if err != nil {
		t.Fatalf("uTLS+ECH handshake must succeed: %v", err)
	}
	conn.Close()

	mu.Lock()
	wire := buf.Bytes()
	mu.Unlock()
	if bytes.Contains(wire, []byte(srv.secretName)) {
		t.Fatalf("real SNI %q must never appear in cleartext on the wire", srv.secretName)
	}
	if !bytes.Contains(wire, []byte(srv.publicName)) {
		t.Fatalf("outer SNI must be the ECH public_name %q", srv.publicName)
	}
}

// ECH rejection on a uTLS dial recovers via retry_configs: the uTLS engine's
// *utls.ECHRejectionError is normalized to *crypto/tls.ECHRejectionError so the
// shared retry helper recognizes it and retries once with the server's configs.
func TestUTLSECHRetryRejectThenAccept(t *testing.T) {
	srv := newECHTestServer(t)
	t.Cleanup(func() { DeleteECHCacheEntryForTest(srv.secretName) })

	wrongKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	common.Must(err)
	wrongList := marshalECHConfigList(t, marshalECHConfig(99, wrongKey.PublicKey().Bytes(), srv.publicName, 32))

	c := srv.engineConfig(wrongList)
	engine := newUTLSEngine(t, c)

	dial, handshakes := srv.listenAndServe(t)
	conn, err := DialClientWithECHRetry(engine, c, dial,
		security.OptionWithDestination{Dest: commonnet.TCPDestination(commonnet.DomainAddress(srv.secretName), 443)})
	if err != nil {
		t.Fatalf("uTLS reject-then-accept must succeed after one retry: %v", err)
	}
	conn.Close()
	if n := handshakes(); n != 2 {
		t.Fatalf("server must observe exactly 2 handshakes (reject + retry), got %d", n)
	}
}
