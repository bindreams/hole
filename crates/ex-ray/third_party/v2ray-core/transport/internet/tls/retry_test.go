//go:build go1.24
// +build go1.24

package tls_test

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"github.com/v2fly/v2ray-core/v5/common"
	commonnet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet/security"
	. "github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

const extensionEncryptedClientHello uint16 = 0xfe0d

// marshalECHConfig builds a single ECHConfig (RFC 9180/ECH draft framing) the Go
// stdlib server and client both parse; mirrors crypto/tls's own test helper.
func marshalECHConfig(id uint8, pubKey []byte, publicName string, maxNameLen uint8) []byte {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16(extensionEncryptedClientHello)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddUint8(id)
		builder.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes(pubKey)
		})
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddUint16(0x0001) // HKDF-SHA256
			builder.AddUint16(0x0001) // AES-128-GCM
		})
		builder.AddUint8(maxNameLen)
		builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes([]byte(publicName))
		})
		builder.AddUint16(0) // extensions
	})
	return builder.BytesOrPanic()
}

func marshalECHConfigList(t *testing.T, configs ...[]byte) []byte {
	t.Helper()
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		for _, cfg := range configs {
			builder.AddBytes(cfg)
		}
	})
	out, err := builder.Bytes()
	common.Must(err)
	return out
}

// echTestServer is a real Go crypto/tls server that holds an ECH key with
// SendAsRetry: a client offering a non-matching ECH config gets rejected with the
// server's real config-list in retry_configs (RFC 9849), and the client's
// subsequent handshake (carrying the real config) is accepted.
type echTestServer struct {
	serverConfig  *gotls.Config
	caPEMs        [][]byte // CA certs the client trusts (AUTHORITY_VERIFY)
	echConfigList []byte   // the server's real config-list (what it sends as retry)
	publicName    string
	secretName    string
}

func newECHTestServer(t *testing.T) *echTestServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	common.Must(err)

	const publicName = "public.example"
	const secretName = "secret.example"

	mkCert := func(dnsName string) (der []byte, pemBytes []byte) {
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: dnsName},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			DNSNames:              []string{dnsName},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		common.Must(err)
		pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		return der, pemBytes
	}

	publicDER, publicPEM := mkCert(publicName)
	secretDER, secretPEM := mkCert(secretName)

	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	common.Must(err)
	echConfig := marshalECHConfig(123, echKey.PublicKey().Bytes(), publicName, 32)
	echConfigList := marshalECHConfigList(t, echConfig)

	serverConfig := &gotls.Config{
		MinVersion: gotls.VersionTLS13,
		Certificates: []gotls.Certificate{
			{Certificate: [][]byte{publicDER}, PrivateKey: key},
			{Certificate: [][]byte{secretDER}, PrivateKey: key},
		},
		EncryptedClientHelloKeys: []gotls.EncryptedClientHelloKey{
			{Config: echConfig, PrivateKey: echKey.Bytes(), SendAsRetry: true},
		},
	}

	return &echTestServer{
		serverConfig:  serverConfig,
		caPEMs:        [][]byte{publicPEM, secretPEM},
		echConfigList: echConfigList,
		publicName:    publicName,
		secretName:    secretName,
	}
}

// listenAndServe starts a real loopback TLS listener (net.Pipe deadlocks on the
// synchronous handshake) accepting each conn the dial closure dials. It returns a
// dial closure producing a fresh raw client conn per call and a func reporting
// how many handshakes the server observed. t.Cleanup stops the accept loop.
func (s *echTestServer) listenAndServe(t *testing.T) (dial func() (net.Conn, error), handshakes func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	t.Cleanup(func() { ln.Close() })

	var mu sync.Mutex
	count := 0
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			count++
			mu.Unlock()
			go func(raw net.Conn) {
				tlsServer := gotls.Server(raw, s.serverConfig)
				if err := tlsServer.Handshake(); err != nil {
					raw.Close()
					return
				}
				io.Copy(io.Discard, tlsServer)
				raw.Close()
			}(raw)
		}
	}()

	addr := ln.Addr().String()
	dial = func() (net.Conn, error) { return net.Dial("tcp", addr) }
	handshakes = func() int {
		mu.Lock()
		defer mu.Unlock()
		return count
	}
	return dial, handshakes
}

// engineConfig builds a v2ray tls.Config whose client handshake offers echList
// (a static EchConfig) and trusts the server's self-signed CAs as roots. A WRONG
// list triggers the server's ECH rejection + retry_configs; real verification
// runs (no AllowInsecure) so the ECH retry path is exercised end-to-end.
func (s *echTestServer) engineConfig(echList []byte) *Config {
	certs := make([]*Certificate, 0, len(s.caPEMs))
	for _, p := range s.caPEMs {
		certs = append(certs, &Certificate{Certificate: p, Usage: Certificate_AUTHORITY_VERIFY})
	}
	return &Config{
		ServerName:        s.secretName,
		DisableSystemRoot: true,
		Certificate:       certs,
		EchConfig:         echList,
	}
}

// The mandatory behavioral test: the stdlib engine path retries ONCE on an ECH
// rejection using the server's retry_configs and succeeds. A non-ECH handshake
// error is terminal (no retry).
func TestDialClientWithECHRetryRejectThenAccept(t *testing.T) {
	srv := newECHTestServer(t)
	// The rejection triggers a best-effort RefreshECHCache write keyed on the
	// ServerName; drop it so it does not leak into sibling tests.
	t.Cleanup(func() { DeleteECHCacheEntryForTest(srv.secretName) })

	// The client initially offers a config-list whose key the server does NOT
	// hold (a fresh, unrelated ECH config) → server rejects with retry_configs.
	wrongKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	common.Must(err)
	wrongConfig := marshalECHConfig(99, wrongKey.PublicKey().Bytes(), srv.publicName, 32)
	wrongList := marshalECHConfigList(t, wrongConfig)

	c := srv.engineConfig(wrongList)
	engine, err := NewTLSSecurityEngineFromConfig(c)
	common.Must(err)

	dial, handshakes := srv.listenAndServe(t)
	conn, err := DialClientWithECHRetry(engine, c, dial,
		security.OptionWithDestination{Dest: commonnet.TCPDestination(commonnet.DomainAddress(srv.secretName), 443)})
	if err != nil {
		t.Fatalf("reject-then-accept must succeed after one retry: %v", err)
	}
	if conn == nil {
		t.Fatal("retry must return a handshaked connection")
	}
	conn.Close()
	if n := handshakes(); n != 2 {
		t.Fatalf("server must observe exactly 2 handshakes (reject + retry), got %d", n)
	}
}

// A non-ECH handshake error is terminal: the helper must NOT retry. The dial
// closure returns a conn whose server side never speaks TLS, so the handshake
// fails with a non-ECH error.
func TestDialClientWithECHRetryNonECHErrorIsTerminal(t *testing.T) {
	c := &Config{ServerName: "example.com", AllowInsecure: true}
	engine, err := NewTLSSecurityEngineFromConfig(c)
	common.Must(err)

	var mu sync.Mutex
	dials := 0
	dial := func() (net.Conn, error) {
		mu.Lock()
		dials++
		mu.Unlock()
		client, server := net.Pipe()
		// Server side closes immediately → client handshake fails (non-ECH).
		go func() { server.Close() }()
		return client, nil
	}

	conn, err := DialClientWithECHRetry(engine, c, dial,
		security.OptionWithDestination{Dest: commonnet.TCPDestination(commonnet.DomainAddress("example.com"), 443)})
	if err == nil {
		conn.Close()
		t.Fatal("a non-ECH handshake error must be terminal")
	}
	var echRej *gotls.ECHRejectionError
	if errors.As(err, &echRej) {
		t.Fatalf("error must not be an ECH rejection: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if dials != 1 {
		t.Fatalf("non-ECH error must not trigger a retry dial, got %d dials", dials)
	}
}
