//go:build go1.24
// +build go1.24

package transportcommon_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	gonet "net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/environment"
	"github.com/v2fly/v2ray-core/v5/common/environment/deferredpersistentstorage"
	"github.com/v2fly/v2ray-core/v5/common/environment/envctx"
	"github.com/v2fly/v2ray-core/v5/common/environment/filesystemimpl"
	"github.com/v2fly/v2ray-core/v5/common/environment/systemnetworkimpl"
	"github.com/v2fly/v2ray-core/v5/common/environment/transientstorageimpl"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/serial"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
	"github.com/v2fly/v2ray-core/v5/transport/internet/transportcommon"
)

const extensionEncryptedClientHello uint16 = 0xfe0d

// marshalECHConfig builds a single ECHConfig the Go stdlib server and client both
// parse; mirrors crypto/tls's own test helper.
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

// echTestServer is a real Go crypto/tls server holding an ECH key with SendAsRetry:
// a client offering a non-matching ECH config is rejected with the server's real
// config-list in retry_configs (RFC 9849); the retry (carrying it) is accepted.
type echTestServer struct {
	serverConfig *gotls.Config
	caPEMs       [][]byte
	publicName   string
	secretName   string
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
		serverConfig: serverConfig,
		caPEMs:       [][]byte{publicPEM, secretPEM},
		publicName:   publicName,
		secretName:   secretName,
	}
}

// listenAndServe starts a real loopback TLS listener and returns its address plus a
// func reporting how many handshakes the server observed.
func (s *echTestServer) listenAndServe(t *testing.T) (addr string, handshakes func() int) {
	t.Helper()
	ln, err := gonet.Listen("tcp", "127.0.0.1:0")
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
			go func(raw gonet.Conn) {
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

	handshakes = func() int {
		mu.Lock()
		defer mu.Unlock()
		return count
	}
	return ln.Addr().String(), handshakes
}

// tlsProtoConfig builds a v2ray tls.Config whose client handshake offers echList
// and trusts the server's self-signed CAs as roots. A WRONG list triggers the
// server's ECH rejection + retry_configs; real verification runs (no AllowInsecure).
func (s *echTestServer) tlsProtoConfig(echList []byte) *tls.Config {
	certs := make([]*tls.Certificate, 0, len(s.caPEMs))
	for _, p := range s.caPEMs {
		certs = append(certs, &tls.Certificate{Certificate: p, Usage: tls.Certificate_AUTHORITY_VERIFY})
	}
	return &tls.Config{
		ServerName:        s.secretName,
		DisableSystemRoot: true,
		Certificate:       certs,
		EchConfig:         echList,
	}
}

// countingDialer is the SystemDialer the transport environment hands the
// transportcommon dialer: it dials the loopback TLS listener and counts each dial,
// so a retry is observable as a second dial driven through the real seam.
type countingDialer struct {
	addr  string
	mu    sync.Mutex
	dials int
}

func (d *countingDialer) Dial(_ context.Context, _ net.Address, _ net.Destination, _ *internet.SocketConfig) (net.Conn, error) {
	d.mu.Lock()
	d.dials++
	d.mu.Unlock()
	return gonet.Dial("tcp", d.addr)
}

func (d *countingDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

// transportEnvWithDialer assembles a real TransportEnvironment whose Dialer() is the
// supplied SystemDialer, so DialWithSecuritySettings drives the production seam.
func transportEnvWithDialer(t *testing.T, dialer internet.SystemDialer) context.Context {
	t.Helper()
	ctx := context.Background()
	netImpl := systemnetworkimpl.NewSystemNetworkImpl(nil, dialer)
	rootEnv := environment.NewRootEnvImpl(ctx,
		transientstorageimpl.NewScopedTransientStorageImpl(), netImpl.Dialer(), netImpl.Listener(),
		filesystemimpl.NewDefaultFileSystemDefaultImpl(), deferredpersistentstorage.NewDeferredPersistentStorage(ctx))
	transportEnv, err := rootEnv.ProxyEnvironment("o").NarrowScopeToTransport("transportcommon")
	common.Must(err)
	return envctx.ContextWithEnvironment(ctx, transportEnv)
}

func streamSettingsWithTLS(t *testing.T, proto *tls.Config) *internet.MemoryStreamConfig {
	t.Helper()
	return &internet.MemoryStreamConfig{
		SecurityType:     serial.GetMessageType(proto),
		SecuritySettings: proto,
	}
}

// The transportcommon seam (httpupgrade / request transports) must route through the
// ECH-retry helper: an ECH rejection retries ONCE on a fresh dial and succeeds.
func TestDialWithSecuritySettingsRetriesOnECHRejection(t *testing.T) {
	srv := newECHTestServer(t)
	// The rejection triggers a best-effort RefreshECHCache write into the
	// process-global ECH cache, keyed on secret.example. tls.DeleteECHCacheEntryForTest
	// is in package tls's test binary, unreachable from here; the write is confined
	// to this package's test process, so it cannot leak across binaries.

	wrongKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	common.Must(err)
	wrongConfig := marshalECHConfig(99, wrongKey.PublicKey().Bytes(), srv.publicName, 32)
	wrongList := marshalECHConfigList(t, wrongConfig)

	addr, handshakes := srv.listenAndServe(t)
	dialer := &countingDialer{addr: addr}
	ctx := transportEnvWithDialer(t, dialer)

	proto := srv.tlsProtoConfig(wrongList)
	dest := net.TCPDestination(net.DomainAddress(srv.secretName), 443)
	conn, err := transportcommon.DialWithSecuritySettings(ctx, dest, streamSettingsWithTLS(t, proto))
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
	if n := dialer.dialCount(); n != 2 {
		t.Fatalf("the ECH retry must re-dial through the transportcommon seam exactly once (2 dials), got %d", n)
	}
}
