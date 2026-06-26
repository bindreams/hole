//go:build go1.24
// +build go1.24

package quic_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"golang.org/x/crypto/cryptobyte"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/testing/servers/udp"
)

const extensionEncryptedClientHello uint16 = 0xfe0d

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

func marshalECHConfigList(configs ...[]byte) []byte {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		for _, cfg := range configs {
			builder.AddBytes(cfg)
		}
	})
	return builder.BytesOrPanic()
}

// Pins the unwrap-chain assumption dialQUICWithECHRetry depends on: quic-go
// v0.59.1 surfaces an ECH rejection such that errors.As resolves the
// *tls.ECHRejectionError and its RetryConfigList is non-empty. Driven against a
// REAL quic-go handshake (a server holding an ECH key with SendAsRetry whose
// config the client did not use) — not a hand-built error. If a future quic-go
// changes the chain, this fails here instead of silently disabling QUIC retry.
func TestQuicGoECHRejectionUnwrapsToECHRejectionError(t *testing.T) {
	port := udp.PickPort()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	common.Must(err)
	const publicName = "public.example"
	const secretName = "secret.example"
	tmpl := func(dnsName string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: dnsName},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			DNSNames:              []string{dnsName},
			BasicConstraintsValid: true,
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}
	}
	publicDER, err := x509.CreateCertificate(rand.Reader, tmpl(publicName), tmpl(publicName), key.Public(), key)
	common.Must(err)
	publicCert, err := x509.ParseCertificate(publicDER)
	common.Must(err)
	secretDER, err := x509.CreateCertificate(rand.Reader, tmpl(secretName), tmpl(secretName), key.Public(), key)
	common.Must(err)
	secretCert, err := x509.ParseCertificate(secretDER)
	common.Must(err)

	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	common.Must(err)
	echConfig := marshalECHConfig(123, echKey.PublicKey().Bytes(), publicName, 32)
	serverConfigList := marshalECHConfigList(echConfig)

	serverTLS := &gotls.Config{
		MinVersion: gotls.VersionTLS13,
		NextProtos: []string{"h2"},
		Certificates: []gotls.Certificate{
			{Certificate: [][]byte{publicDER}, PrivateKey: key},
			{Certificate: [][]byte{secretDER}, PrivateKey: key},
		},
		EncryptedClientHelloKeys: []gotls.EncryptedClientHelloKey{
			{Config: echConfig, PrivateKey: echKey.Bytes(), SendAsRetry: true},
		},
	}
	sConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.LocalHostIP.IP(), Port: int(port)})
	common.Must(err)
	defer sConn.Close()
	str := &quicgo.Transport{Conn: sConn}
	ln, err := str.Listen(serverTLS, &quicgo.Config{HandshakeIdleTimeout: 8 * time.Second, MaxIdleTimeout: 30 * time.Second})
	common.Must(err)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func(conn *quicgo.Conn) { _, _ = conn.AcceptStream(context.Background()) }(conn)
		}
	}()

	// The client offers a config-list whose key the server does NOT hold →
	// server rejects ECH and returns serverConfigList as retry_configs.
	wrongKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	common.Must(err)
	wrongList := marshalECHConfigList(marshalECHConfig(99, wrongKey.PublicKey().Bytes(), publicName, 32))

	roots := x509.NewCertPool()
	roots.AddCert(publicCert)
	roots.AddCert(secretCert)
	cConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.LocalHostIP.IP(), Port: 0})
	common.Must(err)
	defer cConn.Close()
	ctr := &quicgo.Transport{Conn: cConn}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = ctr.Dial(ctx, &net.UDPAddr{IP: net.LocalHostIP.IP(), Port: int(port)}, &gotls.Config{
		ServerName:                     secretName,
		RootCAs:                        roots,
		NextProtos:                     []string{"h2"},
		EncryptedClientHelloConfigList: wrongList,
	}, &quicgo.Config{HandshakeIdleTimeout: 8 * time.Second, MaxIdleTimeout: 30 * time.Second})

	if err == nil {
		t.Fatal("dial with a non-matching ECH config must be rejected")
	}
	var echRej *gotls.ECHRejectionError
	if !errors.As(err, &echRej) {
		t.Fatalf("quic-go ECH rejection must unwrap to *tls.ECHRejectionError, got: %v", err)
	}
	if len(echRej.RetryConfigList) == 0 {
		t.Fatal("the rejection must carry the server's retry_configs")
	}
	if string(echRej.RetryConfigList) != string(serverConfigList) {
		t.Fatalf("retry_configs = %x, want server config-list %x", echRej.RetryConfigList, serverConfigList)
	}
}
