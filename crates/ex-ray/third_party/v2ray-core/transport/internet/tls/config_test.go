package tls_test

import (
	gotls "crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/log"
	"github.com/v2fly/v2ray-core/v5/common/protocol/tls/cert"
	"github.com/v2fly/v2ray-core/v5/common/serial"
	. "github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

// captureLog records the last v2ray-core log message so a test can assert a
// WriteToLog warning fired. discardLog restores a no-op handler afterward
// (RegisterHandler panics on nil, so cleanup cannot clear it).
type captureLog struct{ msg string }

func (c *captureLog) Handle(m log.Message) { c.msg = m.String() }
func (c *captureLog) last() string         { return c.msg }

type discardLog struct{}

func (discardLog) Handle(log.Message) {}

func TestCertificateIssuing(t *testing.T) {
	certificate := ParseCertificate(cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign)))
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	c := &Config{
		Certificate: []*Certificate{
			certificate,
		},
	}

	tlsConfig := c.GetTLSConfig()
	v2rayCert, err := tlsConfig.GetCertificate(&gotls.ClientHelloInfo{
		ServerName: "www.v2fly.org",
	})
	common.Must(err)

	x509Cert, err := x509.ParseCertificate(v2rayCert.Certificate[0])
	common.Must(err)
	if !x509Cert.NotAfter.After(time.Now()) {
		t.Error("NotAfter: ", x509Cert.NotAfter)
	}
}

func TestExpiredCertificate(t *testing.T) {
	caCert := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	expiredCert := cert.MustGenerate(caCert, cert.NotAfter(time.Now().Add(time.Minute*-2)), cert.CommonName("www.v2fly.org"), cert.DNSNames("www.v2fly.org"))

	certificate := ParseCertificate(caCert)
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	certificate2 := ParseCertificate(expiredCert)

	c := &Config{
		Certificate: []*Certificate{
			certificate,
			certificate2,
		},
	}

	tlsConfig := c.GetTLSConfig()
	v2rayCert, err := tlsConfig.GetCertificate(&gotls.ClientHelloInfo{
		ServerName: "www.v2fly.org",
	})
	common.Must(err)

	x509Cert, err := x509.ParseCertificate(v2rayCert.Certificate[0])
	common.Must(err)
	if !x509Cert.NotAfter.After(time.Now()) {
		t.Error("NotAfter: ", x509Cert.NotAfter)
	}
}

func TestInsecureCertificates(t *testing.T) {
	c := &Config{}

	tlsConfig := c.GetTLSConfig()
	if len(tlsConfig.CipherSuites) > 0 {
		t.Fatal("Unexpected tls cipher suites list: ", tlsConfig.CipherSuites)
	}
}

func BenchmarkCertificateIssuing(b *testing.B) {
	certificate := ParseCertificate(cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign)))
	certificate.Usage = Certificate_AUTHORITY_ISSUE

	c := &Config{
		Certificate: []*Certificate{
			certificate,
		},
	}

	tlsConfig := c.GetTLSConfig()
	lenCerts := len(tlsConfig.Certificates)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = tlsConfig.GetCertificate(&gotls.ClientHelloInfo{
			ServerName: "www.v2fly.org",
		})
		delete(tlsConfig.NameToCertificate, "www.v2fly.org")
		tlsConfig.Certificates = tlsConfig.Certificates[:lenCerts]
	}
}

// With RequireEch, the engine must abort the dial when the ECH config can't be
// obtained, before any ClientHello is written, so the cleartext SNI never hits
// the wire. The DoH URL points at a closed port, so ApplyECH fails offline
// (leaving EncryptedClientHelloConfigList nil) without any network; the gate
// then returns an error from Client instead of constructing the TLS conn.
func TestEngineClientRequireEchGatesUnobtainableConfig(t *testing.T) {
	c := &Config{ServerName: "example.com", Ech_DOHserver: "https://127.0.0.1:1/dns-query", RequireEch: true}
	engine, err := NewTLSSecurityEngineFromConfig(c)
	common.Must(err)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn, err := engine.Client(client)
	if err == nil {
		t.Fatal("RequireEch + unobtainable ECH config must make Client return an error (no handshake)")
	}
	if conn != nil {
		t.Fatal("gated Client must not return a connection")
	}
}

// Without RequireEch, the same unobtainable ECH config is opportunistic: the
// gate does not fire and Client returns a conn (the handshake later proceeds in
// clear). net.Pipe never reads, so no handshake is attempted here.
func TestEngineClientNoRequireEchDoesNotGate(t *testing.T) {
	c := &Config{ServerName: "example.com", Ech_DOHserver: "https://127.0.0.1:1/dns-query"}
	engine, err := NewTLSSecurityEngineFromConfig(c)
	common.Must(err)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn, err := engine.Client(client)
	if err != nil {
		t.Fatalf("without RequireEch, Client must not gate: %v", err)
	}
	if conn == nil {
		t.Fatal("without RequireEch, Client must return a connection")
	}
}

// RequireEch must survive the protobuf wire: ex-ray sets it on the tls.Config,
// serializes via serial.ToTypedMessage, and v2ray deserializes before reading
// it. A getter-only struct field with no descriptor would be dropped here.
func TestConfigRequireEchRoundTrip(t *testing.T) {
	for _, want := range []bool{true, false} {
		typed := serial.ToTypedMessage(&Config{ServerName: "example.com", RequireEch: want})
		msg, err := serial.GetInstanceOf(typed)
		common.Must(err)
		got := msg.(*Config).GetRequireEch()
		if got != want {
			t.Errorf("RequireEch round-trip = %v, want %v", got, want)
		}
	}
}

// GetTLSConfigForClient bundles build + the require-ECH gate: require_ech +
// unobtainable ECH must fail closed (nil cfg, error) before a cleartext-SNI hello.
func TestGetTLSConfigForClient(t *testing.T) {
	t.Run("require_ech unobtainable fails closed", func(t *testing.T) {
		c := &Config{ServerName: "example.com", Ech_DOHserver: "https://127.0.0.1:1/dns-query", RequireEch: true}
		cfg, err := c.GetTLSConfigForClient()
		if err == nil {
			t.Fatal("require_ech + unobtainable ECH must return an error")
		}
		if cfg != nil {
			t.Fatal("failed-closed factory must return a nil config")
		}
	})
	t.Run("auto unobtainable proceeds", func(t *testing.T) {
		c := &Config{ServerName: "example.com", Ech_DOHserver: "https://127.0.0.1:1/dns-query"}
		cfg, err := c.GetTLSConfigForClient()
		if err != nil {
			t.Fatalf("without require_ech the factory must not gate: %v", err)
		}
		if cfg == nil {
			t.Fatal("factory must return a config")
		}
	})
	t.Run("nil receiver", func(t *testing.T) {
		cfg, err := (*Config)(nil).GetTLSConfigForClient()
		if err != nil {
			t.Fatalf("nil receiver must not error: %v", err)
		}
		if cfg == nil {
			t.Fatal("nil receiver must build a default config")
		}
	})
}

// GetTLSConfigForUnsupportedClient is the ECH-incapable factory (uTLS, hysteria2):
// it runs HandleEchUnsupported then GetTLSConfig, so ech=always fails closed (nil
// cfg, error naming the engine) while ech=auto builds a config.
func TestGetTLSConfigForUnsupportedClient(t *testing.T) {
	t.Run("always refuses naming the engine", func(t *testing.T) {
		c := &Config{ServerName: "example.com", RequireEch: true}
		cfg, err := c.GetTLSConfigForUnsupportedClient("widget engine")
		if err == nil {
			t.Fatal("ech=always on an ECH-incapable engine must fail closed")
		}
		if cfg != nil {
			t.Fatal("failed-closed factory must return a nil config")
		}
		if !strings.Contains(err.Error(), "widget engine") {
			t.Fatalf("error must name the engine, got: %v", err)
		}
	})
	t.Run("auto builds a config", func(t *testing.T) {
		c := &Config{ServerName: "example.com", Ech_DOHserver: "https://127.0.0.1:1/dns-query"}
		cfg, err := c.GetTLSConfigForUnsupportedClient("widget engine")
		if err != nil {
			t.Fatalf("ech=auto must not refuse: %v", err)
		}
		if cfg == nil {
			t.Fatal("factory must return a config")
		}
	})
}

// HandleEchUnsupported is the shared policy helper for ECH-incapable engines;
// the message names the engine and the ech=always token the per-engine refuse
// tests assert on.
func TestHandleEchUnsupported(t *testing.T) {
	t.Run("always errors and names engine + ech=always", func(t *testing.T) {
		err := (&Config{RequireEch: true}).HandleEchUnsupported("widget engine")
		if err == nil {
			t.Fatal("ech=always must make the helper refuse")
		}
		if msg := err.Error(); !strings.Contains(msg, "widget engine") || !strings.Contains(msg, "ech=always") {
			t.Fatalf("error must name the engine and ech=always, got: %v", msg)
		}
	})
	t.Run("auto with ECH requested returns nil and warns", func(t *testing.T) {
		// The log handler is process-global; this subcase must not run parallel.
		var sink captureLog
		log.RegisterHandler(&sink)
		t.Cleanup(func() { log.RegisterHandler(discardLog{}) })

		if err := (&Config{Ech_DOHserver: "https://127.0.0.1:1/dns-query"}).HandleEchUnsupported("widget engine"); err != nil {
			t.Fatalf("auto must not refuse (it warns): %v", err)
		}
		if msg := sink.last(); !strings.Contains(msg, "widget engine") || !strings.Contains(msg, "ech=auto") {
			t.Fatalf("auto must warn naming the engine and ech=auto, got: %q", msg)
		}
	})
	t.Run("auto without ECH returns nil", func(t *testing.T) {
		if err := (&Config{}).HandleEchUnsupported("widget engine"); err != nil {
			t.Fatalf("auto without ECH must not refuse: %v", err)
		}
	})
	t.Run("nil receiver returns nil", func(t *testing.T) {
		if err := (*Config)(nil).HandleEchUnsupported("widget engine"); err != nil {
			t.Fatalf("nil receiver must not refuse: %v", err)
		}
	})
}

// RequireEchSatisfied is the shared gate the dial paths consult. It must error
// only when RequireEch is set and no ECH config was applied; len(nil)==0 and
// len(empty)==0 both count as "no config" (an empty-but-non-nil list must not
// slip through).
func TestRequireEchSatisfied(t *testing.T) {
	cases := []struct {
		desc       string
		requireEch bool
		echList    []byte
		wantErr    bool
	}{
		{"required, nil list", true, nil, true},
		{"required, empty list", true, []byte{}, true},
		{"required, populated list", true, []byte{0x01}, false},
		{"not required, nil list", false, nil, false},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			cfg := &gotls.Config{EncryptedClientHelloConfigList: c.echList}
			err := (&Config{RequireEch: c.requireEch}).RequireEchSatisfied(cfg)
			if (err != nil) != c.wantErr {
				t.Fatalf("RequireEchSatisfied() err = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}
