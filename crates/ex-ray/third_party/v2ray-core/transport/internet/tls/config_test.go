package tls_test

import (
	gotls "crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/protocol/tls/cert"
	. "github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

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

// With RequireEch, an ApplyECH failure (here: an unreachable DoH server) must
// install a VerifyConnection hook that rejects every handshake, so the real SNI
// is never sent in clear. The DoH URL points at a closed port, so ApplyECH
// fails offline without any network.
func TestGetTLSConfigRequireEchPoisonsOnApplyFailure(t *testing.T) {
	c := &Config{ServerName: "example.com", Ech_DOHserver: "https://127.0.0.1:1/dns-query", RequireEch: true}
	cfg := c.GetTLSConfig()
	if cfg.VerifyConnection == nil {
		t.Fatal("RequireEch + ApplyECH failure must install a poisoning VerifyConnection hook")
	}
	if err := cfg.VerifyConnection(gotls.ConnectionState{}); err == nil {
		t.Fatal("poisoned VerifyConnection must reject the handshake")
	}
}

// Without RequireEch, an ApplyECH failure stays opportunistic: no poison, the
// handshake proceeds in clear (byte-identical to the no-RequireEch path).
func TestGetTLSConfigRequireEchAbsentWhenNotSet(t *testing.T) {
	c := &Config{ServerName: "example.com", Ech_DOHserver: "https://127.0.0.1:1/dns-query"}
	if c.GetTLSConfig().VerifyConnection != nil {
		t.Fatal("without RequireEch, ApplyECH failure must fall back to cleartext (no poison)")
	}
}
