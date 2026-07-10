package utls

import (
	systls "crypto/tls"
	"errors"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"

	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

// presetCarriesECH must be true exactly for presets whose ClientHello template
// holds an ECH extension slot; uTLS can compose real ECH only with those.
func TestPresetCarriesECH(t *testing.T) {
	cases := []struct {
		name string
		id   utls.ClientHelloID
		want bool
	}{
		{"chrome_auto", utls.HelloChrome_Auto, true},
		{"firefox_auto", utls.HelloFirefox_Auto, true},
		{"chrome_133", utls.HelloChrome_133, true},
		{"edge_auto", utls.HelloEdge_Auto, false},
		{"safari_auto", utls.HelloSafari_Auto, false},
		{"chrome_102", utls.HelloChrome_102, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := presetCarriesECH(c.id); got != c.want {
				t.Fatalf("presetCarriesECH(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// chrome_auto is the shipped default fingerprint: it must resolve AND be
// ECH-capable, else a websocket dial downgrades to a cleartext-SNI hello under
// ech=auto. Guards against a uTLS uplift breaking the entry or Chrome's ECH slot.
func TestDefaultFingerprintResolvesAndCarriesECH(t *testing.T) {
	preset, err := nameToUTLSPreset("chrome_auto")
	if err != nil {
		t.Fatalf("default fingerprint chrome_auto must resolve: %v", err)
	}
	if !presetCarriesECH(*preset) {
		t.Fatal("default fingerprint chrome_auto must be ECH-capable")
	}
}

func TestUTLSConfigFromTLSConfigCarriesECH(t *testing.T) {
	echList := []byte{0x00, 0x05, 0xAA, 0xBB, 0xCC}
	out, err := uTLSConfigFromTLSConfig(&systls.Config{
		ServerName:                     "example.com",
		EncryptedClientHelloConfigList: echList,
	})
	if err != nil {
		t.Fatalf("uTLSConfigFromTLSConfig error: %v", err)
	}
	if string(out.EncryptedClientHelloConfigList) != string(echList) {
		t.Fatalf("ECH list not carried: got %v, want %v", out.EncryptedClientHelloConfigList, echList)
	}
	if out.MinVersion != utls.VersionTLS13 {
		t.Fatalf("ECH requires MinVersion TLS1.3, got 0x%x", out.MinVersion)
	}
}

func TestUTLSConfigFromTLSConfigNoECHLeavesVersionUnset(t *testing.T) {
	out, err := uTLSConfigFromTLSConfig(&systls.Config{ServerName: "example.com"})
	if err != nil {
		t.Fatalf("uTLSConfigFromTLSConfig error: %v", err)
	}
	if len(out.EncryptedClientHelloConfigList) != 0 {
		t.Fatalf("no ECH expected, got %v", out.EncryptedClientHelloConfigList)
	}
	if out.MinVersion != 0 {
		t.Fatalf("without ECH, MinVersion must stay unset, got 0x%x", out.MinVersion)
	}
}

// normalizeECHRejection must translate a uTLS ECH rejection to the crypto/tls
// type (preserving RetryConfigList) so DialClientWithECHRetry's errors.As matches
// it, and pass every other value (including nil) through unchanged.
func TestNormalizeECHRejection(t *testing.T) {
	rc := []byte{0x01, 0x02}
	got := normalizeECHRejection(&utls.ECHRejectionError{RetryConfigList: rc})
	var gotls *systls.ECHRejectionError
	if !errors.As(got, &gotls) {
		t.Fatalf("must normalize to *crypto/tls.ECHRejectionError, got %T", got)
	}
	if string(gotls.RetryConfigList) != string(rc) {
		t.Fatalf("RetryConfigList = %v, want %v", gotls.RetryConfigList, rc)
	}
	plain := errors.New("boom")
	if normalizeECHRejection(plain) != plain {
		t.Fatal("non-ECH error must pass through unchanged")
	}
	if normalizeECHRejection(nil) != nil {
		t.Fatal("nil must pass through as nil")
	}
}

// clientTLSConfig must panic (contract violation) when an ECH override is handed
// to a non-ECH-capable preset — the retry seam can never produce that, so reaching
// it is a wiring bug. This drives the impossible input directly so the assertion
// is exercised in CI.
func TestClientTLSConfigPanicsOnOverrideForNonECHPreset(t *testing.T) {
	engine := Engine{config: &Config{TlsConfig: &tls.Config{ServerName: "example.com"}}}
	defer func() {
		r := recover()
		s, ok := r.(string)
		if !ok || !strings.Contains(s, "contract violation") {
			t.Fatalf("expected a contract-violation panic, got: %v", r)
		}
	}()
	_, _ = engine.clientTLSConfig(utls.HelloEdge_Auto, []byte{0x01})
}
