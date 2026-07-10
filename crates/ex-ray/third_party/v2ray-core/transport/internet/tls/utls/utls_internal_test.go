package utls

import (
	"testing"

	utls "github.com/refraction-networking/utls"
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
