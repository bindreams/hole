//go:build go1.23
// +build go1.23

package tls

import (
	"crypto/tls"
	"testing"
	"time"
)

// An empty (zero-length) DoH ECH record is "unobtainable", not a usable config:
// ApplyECH must return an error and leave EncryptedClientHelloConfigList empty so
// the dial-path gate fires. The cache is seeded so the empty record is reached
// without any network. (A server advertising an empty SVCB ECH value would
// otherwise silently pass the gate.)
func TestApplyECHRejectsEmptyRecord(t *testing.T) {
	const domain = "empty-ech.example"
	mutex.Lock()
	dnsCache[domain] = record{record: []byte{}, expire: time.Now().Add(time.Hour)}
	mutex.Unlock()
	defer func() {
		mutex.Lock()
		delete(dnsCache, domain)
		mutex.Unlock()
	}()

	c := &Config{ServerName: domain, Ech_DOHserver: "https://127.0.0.1:1/dns-query"}
	cfg := &tls.Config{ServerName: domain}
	if err := ApplyECH(c, cfg); err == nil {
		t.Fatal("ApplyECH must reject an empty ECH record")
	}
	if len(cfg.EncryptedClientHelloConfigList) != 0 {
		t.Fatal("ApplyECH must not apply an empty ECH record")
	}
}
