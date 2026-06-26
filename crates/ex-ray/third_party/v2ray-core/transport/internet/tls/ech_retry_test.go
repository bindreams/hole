//go:build go1.23
// +build go1.23

package tls

import (
	"testing"
	"time"

	"github.com/v2fly/v2ray-core/v5/common/log"
	"github.com/v2fly/v2ray-core/v5/transport/internet/security"
)

// internalCaptureLog records the last v2ray-core log message for an in-package
// test; the external config_test.go helper is not visible from package tls.
// discardInternalLog restores a no-op handler (RegisterHandler panics on nil).
type internalCaptureLog struct{ msg string }

func (c *internalCaptureLog) Handle(m log.Message) { c.msg = m.String() }
func (c *internalCaptureLog) last() string         { return c.msg }

type discardInternalLog struct{}

func (discardInternalLog) Handle(log.Message) {}

// echCacheDomain is the single source of the DoH/cache key: echQueryDomain when
// set, else the (already-resolved) serverName, and "" when neither resolves to a
// domain (an IP SNI has nothing to key a DoH lookup on).
func TestEchCacheDomain(t *testing.T) {
	cases := []struct {
		desc           string
		echQueryDomain string
		serverName     string
		want           string
	}{
		{"server name", "", "example.com", "example.com"},
		{"query domain overrides server name", "ech.example.org", "example.com", "ech.example.org"},
		{"ipv4 server name", "", "127.0.0.1", ""},
		{"ipv6 server name", "", "::1", ""},
		{"empty", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			if got := echCacheDomain(c.echQueryDomain, c.serverName); got != c.want {
				t.Fatalf("echCacheDomain() = %q, want %q", got, c.want)
			}
		})
	}
}

// RefreshECHCache writes the server's retry_configs for FUTURE dials. It keys on
// echCacheDomain, refreshes only the bytes, and resets the expiry of an absent or
// expired entry to now+600s.
func TestRefreshECHCacheWritesAndResetsExpiry(t *testing.T) {
	const domain = "refresh-new.example"
	mutex.Lock()
	delete(dnsCache, domain)
	mutex.Unlock()
	t.Cleanup(func() {
		mutex.Lock()
		delete(dnsCache, domain)
		mutex.Unlock()
	})

	configs := []byte{0xAB, 0xCD}
	before := time.Now()
	RefreshECHCache(&Config{ServerName: domain}, domain, configs)
	after := time.Now()

	mutex.RLock()
	rec, found := dnsCache[domain]
	mutex.RUnlock()
	if !found {
		t.Fatal("RefreshECHCache must write the entry")
	}
	if string(rec.record) != string(configs) {
		t.Fatalf("cached bytes = %v, want %v", rec.record, configs)
	}
	wantLo := before.Add(600 * time.Second)
	wantHi := after.Add(600 * time.Second)
	if rec.expire.Before(wantLo) || rec.expire.After(wantHi) {
		t.Fatalf("expiry %v not in [%v, %v] (want fresh now+600s)", rec.expire, wantLo, wantHi)
	}
}

// Refreshing an un-expired entry keeps its expiry EXACTLY (only the bytes update),
// so a fresh DoH-derived TTL is not clobbered by the best-effort retry write.
func TestRefreshECHCachePreservesUnexpiredTTL(t *testing.T) {
	const domain = "refresh-keep.example"
	seededExpiry := time.Now().Add(9999 * time.Hour)
	mutex.Lock()
	dnsCache[domain] = record{record: []byte{0x01}, expire: seededExpiry}
	mutex.Unlock()
	t.Cleanup(func() {
		mutex.Lock()
		delete(dnsCache, domain)
		mutex.Unlock()
	})

	RefreshECHCache(&Config{ServerName: domain}, domain, []byte{0x02, 0x03})

	mutex.RLock()
	rec := dnsCache[domain]
	mutex.RUnlock()
	if string(rec.record) != string([]byte{0x02, 0x03}) {
		t.Fatalf("bytes not refreshed: %v", rec.record)
	}
	if !rec.expire.Equal(seededExpiry) {
		t.Fatalf("expiry = %v, want exactly seeded %v", rec.expire, seededExpiry)
	}
}

// An expired entry is treated like an absent one: refresh resets to now+600s
// rather than preserving the stale expiry.
func TestRefreshECHCacheResetsExpiredTTL(t *testing.T) {
	const domain = "refresh-expired.example"
	mutex.Lock()
	dnsCache[domain] = record{record: []byte{0x01}, expire: time.Now().Add(-time.Hour)}
	mutex.Unlock()
	t.Cleanup(func() {
		mutex.Lock()
		delete(dnsCache, domain)
		mutex.Unlock()
	})

	before := time.Now()
	RefreshECHCache(&Config{ServerName: domain}, domain, []byte{0x02})
	after := time.Now()

	mutex.RLock()
	rec := dnsCache[domain]
	mutex.RUnlock()
	if rec.expire.Before(before.Add(600*time.Second)) || rec.expire.After(after.Add(600*time.Second)) {
		t.Fatalf("expired entry must reset to now+600s, got %v", rec.expire)
	}
}

// Empty retry_configs is a plain no-op: nothing to store, no log breadcrumb.
func TestRefreshECHCacheEmptyIsNoOp(t *testing.T) {
	const domain = "refresh-empty.example"
	mutex.Lock()
	delete(dnsCache, domain)
	mutex.Unlock()

	RefreshECHCache(&Config{ServerName: domain}, domain, nil)

	mutex.RLock()
	_, found := dnsCache[domain]
	mutex.RUnlock()
	if found {
		t.Fatal("empty retry_configs must not write a cache entry")
	}
}

// retry_configs arriving with no SNI domain to key the cache (IP SNI, no
// EchQueryDomain) cannot be stored; emit a breadcrumb so the dropped best-effort
// refresh is observable, and write nothing.
func TestRefreshECHCacheNoDomainLogsBreadcrumb(t *testing.T) {
	var sink internalCaptureLog
	log.RegisterHandler(&sink)
	t.Cleanup(func() { log.RegisterHandler(discardInternalLog{}) })

	RefreshECHCache(&Config{ServerName: "127.0.0.1"}, "127.0.0.1", []byte{0x01})

	if msg := sink.last(); msg == "" {
		t.Fatal("retry_configs with no keyable domain must emit a debug breadcrumb")
	}
}

// forceHandshake must observe the ECH rejection via Handshake(); a conn that
// lacks Handshake() is an unexpected engine — a contract violation, not a silent
// success. Returning nil would let an un-handshaked conn pass as established.
type noHandshakeConn struct{ security.Conn }

func TestForceHandshakeContractViolation(t *testing.T) {
	err := forceHandshake(noHandshakeConn{})
	if err == nil {
		t.Fatal("a conn lacking Handshake() must return a contract-violation error, not nil")
	}
}
