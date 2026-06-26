//go:build go1.23
// +build go1.23

package quic

import (
	gotls "crypto/tls"
	"errors"
	"testing"

	"github.com/quic-go/quic-go"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

// dialQUICWithECHRetry retries ONCE on an ECH rejection: the first dial returns a
// rejection carrying retry_configs, and the seam must re-dial with a config whose
// EncryptedClientHelloConfigList is those retry_configs. AllowInsecure keeps the
// gated build from needing a DoH lookup, and a per-test ServerName avoids
// poisoning the process-wide DoH cache for sibling tests.
func TestDialQUICWithECHRetryRetriesWithServerConfigs(t *testing.T) {
	retryConfigs := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	// The retry writes RefreshECHCache(domain) in the tls package's process-wide
	// cache, which this package cannot reach to clean up; domain is unique to this
	// test so no sibling reads the stale entry.
	const domain = "retry-quic.example"
	dest := net.TCPDestination(net.DomainAddress(domain), 443)

	var calls int
	var secondCfg *gotls.Config
	dial := func(cfg *gotls.Config) (*quic.Conn, error) {
		calls++
		if calls == 1 {
			return nil, &gotls.ECHRejectionError{RetryConfigList: retryConfigs}
		}
		secondCfg = cfg
		return nil, errors.New("sentinel: retry dial reached")
	}

	_, _ = dialQUICWithECHRetry(&tls.Config{ServerName: domain, AllowInsecure: true}, dest, dial)
	if calls != 2 {
		t.Fatalf("seam must dial exactly twice (reject + retry), got %d", calls)
	}
	if secondCfg == nil {
		t.Fatal("seam must re-dial after an ECH rejection")
	}
	if string(secondCfg.EncryptedClientHelloConfigList) != string(retryConfigs) {
		t.Fatalf("retry config-list = %v, want server retry_configs %v", secondCfg.EncryptedClientHelloConfigList, retryConfigs)
	}
}

// An ECH rejection with an EMPTY RetryConfigList is terminal: RFC 9849 gives
// nothing to retry with, so the seam must surface it without a second dial.
func TestDialQUICWithECHRetryEmptyRetryConfigsTerminal(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("empty-quic.example"), 443)

	var calls int
	dial := func(cfg *gotls.Config) (*quic.Conn, error) {
		calls++
		return nil, &gotls.ECHRejectionError{RetryConfigList: nil}
	}

	_, err := dialQUICWithECHRetry(&tls.Config{ServerName: "empty-quic.example", AllowInsecure: true}, dest, dial)
	var echRej *gotls.ECHRejectionError
	if !errors.As(err, &echRej) {
		t.Fatalf("empty-retry-config rejection must surface unchanged, got: %v", err)
	}
	if calls != 1 {
		t.Fatalf("empty RetryConfigList must not trigger a retry, got %d dials", calls)
	}
}

// A non-ECH dial error is terminal: the seam must not retry.
func TestDialQUICWithECHRetryNonECHErrorTerminal(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("nonech-quic.example"), 443)
	sentinel := errors.New("connection refused")

	var calls int
	dial := func(cfg *gotls.Config) (*quic.Conn, error) {
		calls++
		return nil, sentinel
	}

	_, err := dialQUICWithECHRetry(&tls.Config{ServerName: "nonech-quic.example", AllowInsecure: true}, dest, dial)
	if !errors.Is(err, sentinel) {
		t.Fatalf("non-ECH error must surface unchanged, got: %v", err)
	}
	if calls != 1 {
		t.Fatalf("non-ECH error must not trigger a retry, got %d dials", calls)
	}
}

// The gated config build runs in the seam: RequireEch + unobtainable ECH must
// fail closed BEFORE the first dial, so the dialer is never called.
func TestDialQUICWithECHRetryGateRunsBeforeDial(t *testing.T) {
	dest := net.TCPDestination(net.DomainAddress("gate-quic.example"), 443)

	var calls int
	dial := func(cfg *gotls.Config) (*quic.Conn, error) {
		calls++
		return nil, errors.New("sentinel: should not be reached")
	}

	c := &tls.Config{ServerName: "gate-quic.example", Ech_DOHserver: "https://127.0.0.1:1/dns-query", RequireEch: true}
	_, err := dialQUICWithECHRetry(c, dest, dial)
	if err == nil {
		t.Fatal("require_ech + unobtainable ECH must fail closed in the seam")
	}
	if calls != 0 {
		t.Fatalf("gate must fail before any dial, got %d dials", calls)
	}
}
