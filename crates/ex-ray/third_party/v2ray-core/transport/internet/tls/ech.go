//go:build go1.23
// +build go1.23

package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

// echCacheDomain is the single source of the DoH/cache key: echQueryDomain when
// set, else serverName, and "" when neither resolves to a domain. ApplyECH and
// RefreshECHCache both key on it so a retry-config refresh lands under the key a
// future dial reads. Pass the same serverName ApplyECH sees (the resolved
// config.ServerName) so the keys match.
func echCacheDomain(echQueryDomain, serverName string) string {
	domain := echQueryDomain
	if domain == "" {
		domain = serverName
	}
	if addr := net.ParseAddress(domain); addr.Family().IsDomain() {
		return addr.Domain()
	}
	return ""
}

func ApplyECH(c *Config, config *tls.Config) error {
	var ECHConfig []byte
	var err error

	if len(c.EchConfig) > 0 {
		ECHConfig = c.EchConfig
	} else { // ECH config > DOH lookup
		domain := echCacheDomain(c.EchQueryDomain, config.ServerName)
		if domain == "" {
			return newError("Using DOH for ECH needs SNI")
		}
		ECHConfig, err = QueryRecord(domain, c.Ech_DOHserver)
		if err != nil {
			return err
		}
	}

	// An empty record is unobtainable, not a usable config: leave the list empty
	// so the dial-path require-ECH gate fires instead of handshaking ECH-less.
	if len(ECHConfig) == 0 {
		return newError("empty ECH config")
	}

	config.EncryptedClientHelloConfigList = ECHConfig
	return nil
}

// RefreshECHCache stores the server's retry_configs so FUTURE dials skip the
// stale config; the current connection's retry threads them directly, so this is
// best-effort. serverName is the resolved config.ServerName the rejected dial
// used, so the write keys identically to a future ApplyECH lookup. No-op on empty
// configs. retry_configs with no keyable domain (IP SNI, no EchQueryDomain) leaves
// a debug breadcrumb and writes nothing. An absent or expired entry resets to
// now+600s; an un-expired entry keeps its expiry so a fresh DoH TTL is not clobbered.
func RefreshECHCache(c *Config, serverName string, retryConfigs []byte) {
	if len(retryConfigs) == 0 {
		return
	}
	echQueryDomain := ""
	if c != nil {
		echQueryDomain = c.EchQueryDomain
	}
	domain := echCacheDomain(echQueryDomain, serverName)
	if domain == "" {
		newError("ECH retry_configs received but no SNI domain to key the cache; future dials retry per-connection").AtDebug().WriteToLog()
		return
	}

	mutex.Lock()
	defer mutex.Unlock()
	rec := dnsCache[domain]
	rec.record = retryConfigs
	if !rec.expire.After(time.Now()) {
		rec.expire = time.Now().Add(600 * time.Second)
	}
	dnsCache[domain] = rec
}

type record struct {
	record []byte
	expire time.Time
}

var (
	dnsCache = make(map[string]record)
	mutex    sync.RWMutex
)

func QueryRecord(domain string, server string) ([]byte, error) {
	mutex.Lock()
	rec, found := dnsCache[domain]
	if found && rec.expire.After(time.Now()) {
		mutex.Unlock()
		return rec.record, nil
	}
	mutex.Unlock()

	newError("Trying to query ECH config for domain: ", domain, " with ECH server: ", server).AtDebug().WriteToLog()
	record, ttl, err := dohQuery(server, domain)
	if err != nil {
		return []byte{}, err
	}

	if ttl < 600 {
		ttl = 600
	}

	mutex.Lock()
	defer mutex.Unlock()
	rec.record = record
	rec.expire = time.Now().Add(time.Second * time.Duration(ttl))
	dnsCache[domain] = rec
	return record, nil
}

func dohQuery(server string, domain string) ([]byte, uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	m.Id = 0
	msg, err := m.Pack()
	if err != nil {
		return []byte{}, 0, err
	}
	tr := &http.Transport{
		IdleConnTimeout:   90 * time.Second,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			conn, err := internet.DialSystem(ctx, dest, nil)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest("POST", server, bytes.NewReader(msg))
	if err != nil {
		return []byte{}, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, 0, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return []byte{}, 0, newError("query failed with response code:", resp.StatusCode)
	}
	respMsg := new(dns.Msg)
	err = respMsg.Unpack(respBody)
	if err != nil {
		return []byte{}, 0, err
	}
	if len(respMsg.Answer) > 0 {
		for _, answer := range respMsg.Answer {
			if https, ok := answer.(*dns.HTTPS); ok && https.Hdr.Name == dns.Fqdn(domain) {
				for _, v := range https.Value {
					if echConfig, ok := v.(*dns.SVCBECHConfig); ok {
						newError(context.Background(), "Get ECH config:", echConfig.String(), " TTL:", respMsg.Answer[0].Header().Ttl).AtDebug().WriteToLog()
						return echConfig.ECH, answer.Header().Ttl, nil
					}
				}
			}
		}
	}
	return []byte{}, 0, newError("no ech record found")
}
