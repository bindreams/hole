package tls

import (
	"crypto/hmac"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/protocol/tls/cert"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

var globalSessionCache = tls.NewLRUClientSessionCache(128)

const exp8357 = "experiment:8357"

// ParseCertificate converts a cert.Certificate to Certificate.
func ParseCertificate(c *cert.Certificate) *Certificate {
	if c != nil {
		certPEM, keyPEM := c.ToPEM()
		return &Certificate{
			Certificate: certPEM,
			Key:         keyPEM,
		}
	}
	return nil
}

func (c *Config) loadSelfCertPool(usage Certificate_Usage) (*x509.CertPool, error) {
	root := x509.NewCertPool()
	for _, cert := range c.Certificate {
		if cert.Usage == usage {
			if !root.AppendCertsFromPEM(cert.Certificate) {
				return nil, newError("failed to append cert").AtWarning()
			}
		}
	}
	return root, nil
}

// BuildCertificates builds a list of TLS certificates from proto definition.
func (c *Config) BuildCertificates() []tls.Certificate {
	certs := make([]tls.Certificate, 0, len(c.Certificate))
	for _, entry := range c.Certificate {
		if entry.Usage != Certificate_ENCIPHERMENT {
			continue
		}
		keyPair, err := tls.X509KeyPair(entry.Certificate, entry.Key)
		if err != nil {
			newError("ignoring invalid X509 key pair").Base(err).AtWarning().WriteToLog()
			continue
		}
		certs = append(certs, keyPair)
	}
	return certs
}

func isCertificateExpired(c *tls.Certificate) bool {
	if c.Leaf == nil && len(c.Certificate) > 0 {
		if pc, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			c.Leaf = pc
		}
	}

	// If leaf is not there, the certificate is probably not used yet. We trust user to provide a valid certificate.
	return c.Leaf != nil && c.Leaf.NotAfter.Before(time.Now().Add(time.Minute*2))
}

func issueCertificate(rawCA *Certificate, domain string) (*tls.Certificate, error) {
	parent, err := cert.ParseCertificate(rawCA.Certificate, rawCA.Key)
	if err != nil {
		return nil, newError("failed to parse raw certificate").Base(err)
	}
	newCert, err := cert.Generate(parent, cert.CommonName(domain), cert.DNSNames(domain))
	if err != nil {
		return nil, newError("failed to generate new certificate for ", domain).Base(err)
	}
	newCertPEM, newKeyPEM := newCert.ToPEM()
	cert, err := tls.X509KeyPair(newCertPEM, newKeyPEM)
	return &cert, err
}

func (c *Config) getCustomCA() []*Certificate {
	certs := make([]*Certificate, 0, len(c.Certificate))
	for _, certificate := range c.Certificate {
		if certificate.Usage == Certificate_AUTHORITY_ISSUE {
			certs = append(certs, certificate)
		}
	}
	return certs
}

func getGetCertificateFunc(c *tls.Config, ca []*Certificate) func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var access sync.RWMutex

	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		domain := hello.ServerName
		certExpired := false

		access.RLock()
		certificate, found := c.NameToCertificate[domain]
		access.RUnlock()

		if found {
			if !isCertificateExpired(certificate) {
				return certificate, nil
			}
			certExpired = true
		}

		if certExpired {
			newCerts := make([]tls.Certificate, 0, len(c.Certificates))

			access.Lock()
			for _, certificate := range c.Certificates {
				cert := certificate
				if !isCertificateExpired(&cert) {
					newCerts = append(newCerts, cert)
				} else if cert.Leaf != nil {
					expTime := cert.Leaf.NotAfter.Format(time.RFC3339)
					newError("old certificate for ", domain, " (expire on ", expTime, ") discard").AtInfo().WriteToLog()
				}
			}

			c.Certificates = newCerts
			access.Unlock()
		}

		var issuedCertificate *tls.Certificate

		// Create a new certificate from existing CA if possible
		for _, rawCert := range ca {
			if rawCert.Usage == Certificate_AUTHORITY_ISSUE {
				newCert, err := issueCertificate(rawCert, domain)
				if err != nil {
					newError("failed to issue new certificate for ", domain).Base(err).WriteToLog()
					continue
				}
				parsed, err := x509.ParseCertificate(newCert.Certificate[0])
				if err == nil {
					newCert.Leaf = parsed
					expTime := parsed.NotAfter.Format(time.RFC3339)
					newError("new certificate for ", domain, " (expire on ", expTime, ") issued").AtInfo().WriteToLog()
				} else {
					newError("failed to parse new certificate for ", domain).Base(err).WriteToLog()
				}

				access.Lock()
				c.Certificates = append(c.Certificates, *newCert)
				issuedCertificate = &c.Certificates[len(c.Certificates)-1]
				access.Unlock()
				break
			}
		}

		if issuedCertificate == nil {
			return nil, newError("failed to create a new certificate for ", domain)
		}

		access.Lock()
		c.BuildNameToCertificate()
		access.Unlock()

		return issuedCertificate, nil
	}
}

func (c *Config) IsExperiment8357() bool {
	return strings.HasPrefix(c.ServerName, exp8357)
}

func (c *Config) parseServerName() string {
	if c.IsExperiment8357() {
		return c.ServerName[len(exp8357):]
	}

	return c.ServerName
}

func (c *Config) verifyPeerCert(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if c.PinnedPeerCertificateChainSha256 != nil {
		hashValue := GenerateCertChainHash(rawCerts)
		for _, v := range c.PinnedPeerCertificateChainSha256 {
			if hmac.Equal(hashValue, v) {
				return nil
			}
		}
		return newError("peer cert is unrecognized: ", base64.StdEncoding.EncodeToString(hashValue))
	}
	return nil
}

type alwaysFlushWriter struct {
	file *os.File
}

func (a *alwaysFlushWriter) Write(p []byte) (n int, err error) {
	n, err = a.file.Write(p)
	a.file.Sync()
	return n, err
}

// GetTLSConfig converts this Config into tls.Config.
//
// WARNING: this builds a bare config with no ECH fail-closed gate, so client dial
// paths must NOT call it directly — ECH-capable paths use GetTLSConfigForClient and
// ECH-incapable engines (uTLS, hysteria2) use GetTLSConfigForUnsupportedClient; both
// fail closed so a required-but-unobtainable ECH config never leaks the real SNI in
// cleartext. Only server listeners, which send no ClientHello, call this directly.
func (c *Config) GetTLSConfig(opts ...Option) *tls.Config {
	root, err := c.getCertPool()
	if err != nil {
		newError("failed to load system root certificate").AtError().Base(err).WriteToLog()
	}

	if c == nil {
		return &tls.Config{
			ClientSessionCache:     globalSessionCache,
			RootCAs:                root,
			InsecureSkipVerify:     false,
			NextProtos:             nil,
			SessionTicketsDisabled: true,
		}
	}

	clientRoot, err := c.loadSelfCertPool(Certificate_AUTHORITY_VERIFY_CLIENT)
	if err != nil {
		newError("failed to load client root certificate").AtError().Base(err).WriteToLog()
	}

	config := &tls.Config{
		ClientSessionCache:     globalSessionCache,
		RootCAs:                root,
		InsecureSkipVerify:     c.AllowInsecure,
		NextProtos:             c.NextProtocol,
		SessionTicketsDisabled: !c.EnableSessionResumption,
		VerifyPeerCertificate:  c.verifyPeerCert,
		ClientCAs:              clientRoot,
	}

	if c.AllowInsecureIfPinnedPeerCertificate && c.PinnedPeerCertificateChainSha256 != nil {
		config.InsecureSkipVerify = true
	}

	for _, opt := range opts {
		opt(config)
	}

	config.Certificates = c.BuildCertificates()
	config.BuildNameToCertificate()

	caCerts := c.getCustomCA()
	if len(caCerts) > 0 {
		config.GetCertificate = getGetCertificateFunc(config, caCerts)
	}

	if sn := c.parseServerName(); len(sn) > 0 {
		config.ServerName = sn
	}

	if len(config.NextProtos) == 0 {
		config.NextProtos = []string{"h2", "http/1.1"}
	}

	if c.VerifyClientCertificate {
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	switch c.MinVersion {
	case Config_TLS1_0:
		config.MinVersion = tls.VersionTLS10
	case Config_TLS1_1:
		config.MinVersion = tls.VersionTLS11
	case Config_TLS1_2:
		config.MinVersion = tls.VersionTLS12
	case Config_TLS1_3:
		config.MinVersion = tls.VersionTLS13
	}

	switch c.MaxVersion {
	case Config_TLS1_0:
		config.MaxVersion = tls.VersionTLS10
	case Config_TLS1_1:
		config.MaxVersion = tls.VersionTLS11
	case Config_TLS1_2:
		config.MaxVersion = tls.VersionTLS12
	case Config_TLS1_3:
		config.MaxVersion = tls.VersionTLS13
	}

	if len(c.EchConfig) > 0 || len(c.Ech_DOHserver) > 0 {
		// On failure ApplyECH leaves EncryptedClientHelloConfigList empty; the
		// GetTLSConfigForClient gate then aborts an ech=always dial (require_ech)
		// or proceeds in cleartext (auto).
		if err := ApplyECH(c, config); err != nil {
			newError("unable to set ECH").AtError().Base(err).WriteToLog()
		}
	}

	if len(c.Ciphersuites) > 0 {
		config.CipherSuites = make([]uint16, 0, len(c.Ciphersuites))
		for _, cs := range c.Ciphersuites {
			config.CipherSuites = append(config.CipherSuites, uint16(cs))
		}
	}

	return config
}

// RequireEchSatisfied reports an error when ech=always (RequireEch) was set but
// no ECH config was applied, so a client dial path can fail BEFORE the handshake
// writes a cleartext-SNI ClientHello. cfg is the *crypto/tls.Config built by
// GetTLSConfig; len==0 catches both a nil and an empty-but-non-nil ECH list.
func (c *Config) RequireEchSatisfied(cfg *tls.Config) error {
	if c != nil && c.RequireEch && len(cfg.EncryptedClientHelloConfigList) == 0 {
		return newError("ECH required but no ECH config could be obtained; refusing to handshake (would leak cleartext SNI)")
	}
	return nil
}

// HandleEchUnsupported applies the ECH policy for a transport that cannot carry
// an ECH config (its conversion drops EncryptedClientHelloConfigList): it refuses
// when ech=always (RequireEch) so the dial fails closed instead of writing a
// cleartext-SNI ClientHello, and warns when ech=auto requested ECH so the
// cleartext-SNI fallback is observable.
func (c *Config) HandleEchUnsupported(engine string) error {
	if c == nil {
		return nil
	}
	if c.RequireEch {
		return newError(engine + " cannot satisfy ech=always (cannot carry an ECH config); refusing to handshake")
	}
	if len(c.EchConfig) > 0 || len(c.Ech_DOHserver) > 0 {
		newError(engine + " cannot carry ECH; proceeding with cleartext SNI under ech=auto").AtWarning().WriteToLog()
	}
	return nil
}

// GetTLSConfigForClient builds a client *tls.Config and fails closed when
// ech=always (RequireEch) is set but no ECH config could be obtained, so the
// dial aborts before a cleartext-SNI ClientHello is written. ECH-capable client
// dial paths call this; see GetTLSConfig's warning for the full contract.
func (c *Config) GetTLSConfigForClient(opts ...Option) (*tls.Config, error) {
	config := c.GetTLSConfig(opts...)
	if err := c.RequireEchSatisfied(config); err != nil {
		return nil, err
	}
	return config, nil
}

// GetTLSConfigForUnsupportedClient builds a client *tls.Config for an engine that
// cannot carry an ECH config (uTLS, hysteria2): it runs HandleEchUnsupported(engine)
// first — refusing ech=always, warning on ech=auto — so the incapable path is
// fail-closed by construction like GetTLSConfigForClient.
func (c *Config) GetTLSConfigForUnsupportedClient(engine string, opts ...Option) (*tls.Config, error) {
	if err := c.HandleEchUnsupported(engine); err != nil {
		return nil, err
	}
	return c.GetTLSConfig(opts...), nil
}

// Option for building TLS config.
type Option func(*tls.Config)

// WithDestination sets the server name in TLS config.
func WithDestination(dest net.Destination) Option {
	return func(config *tls.Config) {
		if config.ServerName == "" {
			switch dest.Address.Family() {
			case net.AddressFamilyDomain:
				config.ServerName = dest.Address.Domain()
			case net.AddressFamilyIPv4, net.AddressFamilyIPv6:
				config.ServerName = dest.Address.IP().String()
			}
		}
	}
}

// WithNextProto sets the ALPN values in TLS config.
func WithNextProto(protocol ...string) Option {
	return func(config *tls.Config) {
		if len(config.NextProtos) == 0 {
			config.NextProtos = protocol
		}
	}
}

// ConfigFromStreamSettings fetches Config from stream settings. Nil if not found.
func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil {
		return nil
	}
	if settings.SecuritySettings == nil {
		return nil
	}
	// Fail close for unknown TLS settings type.
	// For TLS Clients, Security Engine should be used, instead of this.
	config := settings.SecuritySettings.(*Config)
	return config
}

// TLSConfigFromStreamSettings returns the TLS Config when the security settings
// are TLS, else nil — without the fail-closed panic of ConfigFromStreamSettings.
// A client dial path uses this to pass the proto config to the ECH-retry helper
// even when a non-TLS engine (e.g. uTLS) is selected; the helper uses it only for
// the best-effort cache refresh, which a non-TLS engine never reaches.
func TLSConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil {
		return nil
	}
	config, _ := settings.SecuritySettings.(*Config)
	return config
}
