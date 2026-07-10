package utls

import (
	"context"
	systls "crypto/tls"
	"errors"

	utls "github.com/refraction-networking/utls"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet/security"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
)

//go:generate go run github.com/v2fly/v2ray-core/v5/common/errors/errorgen

func NewUTLSSecurityEngineFromConfig(config *Config) (security.Engine, error) {
	if config.TlsConfig == nil {
		return nil, newError("mandatory field tls_config is not specified")
	}
	return &Engine{config: config}, nil
}

type Engine struct {
	config *Config
}

// clientTLSConfig builds the *crypto/tls.Config for a uTLS client dial. An
// ECH-capable preset routes through the fail-closed gate, or carries a retry
// override directly (provably non-empty, so the gate would pass). A preset whose
// ClientHello cannot hold an ECH extension keeps the unsupported-engine path.
func (e Engine) clientTLSConfig(preset utls.ClientHelloID, echOverride []byte, options ...tls.Option) (*systls.Config, error) {
	if !presetCarriesECH(preset) {
		if len(echOverride) > 0 {
			// Contract assertion: a non-capable preset can never produce the ECH
			// rejection that makes the retry seam thread an override, so this is
			// unreachable. Panic (Go's contract-violation idiom here, matching
			// common.Must) so a wiring regression trips loudly in CI rather than
			// silently mis-dialing; a unit test constructs this impossible input.
			panic("utls: ECH override handed to a non-ECH-capable preset (contract violation)")
		}
		return e.config.TlsConfig.GetTLSConfigForUnsupportedClient("uTLS engine", options...)
	}
	if len(echOverride) > 0 {
		cfg := e.config.TlsConfig.GetTLSConfig(options...)
		// The branch guard (override non-empty) is itself the fail-closed
		// guarantee: the ECH list is set, so this cannot yield a cleartext-SNI dial.
		cfg.EncryptedClientHelloConfigList = echOverride
		return cfg, nil
	}
	return e.config.TlsConfig.GetTLSConfigForClient(options...)
}

func (e Engine) Client(conn net.Conn, opts ...security.Option) (security.Conn, error) {
	var options []tls.Option
	var echOverride []byte
	for _, v := range opts {
		switch s := v.(type) {
		case security.OptionWithALPN:
			if e.config.ForceAlpn == ForcedALPN_TRANSPORT_PREFERENCE_TAKE_PRIORITY {
				options = append(options, tls.WithNextProto(s.ALPNs...))
			}
		case security.OptionWithDestination:
			options = append(options, tls.WithDestination(s.Dest))
		case security.OptionWithECHConfigOverride:
			echOverride = s.Configs
		default:
			return nil, newError("unknown option")
		}
	}

	preset, err := nameToUTLSPreset(e.config.Imitate)
	if err != nil {
		return nil, newError("unable to get utls preset from name").Base(err)
	}

	tlsConfig, err := e.clientTLSConfig(*preset, echOverride, options...)
	if err != nil {
		return nil, err
	}

	utlsConfig, err := uTLSConfigFromTLSConfig(tlsConfig)
	if err != nil {
		return nil, newError("unable to generate utls config from tls config").Base(err)
	}

	// NoSNI and ECH are mutually exclusive: ECH needs the outer SNI (the
	// public_name), which NoSNI strips. A generic utls.Config can set both, so
	// reject the contradiction rather than emit a broken hello.
	if e.config.NoSNI && len(tlsConfig.EncryptedClientHelloConfigList) > 0 {
		return nil, newError("uTLS NoSNI cannot be combined with ECH (ECH requires the outer SNI)")
	}

	utlsClientConn := utls.UClient(conn, utlsConfig, *preset)

	if e.config.NoSNI {
		if err := utlsClientConn.RemoveSNIExtension(); err != nil {
			return nil, newError("unable to remove server name indication from utls client hello").Base(err)
		}
	}

	if err := utlsClientConn.BuildHandshakeState(); err != nil {
		return nil, newError("unable to build utls handshake state").Base(err)
	}

	// BuildHandshakeState may overwrite the uTLS ALPN setting, so reconcile
	// against the original tls settings.
	if tlsConfig.NextProtos != nil {
		for n, v := range utlsClientConn.Extensions {
			if aplnExtension, ok := v.(*utls.ALPNExtension); ok {
				if e.config.ForceAlpn == ForcedALPN_TRANSPORT_PREFERENCE_TAKE_PRIORITY {
					aplnExtension.AlpnProtocols = tlsConfig.NextProtos
					break
				}
				if e.config.ForceAlpn == ForcedALPN_NO_ALPN {
					utlsClientConn.Extensions = append(utlsClientConn.Extensions[:n], utlsClientConn.Extensions[n+1:]...)
					break
				}
			}
		}
	}

	if err := utlsClientConn.BuildHandshakeState(); err != nil {
		return nil, newError("unable to build utls handshake state after modification").Base(err)
	}

	// Deferred handshake, matching the standard tls engine's lazy contract. The
	// caller drives it (DialClientWithECHRetry, or a generic driver on first I/O);
	// ECH-rejection normalization on Handshake/Read/Write reaches the retry seam
	// whichever path fires.
	return uTLSClientConnection{utlsClientConn}, nil
}

type uTLSClientConnection struct {
	*utls.UConn
}

func (u uTLSClientConnection) GetConnectionApplicationProtocol() (string, error) {
	if err := u.Handshake(); err != nil {
		return "", err
	}
	return u.ConnectionState().NegotiatedProtocol, nil
}

// normalizeECHRejection translates a uTLS ECH rejection to the crypto/tls type so
// errors.As in DialClientWithECHRetry matches it; confines the utls import to this
// subpackage. Non-ECH errors and nil pass through unchanged.
func normalizeECHRejection(err error) error {
	var echRej *utls.ECHRejectionError
	if errors.As(err, &echRej) {
		return &systls.ECHRejectionError{RetryConfigList: echRej.RetryConfigList}
	}
	return err
}

func (u uTLSClientConnection) Handshake() error {
	return normalizeECHRejection(u.UConn.Handshake())
}

func (u uTLSClientConnection) Read(b []byte) (int, error) {
	n, err := u.UConn.Read(b)
	return n, normalizeECHRejection(err)
}

func (u uTLSClientConnection) Write(b []byte) (int, error) {
	n, err := u.UConn.Write(b)
	return n, normalizeECHRejection(err)
}

func uTLSConfigFromTLSConfig(config *systls.Config) (*utls.Config, error) { // nolint: unparam
	uconfig := &utls.Config{
		Rand:                           config.Rand,
		Time:                           config.Time,
		RootCAs:                        config.RootCAs,
		NextProtos:                     config.NextProtos,
		ServerName:                     config.ServerName,
		VerifyPeerCertificate:          config.VerifyPeerCertificate,
		InsecureSkipVerify:             config.InsecureSkipVerify,
		ClientAuth:                     utls.ClientAuthType(config.ClientAuth),
		ClientCAs:                      config.ClientCAs,
		EncryptedClientHelloConfigList: config.EncryptedClientHelloConfigList,
	}
	// uTLS rejects an ECH config paired with a sub-1.3 version; ECH is TLS 1.3
	// only, so pin the floor explicitly when carrying one.
	if len(config.EncryptedClientHelloConfigList) > 0 {
		uconfig.MinVersion = utls.VersionTLS13
		// On ECH rejection uTLS's default verify checks the outer certificate
		// against config.ServerName (the concealed inner name) rather than the outer
		// public_name as crypto/tls does, so it aborts with
		// CertificateVerificationError and never surfaces the *utls.ECHRejectionError
		// the retry seam needs (uTLS ignores InsecureSkipVerify on rejection, so the
		// abort happens even in insecure mode). Install the rejection-verify hook —
		// which suppresses that broken default — so the rejection reaches
		// DialClientWithECHRetry, which re-dials with the server's retry_configs; that
		// surviving connection undergoes full certificate verification against the
		// real inner name. The rejected handshake is discarded, so not verifying its
		// throwaway outer certificate does not weaken authentication of the kept one.
		uconfig.EncryptedClientHelloRejectionVerify = func(utls.ConnectionState) error { return nil }
	}
	return uconfig, nil
}

// presetCarriesECH reports whether the preset's ClientHello template includes an
// ECH extension slot (a GREASE slot counts — uTLS upgrades it to real ECH). A
// spec that fails to resolve is logged and treated as non-capable, so a silent
// ECH downgrade of the pinned preset stays observable.
func presetCarriesECH(id utls.ClientHelloID) bool {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		newError("uTLS preset spec did not resolve; treating as ECH-incapable").Base(err).AtWarning().WriteToLog()
		return false
	}
	for _, ext := range spec.Extensions {
		if _, ok := ext.(utls.EncryptedClientHelloExtension); ok {
			return true
		}
	}
	return false
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewUTLSSecurityEngineFromConfig(config.(*Config))
	}))
}
