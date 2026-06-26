package tls

import (
	"crypto/tls"

	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet/security"
)

type Engine struct {
	config *Config
}

func (e *Engine) Client(conn net.Conn, opts ...security.Option) (security.Conn, error) {
	var options []Option
	var echOverride []byte
	for _, v := range opts {
		switch s := v.(type) {
		case security.OptionWithALPN:
			options = append(options, WithNextProto(s.ALPNs...))
		case security.OptionWithDestination:
			options = append(options, WithDestination(s.Dest))
		case security.OptionWithECHConfigOverride:
			echOverride = s.Configs
		default:
			return nil, newError("unknown option")
		}
	}

	var config *tls.Config
	if len(echOverride) > 0 {
		// The override is the race-free ECH-rejection retry seam. Its configs are
		// provably non-empty, so skip the require-ECH gate (it would pass anyway)
		// and build the bare config: the retry must not depend on a momentary
		// DoH/cache miss.
		config = e.config.GetTLSConfig(options...)
		config.EncryptedClientHelloConfigList = echOverride
	} else {
		var err error
		config, err = e.config.GetTLSConfigForClient(options...)
		if err != nil {
			return nil, err
		}
	}

	tlsConn := Client(conn, config)
	return tlsConn, nil
}

func NewTLSSecurityEngineFromConfig(config *Config) (security.Engine, error) {
	return &Engine{config: config}, nil
}
