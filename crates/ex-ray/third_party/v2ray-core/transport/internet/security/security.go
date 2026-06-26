package security

//go:generate go run github.com/v2fly/v2ray-core/v5/common/errors/errorgen

import (
	"github.com/v2fly/v2ray-core/v5/common/net"
)

type Engine interface {
	Client(conn net.Conn, opts ...Option) (Conn, error)
}

type Conn interface {
	net.Conn
}

type Option interface {
	isSecurityOption()
}

type OptionWithALPN struct {
	ALPNs []string
}

func (a OptionWithALPN) isSecurityOption() {
}

type OptionWithDestination struct {
	Dest net.Destination
}

func (a OptionWithDestination) isSecurityOption() {
}

// OptionWithECHConfigOverride forces the engine's client config to carry these
// ECH configs (EncryptedClientHelloConfigList), bypassing the DoH cache. It is
// the race-free seam for an ECH-rejection retry: the server's retry_configs are
// threaded directly into the retry connection. An engine that cannot carry ECH
// (uTLS) treats it as a no-op.
type OptionWithECHConfigOverride struct {
	Configs []byte
}

func (a OptionWithECHConfigOverride) isSecurityOption() {
}
