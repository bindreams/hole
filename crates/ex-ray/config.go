package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto" //nolint:staticcheck // SA1019: v2ray-core's serial.ToTypedMessage takes a v1 github.com/golang/protobuf/proto.Message; migrating would add a dependency for no benefit.
	"google.golang.org/protobuf/types/known/anypb"

	_ "github.com/v2fly/v2ray-core/v5/app/proxyman/inbound"
	_ "github.com/v2fly/v2ray-core/v5/app/proxyman/outbound"

	core "github.com/v2fly/v2ray-core/v5"
	vlog "github.com/v2fly/v2ray-core/v5/app/log"
	clog "github.com/v2fly/v2ray-core/v5/common/log"

	"github.com/v2fly/v2ray-core/v5/app/dispatcher"
	"github.com/v2fly/v2ray-core/v5/app/proxyman"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/platform/filesystem"
	"github.com/v2fly/v2ray-core/v5/common/protocol"
	"github.com/v2fly/v2ray-core/v5/common/serial"
	"github.com/v2fly/v2ray-core/v5/proxy/dokodemo"
	"github.com/v2fly/v2ray-core/v5/proxy/freedom"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/quic"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
	"github.com/v2fly/v2ray-core/v5/transport/internet/websocket"
)

var (
	vpn        = flag.Bool("V", false, "Run in VPN mode.")
	fastOpen   = flag.Bool("fast-open", false, "Enable TCP fast open.")
	localAddr  = flag.String("localAddr", "127.0.0.1", "local address to listen on.")
	localPort  = flag.String("localPort", "1984", "local port to listen on.")
	remoteAddr = flag.String("remoteAddr", "127.0.0.1", "remote address to forward.")
	remotePort = flag.String("remotePort", "1080", "remote port to forward.")
	path       = flag.String("path", "/", "URL path for websocket.")
	host       = flag.String("host", "cloudfront.com", "Hostname for server.")
	tlsEnabled = flag.Bool("tls", false, "Enable TLS.")
	cert       = flag.String("cert", "", "Path to TLS certificate file. Overrides certRaw. Default: ~/.acme.sh/{host}/fullchain.cer")
	certRaw    = flag.String("certRaw", "", "Raw TLS certificate content. Intended only for Android.")
	key        = flag.String("key", "", "(server) Path to TLS key file. Default: ~/.acme.sh/{host}/{host}.key")
	mode       = flag.String("mode", "websocket", "Transport mode: websocket, quic (enforced tls).")
	mux        = flag.Int("mux", 1, "Concurrent multiplexed connections (websocket client mode only).")
	server     = flag.Bool("server", false, "Run in server mode")
	logLevel   = flag.String("loglevel", "", "loglevel for v2ray: debug, info, warning (default), error, none.")
	version    = flag.Bool("version", false, "Show current version of ex-ray")
	fwmark     = flag.Int("fwmark", 0, "Set SO_MARK option for outbound sockets.")
	echMode    = flag.String("ech", "auto", "ECH (Encrypted Client Hello) mode: auto (opportunistic), always (fail-closed), never.")
	echDoh     = flag.String("ech-doh", "", "DoH URL used to fetch the ECH config (HTTPS record). Empty disables ECH.")
)

func homeDir() string {
	usr, err := user.Current()
	if err != nil {
		logFatal(err)
		os.Exit(1)
	}
	return usr.HomeDir
}

func readCertificate() ([]byte, error) {
	if *cert != "" {
		return filesystem.ReadFile(*cert)
	}
	if *certRaw != "" {
		certHead := "-----BEGIN CERTIFICATE-----"
		certTail := "-----END CERTIFICATE-----"
		fixedCert := certHead + "\n" + *certRaw + "\n" + certTail
		return []byte(fixedCert), nil
	}
	panic("thou shalt not reach hear")
}

func logConfig(logLevel string) *vlog.Config {
	config := &vlog.Config{
		Error:  &vlog.LogSpecification{Type: vlog.LogType_Console, Level: clog.Severity_Warning},
		Access: &vlog.LogSpecification{Type: vlog.LogType_Console},
	}
	level := strings.ToLower(logLevel)
	switch level {
	case "debug":
		config.Error.Level = clog.Severity_Debug
	case "info":
		config.Error.Level = clog.Severity_Info
	case "error":
		config.Error.Level = clog.Severity_Error
	case "none":
		config.Error.Type = vlog.LogType_None
		config.Access.Type = vlog.LogType_None
	}
	return config
}

func parseLocalAddr(localAddr string) []string {
	return strings.Split(localAddr, "|")
}

// uint32Opt converts an operator-supplied integer option to uint32, rejecting
// out-of-range values loudly instead of letting them silently wrap. The bound
// guard wrapping the conversion is gosec G115's recognized mitigation, so the
// cast needs no //nolint. The error propagates through generateConfig ->
// buildV2Ray -> main's emitFatal + os.Exit(23), the same config-error path
// (exit 23) as an invalid remotePort (main.go).
func uint32Opt(name string, v int) (uint32, error) {
	if v >= 0 && v <= math.MaxUint32 {
		return uint32(v), nil
	}
	return 0, newError("invalid", name, "(expected 0..4294967295), got:", v)
}

func generateConfig() (*core.Config, error) {
	lport, err := net.PortFromString(*localPort)
	if err != nil {
		return nil, newError("invalid localPort:", *localPort).Base(err)
	}
	rport, err := strconv.ParseUint(*remotePort, 10, 32)
	if err != nil {
		return nil, newError("invalid remotePort:", *remotePort).Base(err)
	}
	// Validate operator-supplied numeric options up-front, before the
	// server/client split, so out-of-range mux/fwmark are rejected identically
	// in both modes. This also makes the guard dominate both cast sites below,
	// so gosec G115 clears with no cast remaining at those sites.
	muxU32, err := uint32Opt("mux", *mux)
	if err != nil {
		return nil, err
	}
	fwmarkU32, err := uint32Opt("fwmark", *fwmark)
	if err != nil {
		return nil, err
	}
	outboundProxy := serial.ToTypedMessage(&freedom.Config{
		DestinationOverride: &freedom.DestinationOverride{
			Server: &protocol.ServerEndpoint{
				Address: net.NewIPOrDomain(net.ParseAddress(*remoteAddr)),
				Port:    uint32(rport),
			},
		},
	})

	var transportSettings proto.Message
	var connectionReuse bool
	switch *mode {
	case "websocket":
		transportSettings = &websocket.Config{
			Path: *path,
			Header: []*websocket.Header{
				{Key: "Host", Value: *host},
			},
		}
		if *mux != 0 {
			connectionReuse = true
		}
	case "quic":
		transportSettings = &quic.Config{
			Security: &protocol.SecurityConfig{Type: protocol.SecurityType_NONE},
		}
		*tlsEnabled = true
	default:
		return nil, newError("unsupported mode:", *mode)
	}

	streamConfig := internet.StreamConfig{
		ProtocolName: *mode,
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: *mode,
			Settings:     serial.ToTypedMessage(transportSettings),
		}},
	}
	if *fastOpen || *fwmark != 0 {
		socketConfig := &internet.SocketConfig{}
		if *fastOpen {
			socketConfig.Tfo = internet.SocketConfig_Enable
		}
		if *fwmark != 0 {
			socketConfig.Mark = fwmarkU32
		}

		streamConfig.SocketSettings = socketConfig
	}
	if *tlsEnabled {
		tlsConfig := tls.Config{ServerName: *host}
		if *server {
			certificate := tls.Certificate{}
			if *cert == "" && *certRaw == "" {
				*cert = fmt.Sprintf("%s/.acme.sh/%s/fullchain.cer", homeDir(), *host)
				logWarn("No TLS cert specified, trying", *cert)
			}
			certificate.Certificate, err = readCertificate()
			if err != nil {
				return nil, newError("failed to read cert").Base(err)
			}
			if *key == "" {
				*key = fmt.Sprintf("%[1]s/.acme.sh/%[2]s/%[2]s.key", homeDir(), *host)
				logWarn("No TLS key specified, trying", *key)
			}
			certificate.Key, err = filesystem.ReadFile(*key)
			if err != nil {
				return nil, newError("failed to read key file").Base(err)
			}
			tlsConfig.Certificate = []*tls.Certificate{&certificate}
		} else if *cert != "" || *certRaw != "" {
			certificate := tls.Certificate{Usage: tls.Certificate_AUTHORITY_VERIFY}
			certificate.Certificate, err = readCertificate()
			if err != nil {
				return nil, newError("failed to read cert").Base(err)
			}
			tlsConfig.Certificate = []*tls.Certificate{&certificate}
		}
		streamConfig.SecurityType = serial.GetMessageType(&tlsConfig)
		streamConfig.SecuritySettings = []*anypb.Any{serial.ToTypedMessage(&tlsConfig)}
	}

	apps := []*anypb.Any{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(logConfig(*logLevel)),
	}

	if *server {
		proxyAddress := net.LocalHostIP
		if connectionReuse {
			// This address is required when mux is used on client.
			// dokodemo is not aware of mux connections by itself.
			proxyAddress = net.ParseAddress("v1.mux.cool")
		}
		localAddrs := parseLocalAddr(*localAddr)
		inbounds := make([]*core.InboundHandlerConfig, len(localAddrs))

		for i := 0; i < len(localAddrs); i++ {
			inbounds[i] = &core.InboundHandlerConfig{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortRange:      net.SinglePortRange(lport),
					Listen:         net.NewIPOrDomain(net.ParseAddress(localAddrs[i])),
					StreamSettings: &streamConfig,
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(proxyAddress),
					Networks: []net.Network{net.Network_TCP},
				}),
			}
		}

		return &core.Config{
			Inbound: inbounds,
			Outbound: []*core.OutboundHandlerConfig{{
				ProxySettings: outboundProxy,
			}},
			App: apps,
		}, nil
	}

	senderConfig := proxyman.SenderConfig{StreamSettings: &streamConfig}
	if connectionReuse {
		senderConfig.MultiplexSettings = &proxyman.MultiplexingConfig{Enabled: true, Concurrency: muxU32}
	}
	return &core.Config{
		Inbound: []*core.InboundHandlerConfig{{
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				PortRange: net.SinglePortRange(lport),
				Listen:    net.NewIPOrDomain(net.ParseAddress(*localAddr)),
			}),
			ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
				Address:  net.NewIPOrDomain(net.LocalHostIP),
				Networks: []net.Network{net.Network_TCP},
			}),
		}},
		Outbound: []*core.OutboundHandlerConfig{{
			SenderSettings: serial.ToTypedMessage(&senderConfig),
			ProxySettings:  outboundProxy,
		}},
		App: apps,
	}, nil
}
