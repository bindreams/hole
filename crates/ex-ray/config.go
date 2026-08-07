package main

import (
	"flag"
	"fmt"
	"math"
	"os/user"
	"slices"
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
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls/utls"
	"github.com/v2fly/v2ray-core/v5/transport/internet/websocket"
)

// muxDefault, tcpKeepAliveDefault, and fwmarkDefault are these three flags'
// registered defaults, named so the values aren't repeated as magic
// numbers at the flag registration and (for mux) in doc comments elsewhere
// that reference "the default".
const (
	muxDefault          = 1
	tcpKeepAliveDefault = 15
	fwmarkDefault       = 0
)

// allowedEchModes is the single source of truth for the `ech` option's
// vocabulary, referenced both by parseOptsIntoFlags' parse-time validation
// (main.go, reachable from SS_PLUGIN_OPTIONS) and by buildTLSConfig's own
// switch below (reachable from a raw `-ech=` CLI flag, which bypasses
// parseOptsIntoFlags entirely) -- keeping one list means a future mode
// addition can't update one check and silently miss the other.
var allowedEchModes = []string{"auto", "always", "never"}

var (
	vpn          = flag.Bool("V", false, "Run in VPN mode.")
	fastOpen     = flag.Bool("fast-open", false, "Enable TCP fast open.")
	localAddr    = flag.String("localAddr", "127.0.0.1", "local address to listen on.")
	localPort    = flag.String("localPort", "1984", "local port to listen on.")
	remoteAddr   = flag.String("remoteAddr", "127.0.0.1", "remote address to forward.")
	remotePort   = flag.String("remotePort", "1080", "remote port to forward.")
	path         = flag.String("path", "/", "URL path for websocket.")
	host         = flag.String("host", "cloudfront.com", "Hostname for server.")
	tlsEnabled   = flag.Bool("tls", false, "Enable TLS.")
	cert         = flag.String("cert", "", "Path to TLS certificate file. Overrides certRaw. Default: ~/.acme.sh/{host}/fullchain.cer")
	certRaw      = flag.String("certRaw", "", "Raw TLS certificate content. Intended only for Android.")
	key          = flag.String("key", "", "(server) Path to TLS key file. Default: ~/.acme.sh/{host}/{host}.key")
	mode         = flag.String("mode", "websocket", "Transport mode: websocket, quic (enforced tls).")
	mux          = flag.Int("mux", muxDefault, "Concurrent multiplexed connections (websocket client mode only).")
	server       = flag.Bool("server", false, "Run in server mode")
	logLevel     = flag.String("loglevel", "", "loglevel for v2ray: debug, info, warning (default), error, none.")
	version      = flag.Bool("version", false, "Show current version of ex-ray")
	fwmark       = flag.Int("fwmark", fwmarkDefault, "Set SO_MARK option for outbound sockets.")
	echMode      = flag.String("ech", "auto", "ECH (Encrypted Client Hello) mode: auto (opportunistic), always (fail-closed), never.")
	echDoh       = flag.String("ech-doh", "", "DoH URL used to fetch the ECH config (HTTPS record). Empty disables ECH.")
	tcpKeepAlive = flag.Int("tcp-keepalive", tcpKeepAliveDefault, "Seconds an idle outbound connection waits before TCP keepalive probes start. Three probes at the same spacing follow, so a black-holed idle connection is dropped after about four times this value. 0 disables keepalive entirely, including Go's own default.")
)

// redactedError wraps cause for errors.Is/errors.As chaining while keeping
// Error() text limited to msg -- used where cause's own Error() text may
// embed operator-supplied content (e.g. a cert/key path built from
// SS_PLUGIN_OPTIONS) that must never reach the sitrep. v2ray-core's own
// Error.Base() couples Unwrap() to an Error() that unconditionally appends
// the wrapped error's text, so it cannot express "chainable but redacted"
// -- this type can.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

// homeDir resolves the operator's home directory, used only to build the
// default ~/.acme.sh cert/key paths when the server-mode operator gave
// neither. Returns an error rather than exiting directly, so a failure here
// reaches main() through the same buildTLSConfig -> generateConfig ->
// buildV2Ray -> failFatal path as every other config-class error in this
// file -- a `fatal` sitrep with exit 23, not a bare stderr line and exit 1
// that breaks the sitrep's hello-then-exactly-one-terminal-event contract.
func homeDir() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", newError("failed to determine home directory").Base(err)
	}
	return usr.HomeDir, nil
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

// logConfig builds the v2ray-core log config for the operator-chosen
// level. An unrecognized value is fatal rather than silently resolving to
// the Warning default -- the empty string ("" -- no loglevel option given)
// and the explicit "warning" spelling are the two ways to ask for that
// default; anything else that doesn't match a known level is an error, not
// a guess.
func logConfig(logLevel string) (*vlog.Config, error) {
	config := &vlog.Config{
		Error:  &vlog.LogSpecification{Type: vlog.LogType_Console, Level: clog.Severity_Warning},
		Access: &vlog.LogSpecification{Type: vlog.LogType_Console},
	}
	switch strings.ToLower(logLevel) {
	case "", "warning":
		// Already the default set above.
	case "debug":
		config.Error.Level = clog.Severity_Debug
	case "info":
		config.Error.Level = clog.Severity_Info
	case "error":
		config.Error.Level = clog.Severity_Error
	case "none":
		config.Error.Type = vlog.LogType_None
		config.Access.Type = vlog.LogType_None
	default:
		return nil, newError("invalid loglevel: value is not recognized")
	}
	return config, nil
}

func parseLocalAddr(localAddr string) []string {
	return strings.Split(localAddr, "|")
}

// validPort parses and range-checks a SIP003 port string, the single
// source of truth both main()'s early port-0 guard and generateConfig's
// own localPort/remotePort validation route through -- two independently
// written parsers is exactly the kind of drift that can silently
// reintroduce a port-0/mis-report bug: strconv.Atoi alone accepts syntax
// (e.g. a leading "+") that net.PortFromString (built on
// strconv.ParseUint) rejects.
func validPort(s string) (net.Port, error) {
	return net.PortFromString(s)
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
	return 0, newError("invalid", name, "(expected 0..4294967295)")
}

const (
	// keepAliveProbeCount is fixed rather than configurable: the option's one
	// number is the idle time, and the probe count is what turns it into the
	// documented detection bound.
	keepAliveProbeCount = 3
	// keepAliveMaxSeconds is the range Linux accepts for TCP_KEEPIDLE and
	// TCP_KEEPINTVL. Rejecting above it turns an operator typo into a startup
	// config error rather than a swallowed EINVAL on the first dial.
	keepAliveMaxSeconds = 32767
)

// tcpKeepAliveParams validates the tcp-keepalive option and expands it into the
// socket timings. Pure, so generateConfig can call it freely. The bound guard
// wrapping the conversion is gosec G115's recognized mitigation, as in uint32Opt.
func tcpKeepAliveParams() (keepAliveParams, error) {
	v := *tcpKeepAlive
	if v < 0 || v > keepAliveMaxSeconds {
		return keepAliveParams{}, newError("invalid tcp-keepalive (expected 0..", keepAliveMaxSeconds, ")")
	}
	idle := int32(v)
	if idle == 0 {
		return keepAliveParams{}, nil
	}
	return keepAliveParams{IdleSeconds: idle, IntervalSeconds: idle, Probes: keepAliveProbeCount}, nil
}

// registerTCPKeepAlive must run exactly once, before core.New: it mutates
// process-global state, and generateConfig deliberately does not call it
// because RegisterDialerController appends and the tests call generateConfig
// repeatedly.
//
// Server mode is skipped: ex-ray's outbound there dials loopback to ss-server,
// and a listener is unreachable from a dialer controller anyway.
func registerTCPKeepAlive() error {
	if *server {
		return nil
	}
	params, err := tcpKeepAliveParams()
	if err != nil {
		return err
	}
	ctl := keepAliveDialerController(params)
	if ctl == nil {
		return nil
	}
	return internet.RegisterDialerController(ctl)
}

// buildTLSConfig assembles the v2ray tls.Config: SNI stays *host, ECH is armed
// by Ech_DOHserver (ech != "never" with a non-empty ech-doh), and ech=always
// also sets RequireEch so v2ray aborts the dial rather than leak a cleartext SNI
// when the ECH config can't be obtained.
//
// ech=always with an empty ech-doh is a configuration error (mirrors main.go's
// exit-23 contract): "always" promises fail-closed ECH, impossible without a
// DoH source.
func buildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{ServerName: *host}

	if *server {
		certificate := tls.Certificate{}
		if *cert == "" && *certRaw == "" {
			home, err := homeDir()
			if err != nil {
				return nil, err
			}
			*cert = fmt.Sprintf("%s/.acme.sh/%s/fullchain.cer", home, *host)
			logWarn("No TLS cert specified, trying", *cert)
		}
		var err error
		certificate.Certificate, err = readCertificate()
		if err != nil {
			logWarn("failed to read cert:", err)
			return nil, &redactedError{msg: "failed to read cert", cause: err}
		}
		if *key == "" {
			home, err := homeDir()
			if err != nil {
				return nil, err
			}
			*key = fmt.Sprintf("%[1]s/.acme.sh/%[2]s/%[2]s.key", home, *host)
			logWarn("No TLS key specified, trying", *key)
		}
		certificate.Key, err = filesystem.ReadFile(*key)
		if err != nil {
			logWarn("failed to read key file:", err)
			return nil, &redactedError{msg: "failed to read key file", cause: err}
		}
		tlsConfig.Certificate = []*tls.Certificate{&certificate}
	} else if *cert != "" || *certRaw != "" {
		certificate := tls.Certificate{Usage: tls.Certificate_AUTHORITY_VERIFY}
		var err error
		certificate.Certificate, err = readCertificate()
		if err != nil {
			logWarn("failed to read cert:", err)
			return nil, &redactedError{msg: "failed to read cert", cause: err}
		}
		tlsConfig.Certificate = []*tls.Certificate{&certificate}
	}

	if !slices.Contains(allowedEchModes, *echMode) {
		return nil, newError(fmt.Sprintf("invalid ech mode (expected one of %s)", strings.Join(allowedEchModes, ", ")))
	}
	switch *echMode {
	case "never":
		// no-op; never touch ECH regardless of ech-doh.
	case "auto", "always":
		if *echDoh != "" {
			tlsConfig.Ech_DOHserver = *echDoh
			if *echMode == "always" {
				tlsConfig.RequireEch = true
			}
		} else if *echMode == "always" {
			return nil, newError("ech=always requires ech-doh to be set; refusing to start without a DoH source for fail-closed ECH")
		}
	default:
		// Unreachable given the slices.Contains guard above: every value in
		// allowedEchModes must have a case here, or a future entry added to
		// the list without a matching case would silently apply no ECH
		// config at all instead of failing loudly -- exactly the class of
		// bug this file otherwise fails loud on.
		panic(fmt.Sprintf("unreachable: echMode %q passed the allowedEchModes guard but has no switch case", *echMode))
	}

	return tlsConfig, nil
}

// chrome_auto tracks the newest Chrome the vendored uTLS knows and is
// ECH-capable, so SNI concealment composes with the mimicked fingerprint.
const defaultFingerprint = "chrome_auto"

// securitySettings returns the stream's security proto message. A client
// websocket dial wraps the tls.Config in the uTLS engine; server listeners and
// quic keep the bare tls.Config — a server sends no ClientHello, and quic
// hard-requires a *tls.Config (it manages its own TLS+ECH).
func securitySettings(tlsConfig *tls.Config) proto.Message {
	if !*server && *mode == "websocket" {
		return &utls.Config{
			TlsConfig: tlsConfig,
			Imitate:   defaultFingerprint,
			ForceAlpn: utls.ForcedALPN_TRANSPORT_PREFERENCE_TAKE_PRIORITY,
		}
	}
	return tlsConfig
}

func generateConfig() (*core.Config, error) {
	lport, err := validPort(*localPort)
	if err != nil {
		return nil, newError("invalid localPort: not a valid port")
	}
	rport, err := validPort(*remotePort)
	if err != nil {
		return nil, newError("invalid remotePort: not a valid port")
	}
	// remotePort==0 parses as in-range (validPort allows 0..65535) but the
	// vendored freedom outbound only applies its destination-port override
	// `if server.Port != 0` -- a remotePort=0 silently drops the override
	// entirely, falling back to dokodemo's unset (zero) port, and nothing
	// downstream rejects a zero Destination.Port. Reject it explicitly,
	// the same way localPort's port-0 is rejected in main().
	if rport == 0 {
		return nil, newError("invalid remotePort: must not be 0")
	}
	// An empty remoteAddr parses as a zero-length domain address that
	// core.New/Start both accept without complaint -- ex-ray binds and
	// reports ready, then every dial to the upstream fails. net.AnyIP
	// (0.0.0.0) is the same failure shape one level down: freedom's own
	// isValidAddress rejects it too, so the destination-address override
	// is silently discarded and traffic is redirected to dokodemo's
	// net.LocalHostIP fallback instead of the intended upstream -- worse
	// than the empty case, since it's a wrong destination that succeeds
	// rather than one that just fails every dial.
	remoteAddress := net.ParseAddress(*remoteAddr)
	if *remoteAddr == "" || remoteAddress == net.AnyIP {
		return nil, newError("invalid remoteAddr: must not be empty or the unspecified address")
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
				Address: net.NewIPOrDomain(remoteAddress),
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
		return nil, newError("unsupported mode (expected websocket or quic)")
	}

	// ech is validated here (not earlier): quic sets *tlsEnabled = true as
	// a side effect of the mode switch just above, and this check must
	// see that. Not only inside buildTLSConfig (which runs only when
	// *tlsEnabled below) either: a valid-vocabulary ech=always without
	// tls set would otherwise silently apply nothing -- the operator
	// asked for fail-closed SNI concealment and gets a fully plaintext
	// transport instead, with no diagnostic. "auto"/"never" make no such
	// promise -- opportunistic ECH with no TLS at all is simply a no-op,
	// not a broken guarantee, so only "always" is checked here.
	if !slices.Contains(allowedEchModes, *echMode) {
		return nil, newError(fmt.Sprintf("invalid ech mode (expected one of %s)", strings.Join(allowedEchModes, ", ")))
	}
	if *echMode == "always" && !*tlsEnabled {
		return nil, newError("ech=always requires tls to be enabled")
	}

	streamConfig := internet.StreamConfig{
		ProtocolName: *mode,
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: *mode,
			Settings:     serial.ToTypedMessage(transportSettings),
		}},
	}
	keepAlive, err := tcpKeepAliveParams()
	if err != nil {
		return nil, err
	}
	// Client mode only -- server-mode streamConfig lands on the inbound, which
	// would strip Go's keepalive from every accepted connection.
	keepAliveWanted := !*server
	if *fastOpen || *fwmark != 0 || keepAliveWanted {
		socketConfig := &internet.SocketConfig{}
		if *fastOpen {
			socketConfig.Tfo = internet.SocketConfig_Enable
		}
		if *fwmark != 0 {
			socketConfig.Mark = fwmarkU32
		}
		if keepAliveWanted {
			if keepAlive.enabled() {
				socketConfig.TcpKeepAliveIdle = keepAlive.IdleSeconds
				socketConfig.TcpKeepAliveInterval = keepAlive.IntervalSeconds
			} else {
				// tcp-keepalive=0: a negative idle is the sentinel that
				// suppresses Go's own keepalive too (see README for why).
				socketConfig.TcpKeepAliveIdle = -1
			}
		}

		streamConfig.SocketSettings = socketConfig
	}
	if *tlsEnabled {
		tlsConfig, err := buildTLSConfig()
		if err != nil {
			return nil, err
		}
		sec := securitySettings(tlsConfig)
		streamConfig.SecurityType = serial.GetMessageType(sec)
		streamConfig.SecuritySettings = []*anypb.Any{serial.ToTypedMessage(sec)}
	}

	logCfg, err := logConfig(*logLevel)
	if err != nil {
		return nil, err
	}
	apps := []*anypb.Any{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(logCfg),
	}

	if *server {
		proxyAddress := net.LocalHostIP
		if connectionReuse {
			// This address is required when mux is used on client.
			// dokodemo is not aware of mux connections by itself.
			proxyAddress = net.ParseAddress("v1.mux.cool")
		}
		// Exactly one inbound: main()'s localAddr guard already rejects
		// any *localAddr that parseLocalAddr would split into more than
		// one address (the sitrep's `ready` event can only report one
		// `listen`, so a multi-address bind could never be honestly
		// reported as ready in the first place -- see main.go).
		return &core.Config{
			Inbound: []*core.InboundHandlerConfig{{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortRange:      net.SinglePortRange(lport),
					Listen:         net.NewIPOrDomain(net.ParseAddress(*localAddr)),
					StreamSettings: &streamConfig,
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					Address:  net.NewIPOrDomain(proxyAddress),
					Networks: []net.Network{net.Network_TCP},
				}),
			}},
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
