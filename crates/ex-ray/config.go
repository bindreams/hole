package main

import (
	gotls "crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"math"
	"os/user"
	"runtime"
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

// muxDefault, tcpKeepAliveDefault and fwmarkDefault are the registered defaults of
// the mux, tcp-keepalive and fwmark flags.
const (
	muxDefault          = 1
	tcpKeepAliveDefault = 15
	fwmarkDefault       = 0
)

// allowedEchModes lists the values of the `ech` option. parseOptsIntoFlags
// (options from SS_PLUGIN_OPTIONS) and generateConfig (which also sees a raw
// `-ech=` flag) both validate against it.
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
	mux          = flag.Int("mux", muxDefault, "Concurrent multiplexed connections (websocket mode only); 0 disables Mux.Cool. Client and server must agree on whether it is on.")
	server       = flag.Bool("server", false, "Run in server mode")
	logLevel     = flag.String("loglevel", "", "loglevel for v2ray: debug, info, warning (default), error, none.")
	version      = flag.Bool("version", false, "Show current version of ex-ray")
	fwmark       = flag.Int("fwmark", fwmarkDefault, "Set SO_MARK option for outbound sockets.")
	echMode      = flag.String("ech", "auto", "ECH (Encrypted Client Hello) mode: auto (opportunistic), always (fail-closed), never.")
	echDoh       = flag.String("ech-doh", "", "DoH URL used to fetch the ECH config (HTTPS record). Empty disables ECH.")
	tcpKeepAlive = flag.Int("tcp-keepalive", tcpKeepAliveDefault, "Seconds an idle outbound connection waits before TCP keepalive probes start. Three probes at the same spacing follow, so a black-holed idle connection is dropped after about four times this value. 0 disables keepalive entirely, including Go's own default.")
)

// redactedError wraps cause so errors.Is and errors.As see through to it, while
// Error() returns only msg. It is for errors whose cause text may embed
// operator-supplied content (such as a cert or key path from SS_PLUGIN_OPTIONS)
// that must not reach the sitrep. v2ray-core's Error.Base cannot do this: its
// Error() always appends the wrapped error's text.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

// homeDir returns the current user's home directory, for the default
// ~/.acme.sh cert and key paths. It returns an error instead of exiting so the
// failure reaches main as a `fatal` sitrep (exit 23), keeping the sitrep's
// hello-then-exactly-one-terminal-event contract.
func homeDir() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", newError("failed to determine home directory").Base(err)
	}
	return usr.HomeDir, nil
}

// readCertificate returns the PEM certificate named by *cert, else the one in
// *certRaw (the body without the BEGIN/END lines, which it adds). One of the
// two must be non-empty.
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

// logConfig builds the v2ray-core log config for logLevel (debug, info,
// warning, error or none, case-insensitive). Empty means the default,
// warning. Any other value is an error, never a silent fallback to the default.
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

// parseLocalAddr splits a localAddr value on `|` into its listen addresses.
func parseLocalAddr(localAddr string) []string {
	return strings.Split(localAddr, "|")
}

// canonicalLocalAddr validates s as a single IP literal and returns v2ray-core's
// canonical string for it, the address v2ray-core will bind. It is the one
// definition shared by main's pre-bind guard and generateConfig. The canonical
// form can differ from the input: an IPv4-mapped IPv6 literal
// ("::ffff:127.0.0.1") is folded to plain IPv4 ("127.0.0.1"). ok is false when s
// is a `|`-joined list or resolves to a domain.
func canonicalLocalAddr(s string) (canonical string, ok bool) {
	addrs := parseLocalAddr(s)
	if len(addrs) != 1 {
		return "", false
	}
	addr := net.ParseAddress(addrs[0])
	if !addr.Family().IsIP() {
		return "", false
	}
	return addr.IP().String(), true
}

// validPort parses a port string, 0 included. It is the one parser shared by
// main's port-0 guard and generateConfig, so both accept exactly the same
// spellings (net.PortFromString rejects some, like a leading "+", that
// strconv.Atoi accepts).
func validPort(s string) (net.Port, error) {
	return net.PortFromString(s)
}

// uint32Opt converts an integer option to uint32, returning an error that
// names the option if v is out of range instead of letting it wrap. The bound
// guard is what gosec G115 recognizes, so the conversion needs no //nolint.
func uint32Opt(name string, v int) (uint32, error) {
	if v >= 0 && v <= math.MaxUint32 {
		return uint32(v), nil
	}
	// newError joins its arguments with no separator, so this is one pre-formatted
	// string.
	return 0, newError(fmt.Sprintf("invalid %s (expected 0..4294967295)", name))
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

// registerTCPKeepAlive installs the dialer controller that applies the
// tcp-keepalive option to outbound sockets. It must run exactly once, before
// core.New: it mutates process-global state, and generateConfig deliberately
// does not call it because RegisterDialerController appends and the tests call
// generateConfig repeatedly.
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

// buildTLSConfig assembles the v2ray tls.Config. SNI stays *host. ECH is armed by
// Ech_DOHserver (ech is not "never" and ech-doh is set), and ech=always also sets
// RequireEch so v2ray aborts the dial rather than leak a cleartext SNI when no
// ECH config can be obtained.
//
// ech=always with an empty ech-doh is a configuration error: "always" promises
// fail-closed ECH, impossible without a DoH source.
//
// Server mode reads the certificate and key (defaulting to ~/.acme.sh/{host}/).
// A client reads a certificate only to pin it as the trusted CA. Both are
// checked to parse. Read errors carry no path (see redactedError).
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
		// v2ray-core drops an unparseable pair with only a warning, leaving no
		// certificate configured, so check it here. X509KeyPair is the parse the TLS
		// stack itself performs.
		if _, err := gotls.X509KeyPair(certificate.Certificate, certificate.Key); err != nil {
			logWarn("cert and key are not a valid X509 key pair:", err)
			return nil, &redactedError{msg: "cert and key are not a valid X509 key pair", cause: err}
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
		// v2ray-core's GetTLSConfig only logs a PEM that fails to parse and then falls
		// back to the system root pool instead of the pinned CA, so check it here.
		if !x509.NewCertPool().AppendCertsFromPEM(certificate.Certificate) {
			logWarn("cert is not a valid PEM certificate")
			return nil, newError("cert is not a valid PEM certificate")
		}
		tlsConfig.Certificate = []*tls.Certificate{&certificate}
		// Windows only: config_windows.go's getCertPool returns a nil pool unless
		// DisableSystemRoot is set, so without this the pin is ignored and any
		// OS-trusted CA satisfies verification. Other platforms append the cert to the
		// system pool (config_other.go) and keep trusting the system roots.
		if runtime.GOOS == "windows" {
			tlsConfig.DisableSystemRoot = true
		}
	}

	// generateConfig runs this check too; it is repeated because tests call
	// buildTLSConfig directly.
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
		// Unreachable given the guard above: a mode added to allowedEchModes without
		// a case here must fail loudly, not apply no ECH config.
		panic(fmt.Sprintf("unreachable: echMode %q passed the allowedEchModes guard but has no switch case", *echMode))
	}

	return tlsConfig, nil
}

// defaultFingerprint is the uTLS fingerprint a client websocket dial mimics.
// chrome_auto tracks the newest Chrome the vendored uTLS knows and is
// ECH-capable, so SNI concealment composes with it.
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

// generateConfig builds the v2ray-core config from the flags. Client mode
// listens on localAddr:localPort as plain TCP and sends the traffic to
// remoteAddr:remotePort over the websocket or quic transport; server mode
// listens on localAddr:localPort over that transport and forwards to
// remoteAddr:remotePort.
//
// It validates for itself, whatever main has already checked, because tests call
// it directly: the local and remote ports and addresses, mux, fwmark, mode, ech
// and the tls it needs, cert, certRaw and key against tls, tcp-keepalive and
// loglevel. host, path, fastOpen and ech-doh get no check here: only
// parseOptsIntoFlags guards an empty host or path, and ech-doh's form is checked
// there too (parseURLOption). Error text never contains an option value.
func generateConfig() (*core.Config, error) {
	lport, err := validPort(*localPort)
	if err != nil {
		return nil, newError("invalid localPort: not a valid port")
	}
	// Port 0 would bind an OS-assigned port that v2ray-core does not report (see main).
	if lport == 0 {
		return nil, newError("invalid localPort: must not be 0")
	}
	// Rejects a `|`-joined list and any hostname: ParseAddress would take either
	// as one domain address.
	if _, ok := canonicalLocalAddr(*localAddr); !ok {
		return nil, newError("invalid localAddr: must be a single IP literal")
	}
	rport, err := validPort(*remotePort)
	if err != nil {
		return nil, newError("invalid remotePort: not a valid port")
	}
	// freedom applies its destination-port override only `if server.Port != 0`, so
	// port 0 would silently forward to a zero port.
	if rport == 0 {
		return nil, newError("invalid remotePort: must not be 0")
	}
	// An empty or whitespace-only remoteAddr parses as an empty domain that
	// core.New accepts, after which every dial to the upstream fails. The
	// unspecified address is also rejected: freedom discards a 0.0.0.0 override and
	// falls back to dokodemo's localhost destination (a wrong destination that
	// succeeds), and for :: every dial fails. The check reads the parsed address,
	// so a value ParseAddress trims to empty is caught, and calls IP() only on an
	// IP family because a domain address panics.
	remoteAddress := net.ParseAddress(*remoteAddr)
	family := remoteAddress.Family()
	if (family.IsDomain() && remoteAddress.Domain() == "") || (family.IsIP() && remoteAddress.IP().IsUnspecified()) {
		return nil, newError("invalid remoteAddr: must not be empty or the unspecified address")
	}
	// Validated before the server/client split so both modes reject the same
	// values; this also dominates the casts below for gosec G115.
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

	// Checked after the mode switch, because quic sets *tlsEnabled. ech=always
	// without tls would otherwise apply nothing and silently give a plaintext
	// transport; auto and never make no such promise, so only always is checked.
	if !slices.Contains(allowedEchModes, *echMode) {
		return nil, newError(fmt.Sprintf("invalid ech mode (expected one of %s)", strings.Join(allowedEchModes, ", ")))
	}
	if *echMode == "always" && !*tlsEnabled {
		return nil, newError("ech=always requires tls to be enabled")
	}
	// Without tls, buildTLSConfig does not run, so a cert, certRaw or key would be
	// silently ignored and ex-ray would report ready on a plaintext transport.
	if !*tlsEnabled && (*cert != "" || *certRaw != "" || *key != "") {
		return nil, newError("cert/certRaw/key require tls to be enabled")
	}
	// A client-mode `key` is not rejected, unlike a cert without tls: it is read
	// only in server mode, and real client options carry an unused `key=<path>`
	// beside `cert=<path>` (crates/bridge/src/test_support/skuld_fixtures.rs builds
	// its ws_tls and quic client fixtures that way).

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
				// tcp-keepalive=0: an idle of 0 would leave Go's own default keepalive
				// in place, so a negative idle is the sentinel that suppresses it too.
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
		// Exactly one inbound: main rejects a `|`-joined localAddr, since `ready`
		// reports one listen address.
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
