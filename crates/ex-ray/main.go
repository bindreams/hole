// Command ex-ray is a first-party SIP003 shadowsocks plugin built on
// v2ray-core. It is wire-compatible with shadowsocks/v2ray-plugin servers
// and clients; see README.md for the design rationale.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	core "github.com/v2fly/v2ray-core/v5"
)

var VERSION = "ex-ray"

// failFatal reports err as a `fatal` sitrep and exits with ex-ray's
// config-class-error code (23) -- distinct from other exit codes so a
// supervisor like systemd does not treat a bad config as a crash worth
// restarting.
func failFatal(err error) {
	emitFatal(err.Error(), nil)
	logFatal(err.Error())
	os.Exit(23) // config-class error
}

// parseOptsIntoFlags reads SS_PLUGIN env vars and cross-assigns them into the
// package-level flag pointers. This is the env-remap seam: it is split out of
// buildV2Ray so main() can compute the listen address between the remap and
// core.New (the config needs the remap to have happened first).
//
// A non-nil return is fatal: the caller must emit a `fatal` sitrep and exit
// non-zero rather than proceed with partially-remapped flags.
//
// localAddr/localPort always name the inbound listener bound by this process,
// in BOTH modes:
//   - client mode: localAddr/localPort come from SS_LOCAL_* (the SS client's
//     plugin-facing endpoint), remoteAddr/remotePort from SS_REMOTE_*.
//   - server mode: the SS server cross-assigns — localAddr/localPort take the
//     SS_REMOTE_* values (the public listen endpoint) and remoteAddr/remotePort
//     take SS_LOCAL_* (the ss-server loopback to forward into).
//
// The cross-assignment below mirrors that: under `*server`, a `localAddr`
// option lands in *remoteAddr and a `remoteAddr` option lands in *localAddr
// (likewise for ports).
func parseOptsIntoFlags() error {
	opts, err := parseEnv()
	if err != nil {
		// Unwrapped, not "invalid SS_PLUGIN_OPTIONS"-prefixed: parseEnv
		// returns two distinct fault classes (a malformed
		// SS_PLUGIN_OPTIONS string, or an incomplete SS_* chain-handoff
		// env, which SS_PLUGIN_OPTIONS may have nothing to do with), and
		// each already names itself accurately.
		return err
	}

	if err := rejectUnrecognizedKeys(opts); err != nil {
		return err
	}

	if c, b := opts.Get("mode"); b {
		*mode = c
	}
	if err := parseIntOption(opts, "mux", mux); err != nil {
		return err
	}
	if err := parseIntOption(opts, "tcp-keepalive", tcpKeepAlive); err != nil {
		return err
	}
	if err := parseBoolOption(opts, "tls", tlsEnabled); err != nil {
		return err
	}
	if err := parseStringOption(opts, "host", host, false); err != nil {
		return err
	}
	if err := parseStringOption(opts, "path", path, false); err != nil {
		return err
	}
	// cert/certRaw/key: empty is a documented, meaningful "use the
	// default" spelling (config.go falls back to ~/.acme.sh when both
	// are empty in server mode) -- not fatal, unlike host/path above.
	if err := parseStringOption(opts, "cert", cert, true); err != nil {
		return err
	}
	if err := parseStringOption(opts, "certRaw", certRaw, true); err != nil {
		return err
	}
	if err := parseStringOption(opts, "key", key, true); err != nil {
		return err
	}
	if c, b := opts.Get("loglevel"); b {
		*logLevel = c
	}
	if err := parseBoolOption(opts, "server", server); err != nil {
		return err
	}
	if c, b := opts.Get("localAddr"); b {
		if *server {
			*remoteAddr = c
		} else {
			*localAddr = c
		}
	}
	if c, b := opts.Get("localPort"); b {
		if *server {
			*remotePort = c
		} else {
			*localPort = c
		}
	}
	if c, b := opts.Get("remoteAddr"); b {
		if *server {
			*localAddr = c
		} else {
			*remoteAddr = c
		}
	}
	if c, b := opts.Get("remotePort"); b {
		if *server {
			*localPort = c
		} else {
			*remotePort = c
		}
	}

	if err := parseBoolOption(opts, "fastOpen", fastOpen); err != nil {
		return err
	}

	if err := parseBoolOption(opts, "__android_vpn", vpn); err != nil {
		return err
	}

	if err := parseIntOption(opts, "fwmark", fwmark); err != nil {
		return err
	}

	if err := parseEnumOption(opts, "ech", allowedEchModes, echMode); err != nil {
		return err
	}
	if err := parseURLOption(opts, "ech-doh", echDoh); err != nil {
		return err
	}

	if *vpn {
		registerControlFunc()
	}

	return nil
}

// buildV2Ray generates the v2ray-core config and constructs the instance. The
// env-remap (parseOptsIntoFlags) MUST have already run.
func buildV2Ray() (core.Server, error) {
	config, err := generateConfig()
	if err != nil {
		return nil, newError("failed to parse config").Base(err)
	}
	instance, err := core.New(config)
	if err != nil {
		return nil, newError("failed to create v2ray instance").Base(err)
	}
	return instance, nil
}

// listenerNetwork reports the IP transport of the inbound listener ex-ray
// binds, derived from the resolved mode/server flags. Only server+quic binds a
// UDP listener (the quic inbound faces the remote client); client mode (a plain
// TCP dokodemo inbound — quic, if configured, applies only to the upstream hop)
// and server+websocket are both TCP. emitReady reports this as the sitrep
// `transports`, mirroring the transport generateConfig selects from the same
// mode/server flags, so the reported transport can never disagree with the one
// v2ray-core binds. An unknown *mode returns "tcp" here and is then rejected by
// generateConfig's switch default before emitReady, so no false "ready" can
// escape. See bindreams/hole#421.
func listenerNetwork() string {
	if *server && *mode == "quic" {
		return "udp"
	}
	return "tcp"
}

func printCoreVersion() {
	version := core.VersionStatement()
	for _, s := range version {
		logInfo(s)
	}
}

func printVersion() {
	fmt.Println("ex-ray", VERSION)
	fmt.Println("Go version", runtime.Version())
	fmt.Println("Yet another SIP003 plugin for shadowsocks")
}

func main() {
	flag.Parse()

	if *version {
		// --version prints to stdout and exits before any sitrep emission, so
		// it is NOT part of the sitrep stream. Return early.
		printVersion()
		return
	}

	// hello MUST be the first sitrep line, and nothing else may touch stdout
	// before it on this path. logInit/printCoreVersion log to stderr.
	emitHello()

	logInit()
	printCoreVersion()

	if err := parseOptsIntoFlags(); err != nil {
		failFatal(err)
	}

	// Must precede core.New: app/proxyman/outbound reads the registered
	// controllers when it builds each handler's dialer.
	if err := registerTCPKeepAlive(); err != nil {
		failFatal(err)
	}

	// ex-ray requires a CONCRETE local port. It cannot honor the sitrep
	// port-0 / OS-assigned-port contract: v2ray-core does not expose the
	// inbound listener's bound port via any public API. Echoing a port-0
	// spelling as `ready.listen` would be a silent spec violation
	// (SITREP.md: listen MUST be the bound address).
	// Hole always hands ex-ray a concrete pre-allocated port; a port-0
	// input is a misconfiguration we fail loudly on rather than mis-report.
	// validPort (config.go) is the same parser generateConfig's own
	// localPort/remotePort validation uses -- a non-canonical spelling
	// ("00", "000") is also port 0 to it, which would otherwise bind an
	// OS-assigned ephemeral port while localListenAddr below -- built from
	// this same raw string -- still reported the original spelling, a
	// bound port that disagrees with what ready.listen claimed. A parse
	// failure or an out-of-range value is a different fault (not a port-0
	// request at all) and gets its own message so the detail doesn't
	// misdirect the operator at a port-0/OS-assignment problem they don't
	// have.
	localPortNum, portErr := validPort(*localPort)
	switch {
	case portErr != nil:
		failFatal(errors.New("invalid localPort: not a valid port"))
	case localPortNum == 0:
		failFatal(errors.New("ex-ray requires a concrete local port; port-0 OS-assignment is not supported (v2ray-core does not expose the bound port)"))
	}

	// localAddr must be exactly one IP literal. Two distinct failure modes
	// this closes:
	//   - Multiple addresses: parseLocalAddr (config.go) splits localAddr
	//     on `|` for a genuine multi-address server-mode listen, but the
	//     sitrep's `ready` event carries exactly one `listen` address
	//     (SITREP.md) -- there is no honest way to report a `|`-joined
	//     value there, and reporting it verbatim produces a string that
	//     fails garter's SocketAddr parse and is silently dropped as an
	//     unrecognized log line instead of being observed as ready.
	//   - A non-IP hostname: "localhost" is the one spelling v2ray-core's
	//     own listener silently rewrites to 127.0.0.1 (ListenTCP), so
	//     reporting the raw *localAddr verbatim would produce
	//     "localhost:<port>", the identical unparseable-SocketAddr
	//     failure as the multi-address case. Every other non-IP hostname
	//     already fails loudly via generateConfig's own "domain address
	//     is not allowed for listening" error; these two are the only
	//     silent gaps.
	if len(parseLocalAddr(*localAddr)) != 1 {
		failFatal(errors.New("invalid localAddr: a single listen address is required (the ready sitrep cannot report more than one)"))
	}
	// canonicalLocalAddr (config.go), not net.ParseIP directly: net.ParseIP
	// accepts spellings v2ray-core's own address type folds before binding
	// -- an IPv4-mapped IPv6 literal ("::ffff:127.0.0.1") parses fine and
	// would pass a bare net.ParseIP check, but v2ray-core binds it as plain
	// IPv4 ("127.0.0.1"). Reporting the raw, unfolded string as
	// ready.listen would disagree with the address actually bound; using
	// the canonical form for both the guard and localListenAddr below
	// means they can't drift apart.
	canonicalAddr, ok := canonicalLocalAddr(*localAddr)
	if !ok {
		failFatal(errors.New("invalid localAddr: must be an IP literal"))
	}

	// localAddr/localPort name the inbound listener in both modes (see
	// parseOptsIntoFlags for the client/server SS_*_* mapping). This is the
	// address v2ray-core binds and that emitReady reports.
	localListenAddr := net.JoinHostPort(canonicalAddr, *localPort)

	// network is the transport the inbound listener binds; emitReady reports it
	// as the sitrep transports.
	network := listenerNetwork()

	server, err := buildV2Ray()
	if err != nil {
		failFatal(err)
	}

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)

	// A bind conflict here is retryable by the host (bind_ephemeral); any other
	// Start failure is fatal. localListenAddr is the authoritative bind address we
	// asked v2ray-core for (never empty); refine to the classifier's exact failed
	// endpoint only when it carries one, so the SITREP addr is never "" (an empty
	// addr fails the host's SocketAddr parse and drops the whole bind_conflict).
	// bind_conflict's addr is meant to name the contended endpoint -- legitimate
	// diagnostic content, not an echo of a rejected value. The generic fatal
	// branch is different: v2ray-core's own Start error is unredacted internal
	// text that can embed *localAddr/*localPort verbatim (e.g. "domain address
	// is not allowed for listening: <value>"), so it must not reach the sitrep;
	// the raw error still reaches stderr via logFatal below.
	if err := server.Start(); err != nil {
		if errno, addr, ok := classifyBindError(err); ok {
			if addr == "" {
				addr = localListenAddr
			}
			emitBindConflict(errno, addr)
		} else {
			emitFatal("failed to start the v2ray-core inbound listener", nil)
		}
		logFatal("failed to start server:", err.Error())
		os.Exit(1)
	}

	defer func() {
		err := server.Close()
		if err != nil {
			logWarn(err.Error())
		}
	}()

	// v2ray-core's Start is synchronous through the listener bind, so the
	// listener is accepting once Start returns nil.
	//
	// localListenAddr is authoritative: ex-ray rejects port 0 (above), so for
	// every accepted input the requested port == the bound port (v2ray-core
	// binds it; Start() returning nil confirms).
	emitReady(localListenAddr, []string{network})

	<-osSignals
}
