// Command ex-ray is a first-party SIP003 shadowsocks plugin built on
// v2ray-core. It is wire-compatible with shadowsocks/v2ray-plugin servers
// and clients; see README.md for the design rationale.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	core "github.com/v2fly/v2ray-core/v5"
)

var VERSION = "ex-ray"

// parseIntOption reads a SIP003 option value from opts and applies it to
// dest, sharing one implementation across mux/tcp-keepalive/fwmark so the
// three can never silently drift apart.
//
// The rule: an empty value means "not specified" and leaves dest alone; a
// non-empty value that fails to parse is fatal. Concretely, both an absent
// key and an explicitly empty value ("key=") are a no-op, leaving dest at
// whatever it already held: dest holds whatever flag.Parse left there --
// main() calls flag.Parse() before parseOptsIntoFlags runs -- the
// registered default when no CLI flag was passed, or the CLI-supplied
// value when one was, deliberately preserved either way, not overwritten.
// A BARE key (no `=` at all) is different: args.go's parser maps it to the
// literal string "1" for every option uniformly, so it goes through the
// same Atoi path as an explicit `=1` and sets dest to 1 -- not "the
// default" for tcp-keepalive/fwmark, whose defaults are 15/0 (see
// TestParseOptsIntoFlagsBareKeyResolvesToLiteralOne; fixing this needs
// args.go's Args type to distinguish a bare key from an explicit "=1", a
// grammar change not attempted here). A non-empty, non-numeric value
// is fatal and never echoes the rejected value: the escaping grammar lets
// a backslash absorb a later segment into a value, so an unparseable
// mux=abc\;certRaw=SECRET could otherwise leak certRaw's value through the
// mux error.
func parseIntOption(opts Args, key string, dest *int) error {
	c, ok := opts.Get(key)
	if !ok || c == "" {
		return nil
	}
	i, err := strconv.Atoi(c)
	if err != nil {
		return newError(fmt.Sprintf("invalid %s: value is not an integer", key))
	}
	*dest = i
	return nil
}

// parseBoolOption reads a SIP003 presence option value from opts and
// applies it to dest. Unlike parseIntOption/parseEnumOption, an explicitly
// empty value ("key=") is NOT a no-op here -- only an absent key is. A bare
// key (no `=` at all) or an explicit "key=1" (args.go maps a bare key to
// the literal "1") is the only spelling that enables the flag; any other
// present value, empty included, is unrecognized and fatal. Inventing a
// wider vocabulary ("true"/"yes"/"on" as a heuristic) is exactly the kind
// of threshold that has no principled stopping point.
//
// The empty-value carve-out matters here specifically because these are
// presence-only options: garter's Mode::from_plugin_options mirrors
// ex-ray's OLD behavior for `server` -- presence of the key, regardless of
// value, means server mode (crates/garter/src/chain_tests.rs). Treating
// `server=` as a no-op would leave *server false while garter still
// swapped the chain's SS_LOCAL/SS_REMOTE env vars for server mode,
// producing exactly the kind of silently-broken-but-reports-ready config
// this whole change exists to prevent -- and fixing that properly needs a
// garter-side change, out of scope here. Rejecting `key=` outright avoids
// the disagreement without touching garter: ex-ray simply refuses to
// start.
//
// Never echoes the rejected value for the same reason parseIntOption
// doesn't.
func parseBoolOption(opts Args, key string, dest *bool) error {
	c, ok := opts.Get(key)
	if !ok {
		return nil
	}
	if c != "1" {
		return newError(fmt.Sprintf("invalid %s: value is not recognized", key))
	}
	*dest = true
	return nil
}

// parseEnumOption reads a SIP003 option value from opts and applies it to
// dest if it matches one of allowed, mirroring parseIntOption/
// parseBoolOption's structural rule: an absent key or an explicitly empty
// value is a no-op; a non-empty value outside allowed is fatal. The
// allowed list is safe to name in the error (it's a small static
// vocabulary, not operator input) but the rejected value itself never is,
// for the same reason as every other option in this file.
func parseEnumOption(opts Args, key string, allowed []string, dest *string) error {
	c, ok := opts.Get(key)
	if !ok || c == "" {
		return nil
	}
	for _, a := range allowed {
		if c == a {
			*dest = c
			return nil
		}
	}
	return newError(fmt.Sprintf("invalid %s: expected one of %s", key, strings.Join(allowed, ", ")))
}

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
		return newError("invalid SS_PLUGIN_OPTIONS").Base(err)
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
	if c, b := opts.Get("host"); b {
		*host = c
	}
	if c, b := opts.Get("path"); b {
		*path = c
	}
	if c, b := opts.Get("cert"); b {
		*cert = c
	}
	if c, b := opts.Get("certRaw"); b {
		*certRaw = c
	}
	if c, b := opts.Get("key"); b {
		*key = c
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
	if c, b := opts.Get("ech-doh"); b {
		*echDoh = c
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
	// inbound listener's bound port via any public API. Echoing ":0" as
	// `ready.listen` would be a silent spec violation (SITREP.md: listen MUST be
	// the bound address).
	// Hole always hands ex-ray a concrete pre-allocated port; a port-0 input
	// is a misconfiguration we fail loudly on rather than mis-report.
	if *localPort == "0" || *localPort == "" {
		emitFatal("ex-ray requires a concrete local port; port-0 OS-assignment is not supported (v2ray-core does not expose the bound port)", nil)
		os.Exit(23) // config-class error
	}

	// localAddr/localPort name the inbound listener in both modes (see
	// parseOptsIntoFlags for the client/server SS_*_* mapping). This is the
	// address v2ray-core binds and that emitReady reports.
	localListenAddr := net.JoinHostPort(*localAddr, *localPort)

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
	// is not allowed for listening: <value>"), so it must not reach the sitrep
	// the way every other fatal site in this file was fixed not to; the raw
	// error still reaches stderr via logFatal below.
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
