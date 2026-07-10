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
	"syscall"

	core "github.com/v2fly/v2ray-core/v5"
)

var VERSION = "ex-ray"

// parseOptsIntoFlags reads SS_PLUGIN env vars and cross-assigns them into the
// package-level flag pointers. This is the env-remap seam: it is split out of
// buildV2Ray so main() can compute the listen address between the remap and
// core.New (the config needs the remap to have happened first).
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
func parseOptsIntoFlags() {
	opts, err := parseEnv()
	if err != nil {
		// parseEnv only errors on a malformed SS_PLUGIN_OPTIONS string; with
		// no SS_* env set it returns empty opts and nil. Either way, leave the
		// flag defaults in place (matches the prior behavior, which guarded the
		// whole remap block on `err == nil`).
		return
	}

	if c, b := opts.Get("mode"); b {
		*mode = c
	}
	if c, b := opts.Get("mux"); b {
		if i, err := strconv.Atoi(c); err == nil {
			*mux = i
		} else {
			logWarn("failed to parse mux, use default value")
		}
	}
	if _, b := opts.Get("tls"); b {
		*tlsEnabled = true
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
	if _, b := opts.Get("server"); b {
		*server = true
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

	if _, b := opts.Get("fastOpen"); b {
		*fastOpen = true
	}

	if _, b := opts.Get("__android_vpn"); b {
		*vpn = true
	}

	if c, b := opts.Get("fwmark"); b {
		if i, err := strconv.Atoi(c); err == nil {
			*fwmark = i
		} else {
			logWarn("failed to parse fwmark, use default value")
		}
	}

	if c, b := opts.Get("ech"); b {
		*echMode = c
	}
	if c, b := opts.Get("ech-doh"); b {
		*echDoh = c
	}

	if *vpn {
		registerControlFunc()
	}
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

	parseOptsIntoFlags()

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
		emitFatal(err.Error(), nil)
		logFatal(err.Error())
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)

	// A bind conflict here is retryable by the host (bind_ephemeral); any other
	// Start failure is fatal. localListenAddr is the authoritative bind address we
	// asked v2ray-core for (never empty); refine to the classifier's exact failed
	// endpoint only when it carries one, so the SITREP addr is never "" (an empty
	// addr fails the host's SocketAddr parse and drops the whole bind_conflict).
	if err := server.Start(); err != nil {
		if errno, addr, ok := classifyBindError(err); ok {
			if addr == "" {
				addr = localListenAddr
			}
			emitBindConflict(errno, addr)
		} else {
			emitFatal("start: "+err.Error(), nil)
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
