// Command ex-ray is a first-party SIP003 shadowsocks plugin built on
// v2ray-core. It is wire-compatible with shadowsocks/v2ray-plugin servers
// and clients; see README.md for the design rationale.
package main

import (
	"context"
	"errors"
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
// buildV2Ray so main() can compute the listen address and run the confirming
// probe BETWEEN the remap and core.New (the probe needs the resolved
// *localAddr:*localPort, the config needs the remap to have happened).
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

// confirmingProbe binds (and immediately releases) listenAddr on the given
// network ("tcp" or "udp") to confirm the address is bindable before core.New
// stands up the real listener. A failure here is the typed bind_conflict
// signal — the host can map the OS errno onto its own retry policy without
// scraping v2ray-core's log text. The network is chosen by listenerNetwork so
// the probe always matches the transport v2ray-core will actually bind.
func confirmingProbe(network, listenAddr string) error {
	var lc net.ListenConfig
	if network == "udp" {
		pc, err := lc.ListenPacket(context.Background(), "udp", listenAddr)
		if err != nil {
			return err
		}
		return pc.Close()
	}
	ln, err := lc.Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		return err
	}
	return ln.Close()
}

// listenerNetwork reports the IP transport of the inbound listener ex-ray
// binds, derived from the resolved mode/server flags. Only server+quic binds a
// UDP listener (the quic inbound faces the remote client); client mode (a plain
// TCP dokodemo inbound — quic, if configured, applies only to the upstream hop)
// and server+websocket are both TCP. The confirming-probe network AND the
// sitrep `transports` value both derive from this single function, so they can
// never disagree — that divergence (a UDP listener mis-reported as ["tcp"]) was
// the exact hazard the v1 quic rejection avoided by refusing quic outright. An
// unknown *mode returns "tcp" here and is then rejected by generateConfig's
// switch default before emitReady, so no false "ready" can escape. See
// bindreams/hole#421.
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
	// inbound listener's bound port via any public API (the confirming-probe
	// binds a separate ephemeral socket it releases, so it cannot reveal
	// v2ray-core's eventual bind). Echoing ":0" as `ready.listen` would be a
	// silent spec violation (SITREP.md: listen MUST be the bound address).
	// Hole always hands ex-ray a concrete pre-allocated port; a port-0 input
	// is a misconfiguration we fail loudly on rather than mis-report.
	if *localPort == "0" || *localPort == "" {
		emitFatal("ex-ray requires a concrete local port; port-0 OS-assignment is not supported (v2ray-core does not expose the bound port)", nil)
		os.Exit(23) // config-class error
	}

	// localAddr/localPort name the inbound listener in both modes (see
	// parseOptsIntoFlags for the client/server SS_*_* mapping). This is the
	// address the confirming-probe checks and that emitReady reports.
	localListenAddr := net.JoinHostPort(*localAddr, *localPort)

	// network is the transport the inbound listener binds (server+quic → "udp",
	// everything else → "tcp"). Both the probe below and emitReady use it, so a
	// quic server UDP-probes its UDP listener and reports transports=["udp"].
	network := listenerNetwork()

	if err := confirmingProbe(network, localListenAddr); err != nil {
		var se syscall.Errno
		if errors.As(err, &se) {
			emitBindConflict(int(se), localListenAddr)
		} else {
			emitBindConflict(0, localListenAddr)
		}
		logFatal("failed to bind", localListenAddr+":", err.Error())
		os.Exit(1)
	}

	server, err := buildV2Ray()
	if err != nil {
		emitFatal(err.Error(), nil)
		logFatal(err.Error())
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)

	if err := server.Start(); err != nil {
		emitFatal("start: "+err.Error(), nil)
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
	// listener is accepting once Start returns nil. The served transport is
	// `network` (server+quic → "udp", else "tcp"), the same value the
	// confirming-probe used above — so the sitrep can never mis-describe it.
	//
	// localListenAddr is authoritative: ex-ray rejects port 0 (above), so for
	// every accepted input the requested port == the bound port (v2ray-core
	// binds it; Start() returning nil confirms).
	emitReady(localListenAddr, []string{network})

	<-osSignals
}
