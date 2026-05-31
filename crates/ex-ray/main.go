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
// package-level flag pointers. It is split out of buildV2Ray so main() can run
// the confirming probe on the resolved *localAddr:*localPort BETWEEN the remap
// and core.New.
//
// localAddr/localPort always name the inbound listener bound by this process,
// in BOTH modes:
//   - client mode: localAddr/localPort come from SS_LOCAL_* (the SS client's
//     plugin-facing endpoint), remoteAddr/remotePort from SS_REMOTE_*.
//   - server mode: the SS server cross-assigns — localAddr/localPort take the
//     SS_REMOTE_* values (the public listen endpoint) and remoteAddr/remotePort
//     take SS_LOCAL_* (the ss-server loopback to forward into).
func parseOptsIntoFlags() {
	opts, err := parseEnv()
	if err != nil {
		// parseEnv only errors on a malformed SS_PLUGIN_OPTIONS string; with
		// no SS_* env set it returns empty opts and nil. Either way, leave the
		// flag defaults in place.
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

// confirmingProbe binds (and immediately releases) listenAddr to confirm the
// address is bindable before core.New stands up the real listener. A failure
// here is the typed bind_conflict signal — the host can map the OS errno onto
// its own retry policy without scraping v2ray-core's log text.
func confirmingProbe(listenAddr string) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", listenAddr)
	if err != nil {
		return err
	}
	return ln.Close()
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

	// quic mode binds a UDP wire listener; ex-ray's TCP confirming-probe and
	// transports=["tcp"] only describe TCP, so reject quic rather than
	// mis-report. Hole always uses the default websocket transport.
	if *mode == "quic" {
		emitFatal("quic mode not supported by ex-ray v1", nil)
		os.Exit(23)
	}

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

	if err := confirmingProbe(localListenAddr); err != nil {
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
	// listener is accepting once Start returns nil. quic was already fatal'd
	// out above, so the served transport is TCP (websocket/default).
	//
	// port 0 was rejected above, so the bound port equals the requested one.
	emitReady(localListenAddr, []string{"tcp"})

	<-osSignals
}
