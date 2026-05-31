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
// startV2Ray so main() can compute the listen address and run the confirming
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

	// quic mode binds a UDP-based wire listener, not TCP. ex-ray's TCP
	// confirming-probe + transports=["tcp"] would be a lie for quic, so v1
	// refuses it explicitly rather than mis-probing. Hole only ever uses the
	// default websocket transport; ex-ray-as-standalone-server with quic is a
	// documented v1 gap. (A correct quic path would UDP-probe and report
	// ["udp"], but only once we are certain the quic inbound binds exactly that
	// UDP addr — until then the honest signal is a typed fatal.)
	if *mode == "quic" {
		emitFatal("quic mode not supported by ex-ray v1", nil)
		os.Exit(23)
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
	// `listen` reports the REQUESTED address (*localAddr:*localPort), not a
	// port v2ray-core re-queried after bind. SITREP's `ready` contract asks
	// for the authoritative BOUND address to enable the OS-assigned-port
	// (bind-`:0`) pattern, but v2ray-core's core.New/Start exposes no API to
	// read back the dokodemo inbound's actual bound port, and the
	// confirming-probe binds-and-releases a DIFFERENT ephemeral socket. The
	// Hole/garter handoff always passes a concrete pre-allocated non-zero port
	// (garter::chain::allocate_one_port), so requested == bound and this is
	// authoritative in practice. A caller that passes SS_LOCAL_PORT=0 would
	// get `:0` echoed back — an unsupported v1 gap, not a silent mis-report
	// for any real Hole path. Closing the gap needs v2ray-core listener
	// introspection (out of scope for the sitrep wiring task).
	emitReady(localListenAddr, []string{"tcp"})

	<-osSignals
}
