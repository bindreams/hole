// Command ex-ray is a first-party SIP003 shadowsocks plugin built on
// v2ray-core. It is wire-compatible with shadowsocks/v2ray-plugin servers
// and clients; `ex-ray -h` and the flag definitions in config.go list its
// options, and third_party/VENDORING.md covers the vendored patches.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	core "github.com/v2fly/v2ray-core/v5"
)

// VERSION is the string `-version` prints. It is "ex-ray" unless a build
// overrides it with `-ldflags -X main.VERSION=...`.
var VERSION = "ex-ray"

// failFatal reports err as a `fatal` sitrep and exits with ex-ray's
// config-class-error code (23), distinct from other exit codes so a
// supervisor does not treat a bad config as a crash worth restarting.
//
// err.Error() becomes the sitrep `detail`, so it must not embed operator-supplied
// option values (see redactedError).
func failFatal(err error) {
	emitFatal(err.Error(), nil)
	logFatal(err.Error())
	os.Exit(23)
}

// parseOptsIntoFlags applies the SIP003 environment (SS_PLUGIN_OPTIONS and the
// SS_* address variables, via parseEnv) to the package-level flag pointers, on
// top of whatever flag.Parse left there. Run it before registerTCPKeepAlive and
// buildV2Ray, both of which read the flags.
//
// A non-nil return is fatal: the caller must emit a `fatal` sitrep and exit
// non-zero rather than proceed with partially-applied flags. Option values are
// never echoed in the error. The per-option rules are the shared block at the
// top of options.go and each parse*Option helper's doc.
//
// localAddr/localPort always name the inbound listener this process binds, in
// both modes:
//   - client mode: localAddr/localPort come from SS_LOCAL_* (the Shadowsocks
//     client's plugin-facing endpoint), remoteAddr/remotePort from SS_REMOTE_*.
//   - server mode: this function swaps the pairs. SIP003 passes a server-side
//     plugin its public endpoint in SS_REMOTE_* and the address of the server to
//     forward into in SS_LOCAL_*, so localAddr/localPort take the SS_REMOTE_*
//     values and remoteAddr/remotePort take SS_LOCAL_*.
//
// Under `*server` a `localAddr` option therefore lands in *remoteAddr and a
// `remoteAddr` option in *localAddr, likewise for ports.
func parseOptsIntoFlags() error {
	opts, err := parseEnv()
	if err != nil {
		// Returned as is: parseEnv's two fault classes (a malformed
		// SS_PLUGIN_OPTIONS, an incomplete SS_* set) each name themselves.
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
	// An empty cert/certRaw/key means "use the default" (server mode falls back to
	// ~/.acme.sh, see buildTLSConfig), so it is not fatal, unlike host/path above.
	if err := parseStringOption(opts, "cert", cert, true); err != nil {
		return err
	}
	if err := parseStringOption(opts, "certRaw", certRaw, true); err != nil {
		return err
	}
	if err := parseStringOption(opts, "key", key, true); err != nil {
		return err
	}
	// An empty loglevel is fatal like host/path: its default spelling is "warning"
	// or an absent key, and "loglevel=" would silently discard a CLI-set -loglevel.
	if err := parseStringOption(opts, "loglevel", logLevel, false); err != nil {
		return err
	}
	if err := parseBoolOption(opts, "server", server); err != nil {
		return err
	}
	// These four are assigned raw, with no parse*Option validation; the checks
	// on them are listenAddr (localAddr, localPort) and generateConfig (remoteAddr,
	// remotePort). A bare key (no `=`) reads as "1"
	// (see parsePluginOptions), so a bare `remoteAddr` sets the upstream
	// destination to the domain "1" and a bare `localPort` or `remotePort` sets
	// port 1; none of those checks rejects that.
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

// buildV2Ray generates the v2ray-core config and constructs the instance.
// parseOptsIntoFlags must have run first.
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

// listenerNetwork reports the transport of the inbound listener ex-ray binds,
// from the *server and *mode flags: "udp" for server+quic (the quic inbound faces
// the remote client), "tcp" for everything else. Client mode is TCP even with
// mode=quic, because quic then applies only to the upstream hop. main reports the
// result as the `transports` value of the `ready` sitrep. An unknown *mode
// returns "tcp" and is rejected by generateConfig before `ready` is emitted.
func listenerNetwork() string {
	if *server && *mode == "quic" {
		return "udp"
	}
	return "tcp"
}

// printCoreVersion logs v2ray-core's version statement to stderr.
func printCoreVersion() {
	version := core.VersionStatement()
	for _, s := range version {
		logInfo(s)
	}
}

// printVersion writes the `-version` banner to stdout.
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

	// hello must be the first sitrep line; nothing else may write to stdout before
	// it on this path. logInit and printCoreVersion log to stderr.
	emitHello()

	logInit()
	printCoreVersion()

	if err := parseOptsIntoFlags(); err != nil {
		failFatal(err)
	}

	// Must precede core.New: the vendored app/proxyman/outbound reads the registered
	// dialer controllers when it builds each handler's dialer.
	if err := registerTCPKeepAlive(); err != nil {
		failFatal(err)
	}

	// The address v2ray-core binds and that emitReady reports (see
	// parseOptsIntoFlags for the client/server mapping).
	localListenAddr, err := listenAddr()
	if err != nil {
		failFatal(err)
	}

	// The transport the inbound listener binds, reported as the sitrep transports.
	network := listenerNetwork()

	server, err := buildV2Ray()
	if err != nil {
		failFatal(err)
	}

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)

	// A bind conflict is retryable by the host; any other Start failure is fatal.
	// The bind_conflict addr is the failed endpoint the classifier reports, or
	// localListenAddr when it reports none, so it is never empty (a host cannot
	// parse an empty one). The generic fatal detail is a fixed string, because
	// v2ray-core's Start error can embed *localAddr or *localPort verbatim; the
	// raw error still goes to stderr via logFatal.
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

	// Start is synchronous through the listener bind, so the listener is accepting
	// once it returns nil. listenAddr refuses port 0, so the requested port is the
	// bound port.
	emitReady(localListenAddr, []string{network})

	<-osSignals
}
