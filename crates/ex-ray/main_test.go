package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestListenerNetwork pins the inbound-transport decision behind the sitrep
// `transports` value: only server+quic is UDP, every other combination is TCP,
// and an unknown mode resolves to "tcp" (generateConfig rejects it before
// emitReady).
func TestListenerNetwork(t *testing.T) {
	// Not parallel: it mutates the package-global *server and *mode flags.
	origServer, origMode := *server, *mode
	t.Cleanup(func() { *server, *mode = origServer, origMode })

	cases := []struct {
		name   string
		server bool
		mode   string
		want   string
	}{
		{"client_websocket", false, "websocket", "tcp"},
		{"client_quic", false, "quic", "tcp"},
		{"server_websocket", true, "websocket", "tcp"},
		{"server_quic", true, "quic", "udp"},
		{"server_unknown_mode", true, "grpc", "tcp"},
		{"client_unknown_mode", false, "grpc", "tcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			*server, *mode = tc.server, tc.mode
			if got := listenerNetwork(); got != tc.want {
				t.Errorf("listenerNetwork() with server=%v mode=%q = %q, want %q", tc.server, tc.mode, got, tc.want)
			}
		})
	}
}

// reserveTCPPortWithFreeUDP returns a held TCP listener whose port is also
// bindable for UDP, so the TCP bind-conflict test cannot fail on a Windows
// excluded-port-range mismatch (TCP and UDP keep separate Hyper-V/WSL/Docker
// reservation tables). It binds TCP on an OS-assigned port, checks the same port
// binds for UDP, then releases the UDP socket. It retries on a per-port mismatch
// with no cap; the OS ephemeral allocator ends the loop.
func reserveTCPPortWithFreeUDP(t *testing.T) (net.Listener, string) {
	t.Helper()
	for {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to bind sentinel TCP listener: %v", err)
		}
		addr := ln.Addr().String()
		pc, udpErr := net.ListenPacket("udp", addr)
		if udpErr != nil {
			// This port is reserved for UDP (excluded-range mismatch); the TCP
			// bind happened to win it anyway. Release and pick another.
			_ = ln.Close()
			continue
		}
		_ = pc.Close()
		return ln, addr
	}
}

// exRayHelperProcessEnv gates TestMainHelperProcess: only the child spawned by
// runExRaySubprocess calls the real main. Under a plain `go test` run it is unset
// and the helper returns immediately.
const exRayHelperProcessEnv = "EXRAY_TEST_HELPER_PROCESS"

// TestMainHelperProcess is not a test of its own. runExRaySubprocess re-execs
// the compiled test binary with -test.run pinned to this name and
// exRayHelperProcessEnv set, so the real main, os.Exit calls included, runs as a
// child process whose sitrep stream and exit code the parent observes. It is the
// standard library's TestHelperProcess pattern (see os/exec's tests).
//
// The child registers the keepalive controller twice, which is harmless.
func TestMainHelperProcess(_ *testing.T) {
	if os.Getenv(exRayHelperProcessEnv) != "1" {
		return
	}
	main()
}

// runExRaySubprocessTimeout bounds how long a child ex-ray process may run
// before emitting its terminal sitrep event. It is the failure bound surfaced to
// a human ("the child produced no terminal sitrep"), not a synchronization
// device: the child is an external process that may never emit one.
const runExRaySubprocessTimeout = 30 * time.Second

// runExRaySubprocess re-execs the test binary as a fresh ex-ray process with env
// set, and returns the parsed hello event, the parsed terminal sitrep event
// (whichever of ready, bind_conflict or fatal follows hello), and the exit code.
//
// Exactly one terminal event follows hello (crates/garter/SITREP.md, "Event
// ordering"), so reading two lines is the rendezvous. The timeout context is the
// backstop for a child that wedges before emitting one, such as a swallowed
// parse error that lets ex-ray bind and block on <-osSignals: the test fails with
// a message instead of waiting for go test's package timeout. After a `ready`
// the child is killed, since main then exits only on SIGINT or SIGTERM, and the
// exit code is -1.
func runExRaySubprocess(t *testing.T, env map[string]string) (hello, terminal map[string]any, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), runExRaySubprocessTimeout)
	defer cancel()
	//nolint:gosec // G204: re-execs this very test binary (os.Args[0]) with a fixed -test.run; no external input reaches Command.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainHelperProcess$")
	cmd.Env = append(os.Environ(), exRayHelperProcessEnv+"=1")
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// cmd.Stderr is a bytes.Buffer, not an *os.File, so os/exec copies the
	// child's stderr into it on a background goroutine that only Wait joins
	// -- reading stderr.String() before Wait returns races that goroutine.
	// drain kills the child (a no-op if it already exited) and joins it
	// exactly once, so every failure path below can safely read stderr.
	waited := false
	drain := func() string {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			waited = true
		}
		return stderr.String()
	}
	t.Cleanup(func() { drain() })

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		if ctx.Err() != nil {
			t.Fatalf("ex-ray child produced no stdout within %s and was killed; stderr:\n%s", runExRaySubprocessTimeout, drain())
		}
		t.Fatalf("subprocess produced no stdout before closing (scan err: %v); stderr:\n%s", scanner.Err(), drain())
	}
	helloLine := scanner.Text()
	if jerr := json.Unmarshal([]byte(helloLine), &hello); jerr != nil {
		t.Fatalf("hello line %q did not parse as JSON: %v; stderr:\n%s", helloLine, jerr, drain())
	}

	if !scanner.Scan() {
		if ctx.Err() != nil {
			t.Fatalf("ex-ray child emitted hello but produced no terminal sitrep within %s and was killed; stderr:\n%s", runExRaySubprocessTimeout, drain())
		}
		t.Fatalf("subprocess emitted hello but no terminal event before closing (scan err: %v); stderr:\n%s", scanner.Err(), drain())
	}
	terminalLine := scanner.Text()
	if jerr := json.Unmarshal([]byte(terminalLine), &terminal); jerr != nil {
		t.Fatalf("terminal sitrep line %q did not parse as JSON: %v; stderr:\n%s", terminalLine, jerr, drain())
	}

	if terminal["event"] == "ready" {
		drain()
		return hello, terminal, -1 // exit code is meaningless after a forced kill
	}

	waitErr := cmd.Wait()
	waited = true
	if waitErr == nil {
		return hello, terminal, 0
	}
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		// cmd.Wait already returned, so stderr.String() is safe here without drain().
		t.Fatalf("cmd.Wait: %v; stderr:\n%s", waitErr, stderr.String())
	}
	return hello, terminal, exitErr.ExitCode()
}

// freeTCPPort returns a port that was free at the moment of the call, for the
// tests that need ex-ray to bind successfully. Another process may take it before
// the child binds; callers retry on a bind_conflict with address-in-use.
func freeTCPPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeTCPPort: Listen: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("freeTCPPort: SplitHostPort: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("freeTCPPort: Close: %v", err)
	}
	return port
}

// Drives the real process boundary end to end for every fail-loud case:
// hello then fatal on stdout, and a non-zero exit.
func TestFatalSitrepReachesParentAndProcessExitsNonZero(t *testing.T) {
	cases := []struct {
		name                       string
		pluginOptions              string
		wantSecretAbsentFromDetail bool
	}{
		{"malformed_options_dangling_escape", `host=example.com;path=/a\`, false},
		{"malformed_options_empty_key", `host=example.com;=v`, false},
		{"invalid_mux_non_numeric", "mux=off", false},
		{"invalid_tcp_keepalive_non_numeric", "tcp-keepalive=off", false},
		{"invalid_fwmark_non_numeric", "fwmark=off", false},
		{"invalid_remote_port_out_of_range", "remotePort=70000", false},
		{"invalid_remote_port_zero", "remotePort=0", false},
		{"invalid_remote_addr_empty", "remoteAddr=", false},
		{"invalid_remote_addr_any_ip", "remoteAddr=0.0.0.0", false},
		{"invalid_cert_raw_not_pem", "tls;host=example.com;certRaw=not-a-real-certificate", false},
		{"invalid_host_empty", "host=;path=/", false},
		{"invalid_cert_material_without_tls", "certRaw=some-cert-content;host=example.com;path=/", false},
		// "00" is port 0 to net.PortFromString. A raw compare against "0" would miss
		// it, and ex-ray would bind an OS-assigned port while ready.listen reported "00".
		{"invalid_local_port_non_canonical_zero", "localPort=00", false},
		{"malformed_options_never_echo_secret", `certRaw=SUPERSECRETVALUE;;path=/`, true},
		// No-echo for localPort, remotePort and mode through the whole pipeline
		// (parsePluginOptions, parseOptsIntoFlags, buildV2Ray, emitFatal), not just
		// with flag globals set directly as the unit tests do: it shows that a
		// backslash-absorbed secret reaches these sites end to end.
		{"invalid_localPort_never_echo_secret", `localPort=1\;certRaw=SUPERSECRETVALUE`, true},
		{"invalid_remotePort_never_echo_secret", `remotePort=1\;certRaw=SUPERSECRETVALUE`, true},
		{"invalid_mode_never_echo_secret", `mode=abc\;certRaw=SUPERSECRETVALUE`, true},
		// parseEnumOption rejects the ech value inside parseOptsIntoFlags, so this
		// case covers its no-echo behavior, not buildTLSConfig's ech branch.
		{"invalid_ech_mode_never_echo_secret", `tls;host=example.com;ech=abc\;certRaw=SUPERSECRETVALUE`, true},
		// tls and loglevel: an unrecognized value is fatal and never echoes an
		// absorbed secret.
		{"invalid_tls_bool_never_echo_secret", `tls=abc\;certRaw=SUPERSECRETVALUE`, true},
		{"invalid_loglevel_never_echo_secret", `loglevel=abc\;certRaw=SUPERSECRETVALUE`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hello, terminal, exitCode := runExRaySubprocess(t, map[string]string{
				"SS_REMOTE_HOST":    "chain.example.net",
				"SS_REMOTE_PORT":    "9443",
				"SS_LOCAL_HOST":     "10.1.2.3",
				"SS_LOCAL_PORT":     "45999",
				"SS_PLUGIN_OPTIONS": c.pluginOptions,
			})
			if hello["event"] != "hello" {
				t.Errorf("first sitrep line event = %v, want %q", hello["event"], "hello")
			}
			if terminal["event"] != "fatal" {
				t.Fatalf("terminal sitrep event = %v, want %q", terminal["event"], "fatal")
			}
			detail, _ := terminal["detail"].(string)
			if detail == "" {
				t.Error("fatal event has no detail naming the failure")
			}
			if c.wantSecretAbsentFromDetail && strings.Contains(detail, "SUPERSECRETVALUE") {
				t.Errorf("fatal detail leaks option content: %q", detail)
			}
			if exitCode == 0 {
				t.Error("process exited 0; want a non-zero exit so the parent can gate on it")
			}
			if exitCode != 23 {
				t.Errorf("exit code = %d, want 23 (ex-ray's config-class-error convention)", exitCode)
			}
		})
	}
}

// cert points at a nonexistent path carrying an absorbed secret, which the
// os.PathError text would otherwise embed. It needs its own env: in server mode
// SS_REMOTE_HOST becomes *localAddr, and a non-IP *localAddr is fatal before
// buildTLSConfig, so SS_REMOTE_HOST must be an IP literal for the flow to reach
// the cert read.
func TestInvalidCertPathSitrepNeverEchoesSecret(t *testing.T) {
	hello, terminal, exitCode := runExRaySubprocess(t, map[string]string{
		"SS_REMOTE_HOST":    "10.9.8.7",
		"SS_REMOTE_PORT":    "9443",
		"SS_LOCAL_HOST":     "10.1.2.3",
		"SS_LOCAL_PORT":     "45999",
		"SS_PLUGIN_OPTIONS": `tls;server;host=example.com;cert=/nope\;certRaw=SUPERSECRETVALUE`,
	})
	if hello["event"] != "hello" {
		t.Errorf("first sitrep line event = %v, want %q", hello["event"], "hello")
	}
	if terminal["event"] != "fatal" {
		t.Fatalf("terminal sitrep event = %v, want %q", terminal["event"], "fatal")
	}
	detail, _ := terminal["detail"].(string)
	if !strings.Contains(detail, "failed to read cert") {
		t.Errorf("fatal detail = %q, want it to mention the cert read failure (not some other fault)", detail)
	}
	if strings.Contains(detail, "SUPERSECRETVALUE") {
		t.Errorf("fatal detail leaks the absorbed segment: %q", detail)
	}
	if exitCode != 23 {
		t.Errorf("exit code = %d, want 23 (ex-ray's config-class-error convention)", exitCode)
	}
}

// A non-IP localAddr such as "nosuchhost.invalid" is fatal before the process
// tries to bind, with a message that never interpolates the rejected value
// (listenAddr). The generic Start-failure `fatal` is a fixed
// string too; no test drives that branch.
func TestInvalidLocalAddrSitrepNeverEchoesValue(t *testing.T) {
	hello, terminal, exitCode := runExRaySubprocess(t, map[string]string{
		"SS_REMOTE_HOST":    "chain.example.net",
		"SS_REMOTE_PORT":    "9443",
		"SS_LOCAL_HOST":     "10.1.2.3",
		"SS_LOCAL_PORT":     "45999",
		"SS_PLUGIN_OPTIONS": `localAddr=nosuchhost.invalid\;certRaw=SUPERSECRETVALUE;host=example.com;path=/`,
	})
	if hello["event"] != "hello" {
		t.Errorf("first sitrep line event = %v, want %q", hello["event"], "hello")
	}
	if terminal["event"] != "fatal" {
		t.Fatalf("terminal sitrep event = %v, want %q", terminal["event"], "fatal")
	}
	detail, _ := terminal["detail"].(string)
	if !strings.Contains(detail, "localAddr") {
		t.Errorf("fatal detail = %q, want it to mention localAddr", detail)
	}
	if strings.Contains(detail, "SUPERSECRETVALUE") {
		t.Errorf("fatal detail leaks the absorbed segment: %q", detail)
	}
	if exitCode != 23 {
		t.Errorf("exit code = %d, want 23 (ex-ray's config-class-error convention)", exitCode)
	}
}

// A `|`-separated multi-address localAddr (the grammar of upstream
// v2ray-plugin's server-mode multi-listen) is fatal: `ready` carries one
// `listen` address, so listenAddr rejects it in main before buildV2Ray. Server mode
// is used because the `|` grammar is server-only, and there the `remoteAddr`
// option, not `localAddr`, becomes *localAddr (see parseOptsIntoFlags).
func TestMultiAddressLocalAddrSitrepReachesParentAndProcessExitsNonZero(t *testing.T) {
	hello, terminal, exitCode := runExRaySubprocess(t, map[string]string{
		"SS_REMOTE_HOST":    "10.9.8.7",
		"SS_REMOTE_PORT":    "9443",
		"SS_LOCAL_HOST":     "10.1.2.3",
		"SS_LOCAL_PORT":     "45999",
		"SS_PLUGIN_OPTIONS": "server;remoteAddr=127.0.0.1|127.0.0.2;host=example.com;path=/",
	})
	if hello["event"] != "hello" {
		t.Errorf("first sitrep line event = %v, want %q", hello["event"], "hello")
	}
	if terminal["event"] != "fatal" {
		t.Fatalf("terminal sitrep event = %v, want %q", terminal["event"], "fatal")
	}
	detail, _ := terminal["detail"].(string)
	if !strings.Contains(detail, "localAddr") {
		t.Errorf("fatal detail = %q, want it to mention localAddr", detail)
	}
	if exitCode != 23 {
		t.Errorf("exit code = %d, want 23 (ex-ray's config-class-error convention)", exitCode)
	}
}

// A partial SS_* chain-handoff env (here, SS_REMOTE_PORT blank) must be a `fatal`
// sitrep through the real process boundary, not a stderr warning beside `ready`.
func TestPartialSSEnvSitrepReachesParentAndProcessExitsNonZero(t *testing.T) {
	hello, terminal, exitCode := runExRaySubprocess(t, map[string]string{
		"SS_REMOTE_HOST":    "chain.example.net",
		"SS_REMOTE_PORT":    "",
		"SS_LOCAL_HOST":     "10.1.2.3",
		"SS_LOCAL_PORT":     "45999",
		"SS_PLUGIN_OPTIONS": "host=example.com;path=/",
	})
	if hello["event"] != "hello" {
		t.Errorf("first sitrep line event = %v, want %q", hello["event"], "hello")
	}
	if terminal["event"] != "fatal" {
		t.Fatalf("terminal sitrep event = %v, want %q", terminal["event"], "fatal")
	}
	detail, _ := terminal["detail"].(string)
	if !strings.Contains(detail, "SS_*") {
		t.Errorf("fatal detail = %q, want it to mention the incomplete SS_* env", detail)
	}
	if exitCode == 0 {
		t.Error("process exited 0; want a non-zero exit so the parent can gate on it")
	}
}

// A malformed port must be fatal when it comes from the SS_* chain handoff
// (SS_REMOTE_PORT), not only from an SS_PLUGIN_OPTIONS override.
// TestFatalSitrepReachesParentAndProcessExitsNonZero never varies SS_REMOTE_PORT or
// SS_LOCAL_PORT, so it would not catch validation limited to the options path.
func TestInvalidSSEnvPortSitrepReachesParentAndProcessExitsNonZero(t *testing.T) {
	hello, terminal, exitCode := runExRaySubprocess(t, map[string]string{
		"SS_REMOTE_HOST":    "chain.example.net",
		"SS_REMOTE_PORT":    "70000",
		"SS_LOCAL_HOST":     "10.1.2.3",
		"SS_LOCAL_PORT":     "45999",
		"SS_PLUGIN_OPTIONS": "host=example.com;path=/",
	})
	if hello["event"] != "hello" {
		t.Errorf("first sitrep line event = %v, want %q", hello["event"], "hello")
	}
	if terminal["event"] != "fatal" {
		t.Fatalf("terminal sitrep event = %v, want %q", terminal["event"], "fatal")
	}
	detail, _ := terminal["detail"].(string)
	if !strings.Contains(detail, "remotePort") {
		t.Errorf("fatal detail = %q, want it to mention remotePort", detail)
	}
	if exitCode == 0 {
		t.Error("process exited 0; want a non-zero exit so the parent can gate on it")
	}
}

// isAddrInUse reports whether errno (read from a bind_conflict sitrep
// event) is the platform's address-in-use code. Go's syscall.EADDRINUSE is
// the real Unix errno; on Windows it's a fabricated APPLICATION_ERROR-space
// value that never matches the real Winsock WSAEADDRINUSE (10048) ex-ray's
// own classifyBindError (bind_error.go) actually reports.
func isAddrInUse(errno int) bool {
	if runtime.GOOS == "windows" {
		return errno == 10048 // WSAEADDRINUSE
	}
	return errno == int(syscall.EADDRINUSE)
}

// The control: a valid options string must reach ready and bind on the
// SS_LOCAL_*-derived address. Without it, a helper that always reported `fatal`
// would pass every fatal-path case above.
func TestReadySitrepReachesParentOnValidOptions(t *testing.T) {
	// freeTCPPort's port can be taken before the child binds it. classifyBindError
	// reports every listen failure as bind_conflict whatever the errno, so retrying
	// on the event alone would loop forever on a deterministic failure (such as a
	// sandbox that forbids binding loopback). Retry only on address-in-use, the
	// errno the race produces, and fail on any other.
	for {
		port := freeTCPPort(t)
		hello, terminal, _ := runExRaySubprocess(t, map[string]string{
			"SS_REMOTE_HOST":    "example.com",
			"SS_REMOTE_PORT":    "443",
			"SS_LOCAL_HOST":     "127.0.0.1",
			"SS_LOCAL_PORT":     port,
			"SS_PLUGIN_OPTIONS": "host=example.com;path=/",
		})
		if terminal["event"] == "bind_conflict" {
			errno, _ := terminal["errno"].(float64)
			if isAddrInUse(int(errno)) {
				continue
			}
			t.Fatalf("bind_conflict with errno %v, want the address-in-use code to retry, anything else is a real failure; terminal: %v", terminal["errno"], terminal)
		}
		if hello["event"] != "hello" {
			t.Errorf("first sitrep line event = %v, want %q", hello["event"], "hello")
		}
		if terminal["event"] != "ready" {
			t.Fatalf("terminal sitrep event = %v, want %q", terminal["event"], "ready")
		}
		wantListen := "127.0.0.1:" + port
		if terminal["listen"] != wantListen {
			t.Errorf("listen = %v, want %q", terminal["listen"], wantListen)
		}
		return
	}
}

// An IPv4-mapped IPv6 literal ("::ffff:127.0.0.1") passes listenAddr, but
// v2ray-core folds it to plain IPv4 before binding (IPAddress in
// third_party/v2ray-core/common/net/address.go). ready.listen must report the
// folded form v2ray-core bound, or a host cannot tell where ex-ray listens.
func TestReadySitrepReportsCanonicalFormOfV4MappedV6LocalAddr(t *testing.T) {
	for {
		port := freeTCPPort(t)
		hello, terminal, _ := runExRaySubprocess(t, map[string]string{
			"SS_REMOTE_HOST":    "example.com",
			"SS_REMOTE_PORT":    "443",
			"SS_LOCAL_HOST":     "::ffff:127.0.0.1",
			"SS_LOCAL_PORT":     port,
			"SS_PLUGIN_OPTIONS": "host=example.com;path=/",
		})
		if terminal["event"] == "bind_conflict" {
			errno, _ := terminal["errno"].(float64)
			if isAddrInUse(int(errno)) {
				continue
			}
			t.Fatalf("bind_conflict with errno %v, want the address-in-use code to retry, anything else is a real failure; terminal: %v", terminal["errno"], terminal)
		}
		if hello["event"] != "hello" {
			t.Errorf("first sitrep line event = %v, want %q", hello["event"], "hello")
		}
		if terminal["event"] != "ready" {
			t.Fatalf("terminal sitrep event = %v, want %q", terminal["event"], "ready")
		}
		wantListen := "127.0.0.1:" + port
		if terminal["listen"] != wantListen {
			t.Errorf("listen = %v, want the folded IPv4 form %q, not the raw IPv4-mapped-IPv6 literal", terminal["listen"], wantListen)
		}
		return
	}
}

// A leading-zero localPort ("0" + the port) is the same port to v2ray-core, so
// ready.listen must report the canonical decimal form, not the spelling the
// operator wrote: a host compares it against the endpoint it dials.
func TestReadySitrepReportsCanonicalFormOfLeadingZeroLocalPort(t *testing.T) {
	for {
		port := freeTCPPort(t)
		hello, terminal, _ := runExRaySubprocess(t, map[string]string{
			"SS_REMOTE_HOST":    "example.com",
			"SS_REMOTE_PORT":    "443",
			"SS_LOCAL_HOST":     "127.0.0.1",
			"SS_LOCAL_PORT":     "0" + port,
			"SS_PLUGIN_OPTIONS": "host=example.com;path=/",
		})
		if terminal["event"] == "bind_conflict" {
			errno, _ := terminal["errno"].(float64)
			if isAddrInUse(int(errno)) {
				continue
			}
			t.Fatalf("bind_conflict with errno %v, want the address-in-use code to retry, anything else is a real failure; terminal: %v", terminal["errno"], terminal)
		}
		if hello["event"] != "hello" {
			t.Errorf("first sitrep line event = %v, want %q", hello["event"], "hello")
		}
		if terminal["event"] != "ready" {
			t.Fatalf("terminal sitrep event = %v, want %q", terminal["event"], "ready")
		}
		wantListen := "127.0.0.1:" + port
		if terminal["listen"] != wantListen {
			t.Errorf("listen = %v, want the canonical port %q, not the leading-zero spelling", terminal["listen"], wantListen)
		}
		return
	}
}

// The operator-facing `fatal` detail for a refused listen address keeps its
// reason: port 0 is refused because v2ray-core cannot report the bound port, and
// a `|` list because `ready` carries one address. The value is never echoed.
func TestListenAddrFatalDetailKeepsTheReason(t *testing.T) {
	cases := []struct {
		name, options, want string
	}{
		{
			"port_zero",
			"localPort=0;host=example.com;path=/",
			"invalid localPort: port-0 OS-assignment is not supported (v2ray-core does not expose the bound port)",
		},
		{
			"address_list",
			"server;remoteAddr=127.0.0.1|127.0.0.2;host=example.com;path=/",
			"invalid localAddr: a single listen address is required (the ready sitrep cannot report more than one)",
		},
		{
			"hostname",
			"localAddr=nosuchhost.invalid;host=example.com;path=/",
			"invalid localAddr: must be an IP literal",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, terminal, exitCode := runExRaySubprocess(t, map[string]string{
				"SS_REMOTE_HOST":    "10.9.8.7",
				"SS_REMOTE_PORT":    "9443",
				"SS_LOCAL_HOST":     "10.1.2.3",
				"SS_LOCAL_PORT":     "45999",
				"SS_PLUGIN_OPTIONS": tc.options,
			})
			if terminal["event"] != "fatal" {
				t.Fatalf("terminal sitrep event = %v, want %q", terminal["event"], "fatal")
			}
			if detail, _ := terminal["detail"].(string); detail != tc.want {
				t.Errorf("fatal detail = %q, want %q", detail, tc.want)
			}
			if exitCode != 23 {
				t.Errorf("exit code = %d, want 23", exitCode)
			}
		})
	}
}
