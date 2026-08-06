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

// TestListenerNetwork verifies the inbound-transport decision that drives the
// sitrep `transports` value (and mirrors the transport v2ray-core binds). Only
// server+quic binds a UDP listener (the quic inbound faces the remote client);
// every other combination — client mode (plain TCP dokodemo inbound) and
// server+websocket — is TCP. An unknown mode resolves to "tcp" here and is
// rejected later by generateConfig's switch default, before emitReady. See
// bindreams/hole#421.
func TestListenerNetwork(t *testing.T) {
	// Do NOT t.Parallel() this (or its subtests): it mutates the package-global
	// *server/*mode flag pointers, which are shared across the whole test binary.
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
// confirmed bindable for UDP, so the TCP bind-conflict pin test cannot flake
// on a Windows independent-excluded-port-range mismatch
// (TCP and UDP maintain separate Hyper-V/WSL/Docker reservation tables — the
// exact race hole_common::port_alloc::bind_ephemeral exists to absorb on the
// Rust side). It binds TCP on an OS-assigned port, verifies the same port binds
// for UDP, then releases only the UDP socket — leaving TCP held and the UDP
// space proven free. Unbounded retry on a per-port TCP/UDP mismatch (no
// arbitrary cap; the OS ephemeral allocator is the natural termination, same as
// port_alloc).
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

// exRayHelperProcessEnv gates TestMainHelperProcess: only the child spawned
// by runExRaySubprocess actually calls the real main() entry point. Under a
// plain `go test` run (this env var unset) it returns immediately and does
// nothing.
const exRayHelperProcessEnv = "EXRAY_TEST_HELPER_PROCESS"

// TestMainHelperProcess is not a test of its own. runExRaySubprocess re-execs
// the already-compiled test binary with -test.run pinned to this name and
// exRayHelperProcessEnv set, so the real main() -- including its os.Exit
// calls -- runs as a genuine child process the parent test observes end to
// end (stdout sitrep stream + real exit code), without mocking either. This
// is the standard library's own TestHelperProcess pattern (see os/exec's
// tests).
//
// keepalive_wiring_test.go's TestMain runs registerTCPKeepAlive() once
// before any test in this binary, including in the re-exec'd child --
// main() then calls it again on paths that reach it (client mode, no
// registerTCPKeepAlive error). Both calls append to a process-global slice
// in the vendored internet package (that file's own comment: "no
// removal"), but the child is a separate OS process from the one running
// this test, so nothing about that duplication crosses the process
// boundary back into the parent test binary's state; and within the child,
// two structurally-identical controller registrations produce the same
// dial-time keepalive settings twice, not a functional difference. Fatal
// cases never reach it at all (main.go exits before registerTCPKeepAlive's
// own call site).
func TestMainHelperProcess(_ *testing.T) {
	if os.Getenv(exRayHelperProcessEnv) != "1" {
		return
	}
	main()
}

// runExRaySubprocessTimeout bounds how long a child ex-ray process may run
// before emitting its terminal sitrep event. This is the sanctioned
// exception to synchronizing via time: it bounds an external child
// process's exit (something that genuinely might never happen -- a wedge
// anywhere between hello and the terminal event), and the duration is a
// failure bound surfaced to a human ("the child produced no terminal
// sitrep within 30s"), not a synchronization device between two pieces of
// code this repo controls.
const runExRaySubprocessTimeout = 30 * time.Second

// runExRaySubprocess re-execs the test binary as a fresh ex-ray process with
// env set, and returns the parsed hello event, the parsed terminal sitrep
// event (whichever of ready/bind_conflict/fatal follows hello), and the
// exit code.
//
// sitrep.go guarantees exactly one of ready/bind_conflict/fatal follows
// hello before the plugin serves or exits (crates/garter/SITREP.md's "Event
// ordering" section), so reading exactly two lines is the primary
// rendezvous -- not a poll, a real completion signal. The bounded context is
// the backstop for a child that wedges before ever emitting its terminal
// event -- e.g. a silently swallowed parse error that lets ex-ray bind
// successfully and block forever on <-osSignals -- so the test fails with a clear message instead
// of hanging until go test's own package timeout kills everything with no
// indication of which subtest hung. A genuine "ready" terminal event is
// killed immediately after being observed, since main() then only exits on
// SIGINT/SIGTERM.
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

// freeTCPPort returns a port that was free at the moment of the call, for
// the one test below that needs ex-ray to actually bind successfully. The
// listen-then-close-then-reuse pattern is the standard Go idiom for finding
// a free port; the caller (TestReadySitrepReachesParentOnValidOptions)
// handles the resulting check-then-act race the same way this file's
// existing reserveTCPPortWithFreeUDP handles its own: retry on a genuine
// conflict rather than fail the test on an infrastructure race.
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
		{"malformed_options_never_echo_secret", `certRaw=SUPERSECRETVALUE;;path=/`, true},
		// Task 2 Step 7's four generateConfig/buildTLSConfig no-echo fixes,
		// driven through the REAL pipeline (parsePluginOptions ->
		// parseOptsIntoFlags -> buildV2Ray -> generateConfig/buildTLSConfig
		// -> emitFatal), not just via directly-stuffed flag globals the way
		// Task 2's own unit tests do it -- proves the backslash-absorption
		// exploit those unit tests assume is real actually reaches these
		// sites end to end.
		{"invalid_localPort_never_echo_secret", `localPort=1\;certRaw=SUPERSECRETVALUE`, true},
		{"invalid_remotePort_never_echo_secret", `remotePort=1\;certRaw=SUPERSECRETVALUE`, true},
		{"invalid_mode_never_echo_secret", `mode=abc\;certRaw=SUPERSECRETVALUE`, true},
		{"invalid_ech_mode_never_echo_secret", `tls;host=example.com;ech=abc\;certRaw=SUPERSECRETVALUE`, true},
		// Task 2's boolean and loglevel fixes, likewise through the real
		// pipeline: tls=false must be fatal, not a silent TLS-enable, and
		// must never echo an absorbed secret; same for an unrecognized
		// loglevel.
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

// The control: a valid options string must still reach ready and bind on
// the SS_LOCAL_*-derived address. The fatal-path cases above only prove
// real per-input behavior if this control exists: a helper that always
// reported `fatal` would still pass every fatal-path case, but fails here.
func TestReadySitrepReachesParentOnValidOptions(t *testing.T) {
	// freeTCPPort's port can lose a race to another process before the
	// child binds it. classifyBindError (bind_error.go) reports every OS
	// listen failure as bind_conflict regardless of errno, so retrying on
	// the event name alone would also retry -- forever -- on a genuine,
	// deterministic failure (e.g. no permission to bind loopback in a
	// sandboxed CI runner), reintroducing exactly the unbounded-hang risk
	// runExRaySubprocessTimeout exists to catch one level down, where that
	// per-child timeout can't see a parent-level infinite retry. Retry only
	// on the specific errno the race can actually produce (address already
	// in use); anything else is a real environment failure this test
	// should report, not paper over. Unbounded on that one errno, matching
	// this file's existing reserveTCPPortWithFreeUDP: the OS ephemeral
	// allocator is the natural termination.
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
