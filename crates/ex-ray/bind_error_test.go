package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestClassifyBindError(t *testing.T) {
	bindAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1984}
	listen := &net.OpError{Op: "listen", Net: "tcp", Addr: bindAddr, Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	wrappedListen := newError("failed to listen TCP on 1984").Base(
		newError("failed to listen TCP on 127.0.0.1:1984").Base(listen))
	dial := &net.OpError{Op: "dial", Net: "tcp", Addr: bindAddr, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	listenNoErrno := &net.OpError{Op: "listen", Net: "tcp", Addr: bindAddr, Err: errors.New("opaque")}
	// A nil Addr yields addr "" — the case main()'s localListenAddr fallback covers.
	listenNilAddr := &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}

	cases := []struct {
		name         string
		err          error
		wantErrno    int
		wantAddr     string
		wantConflict bool
	}{
		{"wrapped listen EADDRINUSE", wrappedListen, int(syscall.EADDRINUSE), "127.0.0.1:1984", true},
		{"bare listen EADDRINUSE", listen, int(syscall.EADDRINUSE), "127.0.0.1:1984", true},
		{"dial ECONNREFUSED is not a bind conflict", dial, 0, "", false},
		{"plain config error is not a bind conflict", newError("bad config"), 0, "", false},
		{"listen without a raw errno", listenNoErrno, 0, "127.0.0.1:1984", true},
		{"listen with nil Addr yields empty addr", listenNilAddr, int(syscall.EADDRINUSE), "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errno, addr, ok := classifyBindError(c.err)
			if ok != c.wantConflict {
				t.Fatalf("classifyBindError(%v) conflict = %v, want %v", c.err, ok, c.wantConflict)
			}
			if errno != c.wantErrno {
				t.Errorf("classifyBindError(%v) errno = %d, want %d", c.err, errno, c.wantErrno)
			}
			if addr != c.wantAddr {
				t.Errorf("classifyBindError(%v) addr = %q, want %q", c.err, addr, c.wantAddr)
			}
		})
	}
}

// Asserts Start() against a held port classifies as a bind conflict whose errno
// and addr match an independent OS oracle, not the test's own reservation values.
func assertStartClassifiesAsConflict(t *testing.T, what, network, addr string) {
	t.Helper()
	server, err := buildV2Ray()
	if err != nil {
		t.Fatalf("buildV2Ray(%s) = %v, want a buildable config", what, err)
	}
	defer func() { _ = server.Close() }()

	startErr := server.Start()
	if startErr == nil {
		t.Fatalf("server.Start(%s) = nil, want a bind conflict on the held port", what)
	}
	errno, gotAddr, ok := classifyBindError(startErr)
	if !ok {
		t.Fatalf("classifyBindError(%s: %v) = _, _, false; want a recognized listen conflict", what, startErr)
	}
	wantErrno, wantAddr := osListenConflict(t, network, addr)
	if errno != wantErrno {
		t.Errorf("classifyBindError(%s) errno = %d, want the OS conflict errno %d", what, errno, wantErrno)
	}
	if gotAddr != wantAddr {
		t.Errorf("classifyBindError(%s) addr = %q, want the OS conflict addr %q", what, gotAddr, wantAddr)
	}
}

// osListenConflict binds network on addr (expected to already be held) with the
// Go stdlib and returns the errno and addr of the resulting conflict from its own
// *net.OpError — an independent oracle for both values the classifier extracts
// from v2ray-core's bind of the same address (both go through the same net stack,
// so a semantically-equal addr renders identically).
func osListenConflict(t *testing.T, network, addr string) (errno int, gotAddr string) {
	t.Helper()
	var closer io.Closer
	var err error
	if network == "udp" {
		var pc net.PacketConn
		pc, err = net.ListenPacket("udp", addr)
		closer = pc
	} else {
		var ln net.Listener
		ln, err = net.Listen("tcp", addr)
		closer = ln
	}
	if err == nil {
		_ = closer.Close()
		t.Fatalf("oracle: %s bind of held %s unexpectedly succeeded", network, addr)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("oracle: %s bind error %v is not a *net.OpError", network, err)
	}
	var se syscall.Errno
	if !errors.As(opErr, &se) {
		t.Fatalf("oracle: %s conflict %v carries no syscall.Errno", network, err)
	}
	if opErr.Addr != nil {
		gotAddr = opErr.Addr.String()
	}
	return int(se), gotAddr
}

// reserveUDPPort holds a UDP loopback port so v2ray-core's quic listener conflicts on it.
func reserveUDPPort(t *testing.T) (net.PacketConn, string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("hold UDP port: %v", err)
	}
	return pc, pc.LocalAddr().String()
}

// writeSelfSignedCertKey writes a self-signed ECDSA cert + PKCS#8 key (PEM) to a
// temp dir. server+quic mandates TLS, so a valid cert lets the bind (not TLS) be
// the failure under test.
func writeSelfSignedCertKey(t *testing.T, cn string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	writePEMFile(t, certPath, "CERTIFICATE", der)
	writePEMFile(t, keyPath, "PRIVATE KEY", keyDER)
	return certPath, keyPath
}

func writePEMFile(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// Pins that v2ray-core's real inbound-bind error stays classifiable end-to-end.
// Client mode binds a TCP dokodemo inbound.
func TestServerStartBindConflictClassifiesTCP(t *testing.T) {
	ln, addr := reserveTCPPortWithFreeUDP(t)
	defer func() { _ = ln.Close() }()
	bindHost, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) = %v", addr, err)
	}

	restore := withFlags(t, 1, 0, false) // client mode
	defer restore()
	origLA, origLP := *localAddr, *localPort
	*localAddr, *localPort = bindHost, port
	defer func() { *localAddr, *localPort = origLA, origLP }()

	assertStartClassifiesAsConflict(t, "127.0.0.1 TCP", "tcp", addr)
}

// Pins the same guarantee for the server+quic UDP listener (binds a UDP socket
// via tcpWorker.Start → internet.ListenTCP → the quic transport listener). On a
// held UDP port the conflict must classify identically to the TCP case.
func TestServerStartBindConflictClassifiesQUIC(t *testing.T) {
	pc, addr := reserveUDPPort(t)
	defer func() { _ = pc.Close() }()
	bindHost, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) = %v", addr, err)
	}
	certPath, keyPath := writeSelfSignedCertKey(t, "example.test")

	restore := withFlags(t, 1, 0, true) // server mode
	defer restore()
	origMode, origLA, origLP := *mode, *localAddr, *localPort
	origCert, origKey, origHost, origTLS := *cert, *key, *host, *tlsEnabled
	defer func() {
		*mode, *localAddr, *localPort = origMode, origLA, origLP
		*cert, *key, *host, *tlsEnabled = origCert, origKey, origHost, origTLS
	}()
	*mode, *localAddr, *localPort = "quic", bindHost, port
	*cert, *key, *host = certPath, keyPath, "example.test"

	assertStartClassifiesAsConflict(t, "server+quic UDP", "udp", addr)
}

// Pins the config side of the failure disposition: an absent server cert makes
// buildV2Ray surface a config error that is NOT a bind_conflict, so main() routes
// it to fatal/exit-23.
func TestBuildV2RayMissingCertIsNotBindConflict(t *testing.T) {
	restore := withFlags(t, 1, 0, true) // server mode
	defer restore()
	origMode, origLA, origLP := *mode, *localAddr, *localPort
	origCert, origKey, origHost, origTLS := *cert, *key, *host, *tlsEnabled
	defer func() {
		*mode, *localAddr, *localPort = origMode, origLA, origLP
		*cert, *key, *host, *tlsEnabled = origCert, origKey, origHost, origTLS
	}()
	dir := t.TempDir()
	*mode, *localAddr, *localPort = "quic", "127.0.0.1", "1984"
	*cert, *key, *host = filepath.Join(dir, "absent.pem"), filepath.Join(dir, "absent.key"), "example.test"

	_, err := buildV2Ray()
	if err == nil {
		t.Fatal("buildV2Ray() = nil, want the absent-cert config error")
	}
	// Structural, not message-text: the absent cert surfaces as fs.ErrNotExist
	// through v5.52.0's Unwrap, proving buildV2Ray failed on the intended read.
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("buildV2Ray() error = %v, want it to wrap fs.ErrNotExist (the absent cert)", err)
	}
	if _, _, ok := classifyBindError(err); ok {
		t.Fatalf("config error mis-classified as a bind conflict: %v", err)
	}
}
