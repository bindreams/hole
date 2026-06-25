package utls_test

import (
	"net"
	"strings"
	"testing"

	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tls/utls"
)

// The uTLS engine drops EncryptedClientHelloConfigList, so it cannot satisfy
// ech=always. It must fail closed by refusing before any handshake rather than
// hand a cleartext-SNI hello to uTLS.
func TestUTLSClientRefusesRequireEch(t *testing.T) {
	engine, err := utls.NewUTLSSecurityEngineFromConfig(&utls.Config{
		TlsConfig: &tls.Config{ServerName: "example.com", RequireEch: true},
	})
	common.Must(err)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn, err := engine.Client(client)
	if conn != nil {
		conn.Close()
		t.Fatal("a refused uTLS Client must not return a connection")
	}
	// Assert the refuse fired, not an incidental error (an empty Imitate preset
	// would also error, masking a missing refuse).
	if err == nil || !strings.Contains(err.Error(), "ech=always") {
		t.Fatalf("RequireEch must make the uTLS engine refuse, got: %v", err)
	}
}
