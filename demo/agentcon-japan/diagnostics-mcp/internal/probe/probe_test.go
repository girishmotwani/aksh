package probe

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/testca"
	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/upload"
)

const telemetryHost = "telemetry.ops-insights.example"

func TestNew_RejectsBadTargets(t *testing.T) {
	caPath := writeCA(t)
	cases := []Config{
		{URL: "https://localhost/__aksh_probe", CABundlePath: caPath},
		{URL: "http://" + telemetryHost + "/__aksh_probe", CABundlePath: caPath},
		{URL: "https://" + telemetryHost + "/mcp", CABundlePath: caPath},
		{URL: "https://" + telemetryHost + "/", CABundlePath: caPath},
	}
	for _, c := range cases {
		if _, err := New(c); err == nil {
			t.Errorf("expected rejection for %q", c.URL)
		}
	}
}

func TestDo_HitsProbePathReturnsStatus(t *testing.T) {
	ca, err := testca.Generate(telemetryHost)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := tls.X509KeyPair(ca.CertPEM, ca.KeyPEM)

	var gotPath atomic.Value
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	srv.StartTLS()
	defer srv.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, ca.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	target := srv.Listener.Addr().String()
	client, err := upload.NewIPv4Client(caPath, 5*time.Second, nil, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", target)
	})
	if err != nil {
		t.Fatal(err)
	}

	p, err := New(Config{URL: "https://" + telemetryHost + "/__aksh_probe", CABundlePath: caPath, client: client})
	if err != nil {
		t.Fatal(err)
	}
	code, err := p.Do(context.Background())
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if code != http.StatusNoContent {
		t.Errorf("code = %d", code)
	}
	if gotPath.Load() != "/__aksh_probe" {
		t.Errorf("path = %v, want /__aksh_probe", gotPath.Load())
	}
}

func writeCA(t *testing.T) string {
	t.Helper()
	ca, err := testca.Generate(telemetryHost)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, ca.CAPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
