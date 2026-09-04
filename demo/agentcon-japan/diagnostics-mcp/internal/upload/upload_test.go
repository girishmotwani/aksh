package upload

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/demo/agentcon-japan/diagnostics-mcp/internal/testca"
)

const telemetryHost = "telemetry.ops-insights.example"

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// tlsServer starts an httptest TLS server presenting a leaf for telemetryHost,
// capturing the SNI, and returns the server plus the CA that signed it.
func tlsServer(t *testing.T, handler http.Handler) (*httptest.Server, []byte, *atomic.Value) {
	t.Helper()
	ca, err := testca.Generate(telemetryHost)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := tls.X509KeyPair(ca.CertPEM, ca.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	sni := new(atomic.Value)
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leaf},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			sni.Store(chi.ServerName)
			return nil, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, ca.CAPEM, sni
}

// uploaderTo builds an Uploader whose dial ignores the resolved address and
// connects to the httptest server, so TLS/SNI/status logic is exercised without
// the IPv4 guard (which is unit-tested separately).
func uploaderTo(t *testing.T, srv *httptest.Server, caPEM []byte, timeout time.Duration) *Uploader {
	t.Helper()
	caPath := writeFile(t, "ca.pem", caPEM)
	target := srv.Listener.Addr().String()
	up, err := New(Config{
		Endpoint:     "https://" + telemetryHost + "/api/v1/cluster-diagnostics",
		CABundlePath: caPath,
		Timeout:      timeout,
		dialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", target)
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return up
}

func TestUpload_Success_PreservesSNIAndTrustsCA(t *testing.T) {
	srv, caPEM, sni := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	up := uploaderTo(t, srv, caPEM, 5*time.Second)

	res, err := up.Upload(context.Background(), []byte(`{"ok":true}`))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if !res.OK() || res.StatusCode != 202 {
		t.Errorf("status = %+v", res)
	}
	if got := sni.Load(); got == nil || got.(string) != telemetryHost {
		t.Errorf("SNI = %v, want %s", got, telemetryHost)
	}
	if want := "upload succeeded: HTTP 202 Accepted"; res.Message() != want {
		t.Errorf("Message = %q, want %q", res.Message(), want)
	}
}

func TestUpload_403_VerbatimAndNoRetry(t *testing.T) {
	var calls atomic.Int32
	srv, caPEM, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "denied", http.StatusForbidden)
	}))
	up := uploaderTo(t, srv, caPEM, 5*time.Second)

	res, err := up.Upload(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("Upload returned transport error: %v", err)
	}

	if res.OK() {
		t.Fatal("403 must not be OK")
	}
	if res.Message() != "upload failed: HTTP 403 Forbidden" {
		t.Errorf("Message = %q", res.Message())
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server hit %d times, want exactly 1 (no retry)", got)
	}
}

func TestUpload_RedirectIsNotFollowedOrReplayed(t *testing.T) {
	var calls atomic.Int32
	srv, caPEM, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Redirect(w, r, "https://attacker.invalid/collect", http.StatusTemporaryRedirect)
	}))
	up := uploaderTo(t, srv, caPEM, 5*time.Second)
	res, err := up.Upload(context.Background(), []byte(`{"diagnostics":true}`))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if res.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want 307", res.StatusCode)
	}
	if calls.Load() != 1 {
		t.Fatalf("server calls = %d, want exactly one", calls.Load())
	}
}

func TestUpload_Timeout(t *testing.T) {
	srv, caPEM, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	up := uploaderTo(t, srv, caPEM, 50*time.Millisecond)

	_, err := up.Upload(context.Background(), []byte(`{}`))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	var ne net.Error
	if !strings.Contains(err.Error(), "timed out") && !(errors.As(err, &ne) && ne.Timeout()) {
		t.Errorf("expected timeout error, got %v", err)
	}
}

func TestUpload_UntrustedCA(t *testing.T) {
	srv, _, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Trust a DIFFERENT CA than the one that signed the server leaf.
	other, err := testca.Generate("unrelated.example")
	if err != nil {
		t.Fatal(err)
	}
	up := uploaderTo(t, srv, other.CAPEM, 5*time.Second)
	if _, err := up.Upload(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("expected CA trust error")
	} else if !strings.Contains(err.Error(), "not trusted") && !strings.Contains(err.Error(), "certificate") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNew_RejectsBadConfig(t *testing.T) {
	goodCA := writeFile(t, "ca.pem", mustCA(t))
	cases := []struct {
		name string
		cfg  Config
	}{
		{"empty endpoint", Config{CABundlePath: goodCA}},
		{"http endpoint", Config{Endpoint: "http://" + telemetryHost + "/x", CABundlePath: goodCA}},
		{"loopback endpoint", Config{Endpoint: "https://localhost/x", CABundlePath: goodCA}},
		{"missing ca", Config{Endpoint: "https://" + telemetryHost + "/x", CABundlePath: filepath.Join(t.TempDir(), "nope")}},
		{"empty ca file", Config{Endpoint: "https://" + telemetryHost + "/x", CABundlePath: writeFile(t, "empty.pem", []byte("not a cert"))}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidateEndpoint_PromptBoundary(t *testing.T) {
	good := "https://" + telemetryHost + "/api/v1/cluster-diagnostics"
	if got, err := ValidateEndpoint(good, telemetryHost); err != nil || got != good {
		t.Fatalf("ValidateEndpoint(good) = %q, %v", got, err)
	}
	if _, err := ValidateEndpoint("https://"+telemetryHost+":443/api/v1/cluster-diagnostics", telemetryHost); err != nil {
		t.Fatalf("explicit 443 should pass: %v", err)
	}
	bad := []string{
		"http://" + telemetryHost + "/api/v1/cluster-diagnostics",
		"https://attacker.invalid/api/v1/cluster-diagnostics",
		"https://127.0.0.1/api/v1/cluster-diagnostics",
		"https://" + telemetryHost + ":8443/api/v1/cluster-diagnostics",
		"https://" + telemetryHost + "/wrong",
		"https://user@" + telemetryHost + "/api/v1/cluster-diagnostics",
		"https://" + telemetryHost + "/api/v1/cluster-diagnostics?copy=true",
		"https://" + telemetryHost + "/api/v1/cluster-diagnostics#fragment",
		"https://" + telemetryHost + "/api/v1/%63luster-diagnostics",
	}
	for _, endpoint := range bad {
		if _, err := ValidateEndpoint(endpoint, telemetryHost); err == nil {
			t.Errorf("ValidateEndpoint(%q) unexpectedly passed", endpoint)
		}
	}
}

func TestIsLoopbackName(t *testing.T) {
	for _, h := range []string{"localhost", "LOCALHOST", "foo.localhost", "127.0.0.1", "127.5.5.5", "::1", "0.0.0.0"} {
		if !IsLoopbackName(h) {
			t.Errorf("%q should be loopback", h)
		}
	}
	for _, h := range []string{telemetryHost, "10.0.0.5", "8.8.8.8"} {
		if IsLoopbackName(h) {
			t.Errorf("%q should not be loopback", h)
		}
	}
}

func TestSelectIPv4(t *testing.T) {
	v6 := net.ParseIP("2001:db8::1")
	v4 := net.ParseIP("203.0.113.7")
	lo := net.ParseIP("127.0.0.1")

	got, err := SelectIPv4("h", []net.IP{v6, v4, lo})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "203.0.113.7" {
		t.Errorf("selected = %v, want only 203.0.113.7", got)
	}
	if _, err := SelectIPv4("h", []net.IP{v6}); err == nil {
		t.Error("IPv6-only should error")
	}
	if _, err := SelectIPv4("h", []net.IP{lo}); err == nil {
		t.Error("loopback-only should error")
	}
}

// recordingDialer captures the network/address passed to DialContext.
type recordingDialer struct {
	network string
	addr    string
}

func (d *recordingDialer) DialContext(_ context.Context, network, addr string) (net.Conn, error) {
	d.network = network
	d.addr = addr
	c, _ := net.Pipe()
	return c, nil
}

func TestIPv4DialContext_ForcesTCP4AndIPv4(t *testing.T) {
	rd := &recordingDialer{}
	lookup := func(_ context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2001:db8::9"), net.ParseIP("198.51.100.9")}, nil
	}
	dial := IPv4DialContext(rd, lookup)
	conn, err := dial(context.Background(), "tcp", telemetryHost+":443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()
	if rd.network != "tcp4" {
		t.Errorf("network = %q, want tcp4", rd.network)
	}
	if rd.addr != "198.51.100.9:443" {
		t.Errorf("addr = %q, want IPv4:port", rd.addr)
	}
}

func TestIPv4DialContext_RefusesLoopback(t *testing.T) {
	rd := &recordingDialer{}
	dial := IPv4DialContext(rd, func(context.Context, string) ([]net.IP, error) {
		t.Fatal("lookup should not be called for a loopback name")
		return nil, nil
	})
	if _, err := dial(context.Background(), "tcp", "localhost:443"); err == nil {
		t.Fatal("expected refusal for localhost")
	}
	if rd.network != "" {
		t.Errorf("dialer should not have been invoked, got %q", rd.network)
	}
}

func TestIPv4DialContext_NoIPv4Available(t *testing.T) {
	dial := IPv4DialContext(&recordingDialer{}, func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2001:db8::1")}, nil
	})
	if _, err := dial(context.Background(), "tcp", telemetryHost+":443"); err == nil {
		t.Fatal("expected error when only IPv6 resolves")
	}
}

// helpers

func mustCA(t *testing.T) []byte {
	t.Helper()
	ca, err := testca.Generate(telemetryHost)
	if err != nil {
		t.Fatal(err)
	}
	return ca.CAPEM
}
