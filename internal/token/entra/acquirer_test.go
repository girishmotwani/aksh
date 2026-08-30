package entra_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/token"
	"github.com/girishmotwani/aksh/internal/token/entra"
)

// fakeEntra is an httptest-backed mock of the Entra token endpoint that records
// the last client_assertion it received.
type fakeEntra struct {
	server *httptest.Server

	mu            sync.Mutex
	calls         int
	lastAssertion string
	lastClientID  string
	handler       func(w http.ResponseWriter, assertion string)
}

func newFakeEntra(t *testing.T, handler func(w http.ResponseWriter, assertion string)) *fakeEntra {
	t.Helper()
	f := &fakeEntra{handler: handler}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.calls++
		f.lastAssertion = r.FormValue("client_assertion")
		f.lastClientID = r.FormValue("client_id")
		f.mu.Unlock()
		f.handler(w, r.FormValue("client_assertion"))
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeEntra) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeEntra) assertion() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAssertion
}

func writeSAToken(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write SA token: %v", err)
	}
	return path
}

func successHandler(w http.ResponseWriter, _ string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token_type":   "Bearer",
		"expires_in":   3600,
		"access_token": "ACCESS-TOKEN-VALUE",
	})
}

func entraRC() token.ResolvedCredential {
	return token.ResolvedCredential{
		Identity:   "id-1",
		Provider:   "entra",
		Resource:   "https://graph.microsoft.com",
		WireScopes: []string{"https://graph.microsoft.com/.default"},
	}
}

// TestAcquire_ReadsSATokenFileEveryExchange (test 52) — two Acquire calls after
// changing the SA token file send two different client assertions.
func TestAcquire_ReadsSATokenFileEveryExchange(t *testing.T) {
	f := newFakeEntra(t, successHandler)
	saPath := writeSAToken(t, "assertion-one")

	opts := validOptions()
	opts.Authority = f.server.URL
	opts.SATokenPath = saPath
	opts.HTTPClient = f.server.Client()
	a, err := entra.NewAcquirer(opts)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := a.Acquire(context.Background(), entraRC()); err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	first := f.assertion()

	if err := os.WriteFile(saPath, []byte("assertion-two"), 0o600); err != nil {
		t.Fatalf("rewrite SA token: %v", err)
	}
	if _, err := a.Acquire(context.Background(), entraRC()); err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	second := f.assertion()

	if first == second {
		t.Fatalf("client_assertion not re-read: both %q", first)
	}
	if first != "assertion-one" || second != "assertion-two" {
		t.Fatalf("unexpected assertions: first=%q second=%q", first, second)
	}
}

func asAcquireError(t *testing.T, err error) *token.AcquireError {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ae *token.AcquireError
	if !errors.As(err, &ae) {
		t.Fatalf("error %v (%T) is not *token.AcquireError", err, err)
	}
	return ae
}

// TestAcquire_TransientHTTPStatus_ReturnsTransientAcquireError (test 53) —
// HTTP 429/5xx returns *token.AcquireError with Class == Transient.
func TestAcquire_TransientHTTPStatus_ReturnsTransientAcquireError(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway} {
		f := newFakeEntra(t, func(w http.ResponseWriter, _ string) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"temporarily_unavailable"}`))
		})
		opts := validOptions()
		opts.Authority = f.server.URL
		opts.SATokenPath = writeSAToken(t, "assertion")
		opts.HTTPClient = f.server.Client()
		a, err := entra.NewAcquirer(opts)
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.Acquire(context.Background(), entraRC())
		ae := asAcquireError(t, err)
		if ae.Class != token.AcquireErrorTransient {
			t.Fatalf("status %d: class = %v, want Transient", status, ae.Class)
		}
	}
}

// TestAcquire_Timeout_ReturnsTransientAcquireError (test 54) — context deadline
// or HTTP timeout maps to Transient and preserves cancellation semantics.
func TestAcquire_Timeout_ReturnsTransientAcquireError(t *testing.T) {
	release := make(chan struct{})
	f := newFakeEntra(t, func(w http.ResponseWriter, _ string) {
		<-release
		successHandler(w, "")
	})
	t.Cleanup(func() { close(release) })

	opts := validOptions()
	opts.Authority = f.server.URL
	opts.SATokenPath = writeSAToken(t, "assertion")
	opts.HTTPClient = f.server.Client()
	a, err := entra.NewAcquirer(opts)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = a.Acquire(ctx, entraRC())
	ae := asAcquireError(t, err)
	if ae.Class != token.AcquireErrorTransient {
		t.Fatalf("class = %v, want Transient", ae.Class)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error %v does not preserve context.DeadlineExceeded", err)
	}
}

// TestAcquire_InvalidScope_ReturnsPermanentAcquireError (test 55) — an Entra
// invalid-scope style response returns Class == Permanent.
func TestAcquire_InvalidScope_ReturnsPermanentAcquireError(t *testing.T) {
	f := newFakeEntra(t, func(w http.ResponseWriter, _ string) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_scope","error_description":"AADSTS70011: bad scope"}`))
	})
	opts := validOptions()
	opts.Authority = f.server.URL
	opts.SATokenPath = writeSAToken(t, "assertion")
	opts.HTTPClient = f.server.Client()
	a, err := entra.NewAcquirer(opts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Acquire(context.Background(), entraRC())
	ae := asAcquireError(t, err)
	if ae.Class != token.AcquireErrorPermanent {
		t.Fatalf("class = %v, want Permanent", ae.Class)
	}
}

// TestAcquire_Success_ReturnsTokenWithAccessTokenAndExpiry (test 56) — a
// successful token response yields a token.Token with the access token and
// parsed expiry timestamp.
func TestAcquire_Success_ReturnsTokenWithAccessTokenAndExpiry(t *testing.T) {
	f := newFakeEntra(t, successHandler)
	opts := validOptions()
	opts.Authority = f.server.URL
	opts.SATokenPath = writeSAToken(t, "assertion")
	opts.HTTPClient = f.server.Client()
	a, err := entra.NewAcquirer(opts)
	if err != nil {
		t.Fatal(err)
	}

	before := time.Now()
	tok, err := a.Acquire(context.Background(), entraRC())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if tok.Reveal() != "ACCESS-TOKEN-VALUE" {
		t.Fatalf("access token = %q, want ACCESS-TOKEN-VALUE", tok.Reveal())
	}
	exp := tok.ExpiresAt()
	if !exp.After(before) {
		t.Fatalf("expiry %v not after %v", exp, before)
	}
	if exp.After(before.Add(2 * time.Hour)) {
		t.Fatalf("expiry %v unexpectedly far in the future", exp)
	}
}

// TestAcquire_RejectsNonEntraResolvedCredential (test 62) — Acquire rejects a
// resolved credential whose provider is not entra before reading the SA token.
func TestAcquire_RejectsNonEntraResolvedCredential(t *testing.T) {
	f := newFakeEntra(t, successHandler)
	opts := validOptions()
	opts.Authority = f.server.URL
	// Point at a non-existent SA token path: if Acquire tried to read it the
	// error would be about the file, not the provider.
	opts.SATokenPath = filepath.Join(t.TempDir(), "does-not-exist")
	opts.HTTPClient = f.server.Client()
	a, err := entra.NewAcquirer(opts)
	if err != nil {
		t.Fatal(err)
	}

	rc := entraRC()
	rc.Provider = "aws"
	_, err = a.Acquire(context.Background(), rc)
	if err == nil {
		t.Fatal("expected error for non-entra provider, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "entra") &&
		!strings.Contains(strings.ToLower(err.Error()), "provider") {
		t.Fatalf("error %q does not mention provider mismatch", err)
	}
	if f.callCount() != 0 {
		t.Fatalf("expected zero HTTP calls, got %d", f.callCount())
	}
}

// TestAcquire_LogsFailureClassWithoutTokenMaterial (test 68) — acquire failure
// logging includes provider and error class but never token material.
func TestAcquire_LogsFailureClassWithoutTokenMaterial(t *testing.T) {
	const saSecret = "SECRET-SA-ASSERTION-DO-NOT-LOG"

	f := newFakeEntra(t, func(w http.ResponseWriter, _ string) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error"}`))
	})
	opts := validOptions()
	opts.Authority = f.server.URL
	opts.SATokenPath = writeSAToken(t, saSecret)
	opts.HTTPClient = f.server.Client()
	a, err := entra.NewAcquirer(opts)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prev := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prev)
		log.SetFlags(prevFlags)
	})

	_, err = a.Acquire(context.Background(), entraRC())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	logged := buf.String()
	if !strings.Contains(logged, "entra") {
		t.Fatalf("log %q does not mention provider", logged)
	}
	if !strings.Contains(logged, token.AcquireErrorTransient.String()) {
		t.Fatalf("log %q does not mention error class", logged)
	}
	if strings.Contains(logged, saSecret) {
		t.Fatalf("log leaked SA assertion material: %q", logged)
	}
}

func validOptions() entra.Options {
	return entra.Options{
		TenantID:    "tenant-abc",
		ClientID:    "client-xyz",
		Authority:   "https://login.microsoftonline.com/tenant-abc/oauth2/v2.0/token",
		SATokenPath: "/var/run/secrets/aksh/token",
		Timeout:     10 * time.Second,
	}
}

// TestNewAcquirer_MissingTenantID_ReturnsError (test 45) — NewAcquirer rejects
// empty TenantID before creating an HTTP client path.
func TestNewAcquirer_MissingTenantID_ReturnsError(t *testing.T) {
	opts := validOptions()
	opts.TenantID = ""
	a, err := entra.NewAcquirer(opts)
	if err == nil {
		t.Fatal("expected error for missing TenantID, got nil")
	}
	if a != nil {
		t.Fatal("expected nil Acquirer on validation error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "tenant") {
		t.Fatalf("error %q does not mention the TenantID field", err)
	}
}

// TestNewAcquirer_MissingClientID_ReturnsError (test 46) — NewAcquirer rejects
// empty ClientID with a field-specific error.
func TestNewAcquirer_MissingClientID_ReturnsError(t *testing.T) {
	opts := validOptions()
	opts.ClientID = ""
	a, err := entra.NewAcquirer(opts)
	if err == nil {
		t.Fatal("expected error for missing ClientID, got nil")
	}
	if a != nil {
		t.Fatal("expected nil Acquirer on validation error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "client") {
		t.Fatalf("error %q does not mention the ClientID field", err)
	}
}

// TestNewAcquirer_MissingSATokenPath_ReturnsError (test 47) — NewAcquirer
// rejects empty SATokenPath; no exchange can use ambient credentials.
func TestNewAcquirer_MissingSATokenPath_ReturnsError(t *testing.T) {
	opts := validOptions()
	opts.SATokenPath = ""
	a, err := entra.NewAcquirer(opts)
	if err == nil {
		t.Fatal("expected error for missing SATokenPath, got nil")
	}
	if a != nil {
		t.Fatal("expected nil Acquirer on validation error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "satoken") &&
		!strings.Contains(strings.ToLower(err.Error()), "sa token") {
		t.Fatalf("error %q does not mention the SATokenPath field", err)
	}
}

// TestNewAcquirer_NonHTTPSAuthority_ReturnsError (test 48) — NewAcquirer rejects
// http:// and schemeless authorities; only HTTPS authorities are accepted.
func TestNewAcquirer_NonHTTPSAuthority_ReturnsError(t *testing.T) {
	for _, authority := range []string{
		"http://login.microsoftonline.com/tenant/oauth2/v2.0/token",
		"login.microsoftonline.com/tenant/oauth2/v2.0/token",
		"",
		"ftp://example.com/token",
	} {
		opts := validOptions()
		opts.Authority = authority
		a, err := entra.NewAcquirer(opts)
		if err == nil {
			t.Fatalf("expected error for non-HTTPS authority %q, got nil", authority)
		}
		if a != nil {
			t.Fatalf("expected nil Acquirer on validation error for %q", authority)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "authority") &&
			!strings.Contains(strings.ToLower(err.Error()), "https") {
			t.Fatalf("error %q does not mention the Authority/HTTPS requirement", err)
		}
	}
}
