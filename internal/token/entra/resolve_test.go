package entra_test

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
	"github.com/girishmotwani/aksh/internal/token"
	"github.com/girishmotwani/aksh/internal/token/entra"
)

// panicRoundTripper fails the test if any HTTP request is attempted.
type panicRoundTripper struct {
	t      *testing.T
	called int
}

func (p *panicRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	p.called++
	p.t.Fatalf("unexpected HTTP call during local-only operation")
	return nil, nil
}

// TestResolve_NilSelector_ReturnsError (test 49) — entra.Resolve(nil) returns a
// validation error instead of panicking or delegating a nil selector.
func TestResolve_NilSelector_ReturnsError(t *testing.T) {
	_, err := entra.Resolve(nil)
	if err == nil {
		t.Fatal("expected error for nil selector, got nil")
	}
}

// TestResolve_InvalidProvider_ReturnsError (test 50) — entra.Resolve rejects a
// selector with provider aws or any non-empty non-entra value.
func TestResolve_InvalidProvider_ReturnsError(t *testing.T) {
	for _, provider := range []string{"aws", "gcp", "vault"} {
		sel := &v1alpha1.CredentialSelector{
			Provider: provider,
			Resource: "https://graph.microsoft.com",
		}
		_, err := entra.Resolve(sel)
		if err == nil {
			t.Fatalf("expected error for provider %q, got nil", provider)
		}
	}
}

// TestResolve_EmptyProviderAccepted_DelegatesToTokenResolve (test 57) — a
// selector with empty provider is accepted and delegated to token.Resolve,
// preserving provider-neutral defaulting.
func TestResolve_EmptyProviderAccepted_DelegatesToTokenResolve(t *testing.T) {
	sel := &v1alpha1.CredentialSelector{
		Resource: "https://graph.microsoft.com",
		Scopes:   []string{"https://graph.microsoft.com/.default"},
	}
	got, err := entra.Resolve(sel)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want, err := token.Resolve(token.CredentialSelector{
		Resource: sel.Resource,
		Scopes:   sel.Scopes,
	})
	if err != nil {
		t.Fatalf("token.Resolve: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve did not delegate to token.Resolve: got %+v want %+v", got, want)
	}
	if got.Provider != "entra" {
		t.Fatalf("empty provider should default to entra, got %q", got.Provider)
	}
}

// TestResolve_EntraProviderAccepted_DelegatesToTokenResolve (test 58) — a
// selector with provider entra is accepted and the returned resolved credential
// matches the token.Resolve result.
func TestResolve_EntraProviderAccepted_DelegatesToTokenResolve(t *testing.T) {
	sel := &v1alpha1.CredentialSelector{
		Provider: "entra",
		Resource: "https://graph.microsoft.com",
		Scopes:   []string{"https://graph.microsoft.com/.default"},
	}
	got, err := entra.Resolve(sel)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want, err := token.Resolve(token.CredentialSelector{
		Provider: sel.Provider,
		Resource: sel.Resource,
		Scopes:   sel.Scopes,
	})
	if err != nil {
		t.Fatalf("token.Resolve: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve did not match token.Resolve: got %+v want %+v", got, want)
	}
}

// TestLocalSelfTest_MissingProjectedTokenFile_ReturnsError (test 51) —
// LocalSelfTest fails locally when the projected SA token file cannot be read
// and makes zero network calls.
func TestLocalSelfTest_MissingProjectedTokenFile_ReturnsError(t *testing.T) {
	rt := &panicRoundTripper{t: t}
	opts := validOptions()
	opts.SATokenPath = filepath.Join(t.TempDir(), "missing-token")
	opts.HTTPClient = &http.Client{Transport: rt}

	err := entra.LocalSelfTest(opts)
	if err == nil {
		t.Fatal("expected error for missing projected token file, got nil")
	}
	if rt.called != 0 {
		t.Fatalf("expected zero HTTP calls, got %d", rt.called)
	}
}

// TestLocalSelfTest_ValidOptionsAndToken_ReturnsNilWithoutHTTP (test 63) —
// LocalSelfTest with valid WIF options and a readable JWT returns nil while a
// panic-on-use HTTP client records zero calls.
func TestLocalSelfTest_ValidOptionsAndToken_ReturnsNilWithoutHTTP(t *testing.T) {
	rt := &panicRoundTripper{t: t}
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	// A minimal unsigned JWT built at runtime as
	// base64url(header).base64url(payload).signature. Segments are encoded here
	// (rather than pasted as literals) so the fixture is self-evidently a valid
	// three-segment JWT and does not trip secret-scanning redaction in tooling.
	b64 := base64.RawURLEncoding.EncodeToString
	header := b64([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := b64([]byte(`{"sub":"system:serviceaccount:default:agent","aud":"api://AzureADTokenExchange"}`))
	jwt := header + "." + payload + "." + b64([]byte("signature"))
	if err := os.WriteFile(path, []byte(jwt), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	opts := validOptions()
	opts.SATokenPath = path
	opts.HTTPClient = &http.Client{Transport: rt}

	if err := entra.LocalSelfTest(opts); err != nil {
		t.Fatalf("LocalSelfTest returned error for valid options: %v", err)
	}
	if rt.called != 0 {
		t.Fatalf("expected zero HTTP calls, got %d", rt.called)
	}
}
