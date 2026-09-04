package runtime

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/girishmotwani/aksh/internal/token"
	"github.com/girishmotwani/aksh/internal/token/static"
)

// panicAcquirer fails the test if it is ever called; it proves the dispatch
// routes away from a provider it should not touch.
type panicAcquirer struct{ t *testing.T }

func (p panicAcquirer) Acquire(context.Context, token.ResolvedCredential) (token.Token, error) {
	p.t.Fatalf("acquirer called for the wrong provider")
	return token.Token{}, nil
}

func resolveProvider(t *testing.T, provider, resource string) token.ResolvedCredential {
	t.Helper()
	rc, err := token.Resolve(token.CredentialSelector{Provider: provider, Resource: resource})
	if err != nil {
		t.Fatalf("resolve %q: %v", provider, err)
	}
	return rc
}

func TestProviderDispatch_RoutesEntra(t *testing.T) {
	entra := &fakeBaseAcquirer{token: token.NewToken("entra-tok", time.Now().Add(time.Hour))}
	d := providerDispatchAcquirer{Entra: entra, Static: panicAcquirer{t}}

	if _, err := d.Acquire(context.Background(), resolveProvider(t, "entra", "https://vault.example.com")); err != nil {
		t.Fatalf("entra route failed: %v", err)
	}
	if entra.callCount() != 1 {
		t.Fatalf("entra acquirer calls = %d, want 1", entra.callCount())
	}
}

func TestProviderDispatch_EmptyProviderRoutesEntra(t *testing.T) {
	entra := &fakeBaseAcquirer{token: token.NewToken("entra-tok", time.Now().Add(time.Hour))}
	d := providerDispatchAcquirer{Entra: entra}
	// A bare empty provider bypasses token.Resolve's defaulting; the dispatch
	// must still route it to entra for direct callers.
	if _, err := d.Acquire(context.Background(), token.ResolvedCredential{Provider: ""}); err != nil {
		t.Fatalf("empty provider must route to entra: %v", err)
	}
	if entra.callCount() != 1 {
		t.Fatalf("entra calls = %d, want 1", entra.callCount())
	}
}

func TestProviderDispatch_RoutesStatic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("sk-static\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	staticAcq, err := static.NewAcquirer(static.Options{TokenPath: path})
	if err != nil {
		t.Fatalf("new static acquirer: %v", err)
	}
	d := providerDispatchAcquirer{Entra: panicAcquirer{t}, Static: staticAcq}

	tok, err := d.Acquire(context.Background(), resolveProvider(t, "static", "openai-api-key"))
	if err != nil {
		t.Fatalf("static route failed: %v", err)
	}
	if tok.Reveal() != "sk-static" {
		t.Fatalf("static route returned wrong token")
	}
}

func TestProviderDispatch_StaticUnconfiguredFailsClosed(t *testing.T) {
	d := providerDispatchAcquirer{Entra: &fakeBaseAcquirer{}}
	_, err := d.Acquire(context.Background(), resolveProvider(t, "static", "openai-api-key"))
	assertPermanent(t, err)
}

func TestProviderDispatch_UnknownProviderFailsClosed(t *testing.T) {
	d := providerDispatchAcquirer{Entra: &fakeBaseAcquirer{}, Static: &fakeBaseAcquirer{}}
	_, err := d.Acquire(context.Background(), resolveProvider(t, "vault", "secret/data/x"))
	assertPermanent(t, err)
}

// TestProviderDispatch_PreservesGuardSemantics wraps a dispatch in a guard and
// confirms the guard's breaker/negative-cache/metrics semantics are provider-
// agnostic: a permanent failure for an unknown provider is recorded once and
// cached. (Production wires the guard BELOW the dispatch, per provider; this
// composition test only exercises the guard's contract.)
func TestProviderDispatch_PreservesGuardSemantics(t *testing.T) {
	metrics := &fakeAcquireMetrics{}
	negative := token.NewNegativeCache(16, 30*time.Second)
	guarded := runtimeTokenAcquirer{
		Base:     providerDispatchAcquirer{Entra: &fakeBaseAcquirer{}},
		Breaker:  token.NewBreaker(5, 30),
		Negative: negative,
		Metrics:  metrics,
	}
	rc := resolveProvider(t, "static", "openai-api-key") // static unconfigured -> permanent

	if _, err := guarded.Acquire(context.Background(), rc); err == nil {
		t.Fatalf("unconfigured static provider must fail closed")
	}
	if cached := negative.Get(token.CredID(rc)); cached == nil {
		t.Fatalf("permanent dispatch failure must populate the negative cache")
	}
	if entries := metrics.snapshot(); len(entries) != 1 || entries[0].provider != "static" || entries[0].class != "permanent" {
		t.Fatalf("metric labels = %+v, want one static/permanent", entries)
	}
}

// TestStaticProvider_EndToEndInjectsBearer demonstrates the full custody path:
// a policy credential selector with provider "static" resolves through the
// dispatch + guarded cache, and the existing InjectStage stamps the file-backed
// secret as Authorization: Bearer <key> even though SanitiseStage first strips
// the caller's Authorization.
func TestStaticProvider_EndToEndInjectsBearer(t *testing.T) {
	const secret = "sk-openai-real"
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	staticAcq, err := static.NewAcquirer(static.Options{TokenPath: path})
	if err != nil {
		t.Fatalf("new static acquirer: %v", err)
	}
	guarded := runtimeTokenAcquirer{
		Base:     providerDispatchAcquirer{Entra: &fakeBaseAcquirer{}, Static: staticAcq},
		Breaker:  token.NewBreaker(5, 30),
		Negative: token.NewNegativeCache(16, 30*time.Second),
	}
	cache := token.NewTokenCache(guarded, token.CacheOptions{MaxEntries: 8})

	result, err := cache.Get(context.Background(), token.CredentialSelector{Provider: "static", Resource: "openai-api-key"})
	if err != nil {
		t.Fatalf("cache.Get: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// The caller attempted to smuggle its own Authorization; Sanitise strips it.
	req.Header.Set("Authorization", "Bearer dummy-kagent-key")
	rc := &pipeline.RequestContext{Request: req, TokenResult: result}

	if d := (&pipeline.SanitiseStage{}).Execute(rc); !d.IsAllow() {
		t.Fatalf("sanitise disposition = %v, want allow", d.Disposition())
	}
	if d := (&pipeline.InjectStage{}).Execute(rc); !d.IsAllow() {
		t.Fatalf("inject disposition = %v, want allow", d.Disposition())
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+secret {
		t.Fatalf("Authorization header not set to the static bearer credential")
	}
}

// TestNoCredential_LeavesAuthorizationStripped confirms the unchanged
// no-credential behavior: a match with no credential selector injects nothing,
// so SanitiseStage's removal of the caller Authorization is the final state.
func TestNoCredential_LeavesAuthorizationStripped(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer dummy-kagent-key")
	rc := &pipeline.RequestContext{Request: req} // empty TokenResult

	if d := (&pipeline.SanitiseStage{}).Execute(rc); !d.IsAllow() {
		t.Fatalf("sanitise disposition = %v, want allow", d.Disposition())
	}
	if d := (&pipeline.InjectStage{}).Execute(rc); !d.IsAllow() {
		t.Fatalf("inject disposition = %v, want allow", d.Disposition())
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want empty (no credential must not inject)", got)
	}
}

func assertPermanent(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected permanent error, got nil")
	}
	var ae *token.AcquireError
	if !errors.As(err, &ae) {
		t.Fatalf("error %v is not *token.AcquireError", err)
	}
	if ae.Class != token.AcquireErrorPermanent {
		t.Fatalf("class = %s, want permanent", ae.Class)
	}
}
