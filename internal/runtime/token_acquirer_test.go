package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/token"
)

// fakeBaseAcquirer is a controllable token.TokenAcquirer that records call
// counts so the guarded adapter's fail-closed gating can be asserted without a
// live Entra endpoint.
type fakeBaseAcquirer struct {
	mu    sync.Mutex
	calls int
	token token.Token
	err   error
}

func (f *fakeBaseAcquirer) Acquire(_ context.Context, _ token.ResolvedCredential) (token.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.token, f.err
}

func (f *fakeBaseAcquirer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeAcquireMetrics captures the bounded (provider, class) labels the runtime
// adapter records so tests can assert no token material leaks into metrics.
type acquireFailLabel struct{ provider, class string }

type fakeAcquireMetrics struct {
	mu      sync.Mutex
	entries []acquireFailLabel
}

func (f *fakeAcquireMetrics) RecordAcquireFailure(provider, class string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, acquireFailLabel{provider: provider, class: class})
}

func (f *fakeAcquireMetrics) snapshot() []acquireFailLabel {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]acquireFailLabel(nil), f.entries...)
}

func testResolvedCredential(t *testing.T) token.ResolvedCredential {
	t.Helper()
	rc, err := token.Resolve(token.CredentialSelector{
		Provider: "entra",
		Resource: "https://vault.example.com",
		Scopes:   []string{"https://vault.example.com/.default"},
	})
	if err != nil {
		t.Fatalf("resolve credential: %v", err)
	}
	return rc
}

func TestRuntimeTokenAcquirer_ComposesCacheAroundEntraAcquirer(t *testing.T) {
	base := &fakeBaseAcquirer{token: token.NewToken("access", time.Now().Add(time.Hour))}
	guarded := runtimeTokenAcquirer{
		Base:     base,
		Breaker:  token.NewBreaker(5, 30),
		Negative: token.NewNegativeCache(16, 30*time.Second),
	}
	cache := token.NewTokenCache(guarded, token.CacheOptions{MaxEntries: 16})

	sel := token.CredentialSelector{
		Provider: "entra",
		Resource: "https://vault.example.com",
		Scopes:   []string{"https://vault.example.com/.default"},
	}
	first, err := cache.Get(context.Background(), sel)
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if first.CacheHit {
		t.Fatalf("first Get should not be a cache hit")
	}
	second, err := cache.Get(context.Background(), sel)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if !second.CacheHit {
		t.Fatalf("second Get should be served from the cache")
	}
	if got := base.callCount(); got != 1 {
		t.Fatalf("base acquirer calls = %d, want 1 (cache owns hits)", got)
	}
}

func TestRuntimeTokenAcquirer_UsesCredIDForNegativeCacheKey(t *testing.T) {
	rc := testResolvedCredential(t)
	permanent := &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "invalid_scope"}
	base := &fakeBaseAcquirer{err: permanent}
	negative := token.NewNegativeCache(16, 30*time.Second)
	guarded := runtimeTokenAcquirer{Base: base, Breaker: token.NewBreaker(5, 30), Negative: negative}

	if _, err := guarded.Acquire(context.Background(), rc); err == nil {
		t.Fatalf("expected permanent acquire error")
	}
	if cached := negative.Get(token.CredID(rc)); cached == nil {
		t.Fatalf("permanent failure not stored under token.CredID(rc)")
	}
}

func TestRuntimeTokenAcquirer_RecordsBreakerSuccessAfterSuccessfulExchange(t *testing.T) {
	rc := testResolvedCredential(t)
	base := &fakeBaseAcquirer{token: token.NewToken("access", time.Now().Add(time.Hour))}
	breaker := token.NewBreaker(3, 30)
	negative := token.NewNegativeCache(16, 30*time.Second)
	guarded := runtimeTokenAcquirer{Base: base, Breaker: breaker, Negative: negative}

	// Two prior transient failures leave the breaker below its threshold.
	breaker.RecordFailure(token.AcquireErrorTransient)
	breaker.RecordFailure(token.AcquireErrorTransient)

	if _, err := guarded.Acquire(context.Background(), rc); err != nil {
		t.Fatalf("successful exchange returned error: %v", err)
	}

	// A recorded success resets the failure count: two more transient failures
	// must not reach the threshold of three if RecordSuccess ran.
	breaker.RecordFailure(token.AcquireErrorTransient)
	breaker.RecordFailure(token.AcquireErrorTransient)
	if breaker.IsOpen() {
		t.Fatalf("breaker open: RecordSuccess did not reset the failure count")
	}
	if cached := negative.Get(token.CredID(rc)); cached != nil {
		t.Fatalf("successful exchange must not populate the negative cache")
	}
}

func TestRuntimeTokenAcquirer_RecordsBreakerFailureWithClass(t *testing.T) {
	rc := testResolvedCredential(t)

	transientBreaker := token.NewBreaker(1, 30)
	transientBase := &fakeBaseAcquirer{err: &token.AcquireError{Class: token.AcquireErrorTransient, Message: "5xx"}}
	transient := runtimeTokenAcquirer{Base: transientBase, Breaker: transientBreaker, Negative: token.NewNegativeCache(16, 30*time.Second)}
	if _, err := transient.Acquire(context.Background(), rc); err == nil {
		t.Fatalf("expected transient error")
	}
	if !transientBreaker.IsOpen() {
		t.Fatalf("transient class not forwarded to Breaker.RecordFailure (breaker should be open)")
	}

	permanentBreaker := token.NewBreaker(1, 30)
	permanentBase := &fakeBaseAcquirer{err: &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "invalid_scope"}}
	permanent := runtimeTokenAcquirer{Base: permanentBase, Breaker: permanentBreaker, Negative: token.NewNegativeCache(16, 30*time.Second)}
	if _, err := permanent.Acquire(context.Background(), rc); err == nil {
		t.Fatalf("expected permanent error")
	}
	if permanentBreaker.IsOpen() {
		t.Fatalf("permanent class must not open the breaker (wrong class forwarded)")
	}
}

func TestRuntimeTokenAcquirer_Metrics_RecordAcquireFailureByClass(t *testing.T) {
	rc := testResolvedCredential(t)
	metrics := &fakeAcquireMetrics{}
	base := &fakeBaseAcquirer{err: &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "invalid_scope"}}
	guarded := runtimeTokenAcquirer{
		Base:     base,
		Breaker:  token.NewBreaker(5, 30),
		Negative: token.NewNegativeCache(16, 30*time.Second),
		Metrics:  metrics,
	}

	if _, err := guarded.Acquire(context.Background(), rc); err == nil {
		t.Fatalf("expected permanent error")
	}

	entries := metrics.snapshot()
	if len(entries) != 1 {
		t.Fatalf("recorded %d acquire-failure metrics, want 1", len(entries))
	}
	if entries[0].provider != "entra" || entries[0].class != "permanent" {
		t.Fatalf("metric labels = %+v, want provider=entra class=permanent", entries[0])
	}
}

func TestRuntimeTokenAcquirer_OpenBreaker_DeniesWithoutBaseAcquire(t *testing.T) {
	rc := testResolvedCredential(t)
	breaker := token.NewBreaker(1, 30)
	breaker.RecordFailure(token.AcquireErrorTransient) // open it
	if !breaker.IsOpen() {
		t.Fatalf("precondition: breaker should be open")
	}
	base := &fakeBaseAcquirer{token: token.NewToken("access", time.Now().Add(time.Hour))}
	guarded := runtimeTokenAcquirer{Base: base, Breaker: breaker, Negative: token.NewNegativeCache(16, 30*time.Second)}

	_, err := guarded.Acquire(context.Background(), rc)
	if err == nil {
		t.Fatalf("open breaker must fail closed")
	}
	var ae *token.AcquireError
	if !errors.As(err, &ae) || ae.Class != token.AcquireErrorTransient {
		t.Fatalf("open breaker error = %v, want transient AcquireError", err)
	}
	if got := base.callCount(); got != 0 {
		t.Fatalf("base acquirer called %d times, want 0 under open breaker", got)
	}
}

func TestRuntimeTokenAcquirer_NegativeCacheHit_DeniesWithoutBaseAcquire(t *testing.T) {
	rc := testResolvedCredential(t)
	negative := token.NewNegativeCache(16, 30*time.Second)
	cachedErr := &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "invalid_scope"}
	negative.Put(token.CredID(rc), cachedErr)
	base := &fakeBaseAcquirer{token: token.NewToken("access", time.Now().Add(time.Hour))}
	guarded := runtimeTokenAcquirer{Base: base, Breaker: token.NewBreaker(5, 30), Negative: negative}

	_, err := guarded.Acquire(context.Background(), rc)
	if err == nil {
		t.Fatalf("negative cache hit must deny")
	}
	var ae *token.AcquireError
	if !errors.As(err, &ae) || ae.Class != token.AcquireErrorPermanent {
		t.Fatalf("returned error = %v, want the cached permanent AcquireError", err)
	}
	if got := base.callCount(); got != 0 {
		t.Fatalf("base acquirer called %d times, want 0 on negative-cache hit", got)
	}
}

func TestRuntimeTokenAcquirer_TransientFailure_DeniesRequestAndRecordsBreaker(t *testing.T) {
	rc := testResolvedCredential(t)
	breaker := token.NewBreaker(1, 30)
	negative := token.NewNegativeCache(16, 30*time.Second)
	base := &fakeBaseAcquirer{err: &token.AcquireError{Class: token.AcquireErrorTransient, Message: "5xx"}}
	guarded := runtimeTokenAcquirer{Base: base, Breaker: breaker, Negative: negative}

	tok, err := guarded.Acquire(context.Background(), rc)
	if err == nil {
		t.Fatalf("transient failure must deny")
	}
	if tok.Reveal() != "" {
		t.Fatalf("transient failure must not inject a token")
	}
	if !breaker.IsOpen() {
		t.Fatalf("transient failure must record a breaker failure")
	}
	if cached := negative.Get(token.CredID(rc)); cached != nil {
		t.Fatalf("transient failure must not populate the negative cache")
	}
}

func TestRuntimeTokenAcquirer_PermanentFailure_PopulatesNegativeCache(t *testing.T) {
	rc := testResolvedCredential(t)
	negative := token.NewNegativeCache(16, 30*time.Second)
	base := &fakeBaseAcquirer{err: &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "invalid_scope"}}
	guarded := runtimeTokenAcquirer{Base: base, Breaker: token.NewBreaker(5, 30), Negative: negative}

	if _, err := guarded.Acquire(context.Background(), rc); err == nil {
		t.Fatalf("permanent failure must deny")
	}
	if got := base.callCount(); got != 1 {
		t.Fatalf("base calls = %d, want 1", got)
	}
	if cached := negative.Get(token.CredID(rc)); cached == nil {
		t.Fatalf("permanent failure must populate the negative cache")
	}

	// Subsequent requests must be denied from the cache without calling base.
	if _, err := guarded.Acquire(context.Background(), rc); err == nil {
		t.Fatalf("subsequent request must deny from the negative cache")
	}
	if got := base.callCount(); got != 1 {
		t.Fatalf("base calls = %d after cached deny, want 1", got)
	}
}

func TestBreaker_ConcurrentFailures_OpenStateIsRaceFree(t *testing.T) {
	const goroutines = 64
	breaker := token.NewBreaker(goroutines, 30)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			breaker.RecordFailure(token.AcquireErrorTransient)
		}()
	}
	wg.Wait()

	if !breaker.IsOpen() {
		t.Fatalf("breaker should be open after %d concurrent transient failures", goroutines)
	}
}

func TestNegativeCache_ConcurrentGetPut_IsRaceFree(t *testing.T) {
	const goroutines = 64
	negative := token.NewNegativeCache(256, time.Minute)

	rc := testResolvedCredential(t)
	stableID := token.CredID(rc)
	stableErr := &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "invalid_scope"}
	negative.Put(stableID, stableErr)

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		id := stableID + string(rune('A'+(i%26)))
		go func() {
			defer wg.Done()
			negative.Put(id, &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "invalid_scope"})
		}()
		go func() {
			defer wg.Done()
			_ = negative.Get(id)
			_ = negative.Get(stableID)
		}()
	}
	wg.Wait()

	if cached := negative.Get(stableID); cached == nil || cached.Class != token.AcquireErrorPermanent {
		t.Fatalf("stable classified error not preserved under concurrent access: %v", cached)
	}
}

// TestRuntimeTokenAcquirer_NilDependency_FailsClosedWithoutPanic asserts that a
// misconfigured adapter (any of Base, Breaker, or Negative left nil) denies the
// request with a classified transient AcquireError instead of panicking. The
// struct has exported fields and no validating constructor, so nil dependencies
// are reachable; a panic would crash request handling rather than fail closed.
func TestRuntimeTokenAcquirer_NilDependency_FailsClosedWithoutPanic(t *testing.T) {
	rc := testResolvedCredential(t)
	base := &fakeBaseAcquirer{token: token.NewToken("access", time.Now().Add(time.Hour))}
	cases := []struct {
		name string
		a    runtimeTokenAcquirer
	}{
		{"nil base", runtimeTokenAcquirer{Breaker: token.NewBreaker(5, 30), Negative: token.NewNegativeCache(16, 30*time.Second)}},
		{"nil breaker", runtimeTokenAcquirer{Base: base, Negative: token.NewNegativeCache(16, 30*time.Second)}},
		{"nil negative", runtimeTokenAcquirer{Base: base, Breaker: token.NewBreaker(5, 30)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := tc.a.Acquire(context.Background(), rc)
			if err == nil {
				t.Fatalf("missing dependency must fail closed, got nil error")
			}
			var ae *token.AcquireError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %v, want *token.AcquireError", err)
			}
			if ae.Class != token.AcquireErrorTransient {
				t.Fatalf("class = %v, want transient (fail-closed, must not poison negative cache)", ae.Class)
			}
			if tok != (token.Token{}) {
				t.Fatalf("must not return a token when a dependency is missing")
			}
			if base.callCount() != 0 {
				t.Fatalf("must not invoke base acquirer when a dependency is missing")
			}
		})
	}
}
