package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/token"
)

// guardedFor builds a guarded acquirer with a caller-chosen breaker threshold so
// isolation tests are deterministic, mirroring newGuardedAcquirer's wiring but
// with an explicit threshold.
func guardedFor(base token.TokenAcquirer, threshold int) runtimeTokenAcquirer {
	return runtimeTokenAcquirer{
		Base:     base,
		Breaker:  token.NewBreaker(threshold, 30),
		Negative: token.NewNegativeCache(16, 30*time.Second),
	}
}

// TestProviderIsolation_EntraBreakerOpen_DoesNotBlockStatic is the core
// regression test for the shared-breaker coupling: an Entra outage that trips
// Entra's breaker must not deny static reads. With one shared breaker (the old
// wiring) the static request would have been denied "breaker open".
func TestProviderIsolation_EntraBreakerOpen_DoesNotBlockStatic(t *testing.T) {
	entraBase := &fakeBaseAcquirer{err: &token.AcquireError{Class: token.AcquireErrorTransient, Message: "5xx"}}
	staticBase := &fakeBaseAcquirer{token: token.NewToken("sk-static", time.Now().Add(time.Hour))}

	entraGuard := guardedFor(entraBase, 1) // opens after one transient failure
	staticGuard := guardedFor(staticBase, 1)
	d := providerDispatchAcquirer{Entra: entraGuard, Static: staticGuard}

	// Trip Entra's breaker.
	if _, err := d.Acquire(context.Background(), resolveProvider(t, "entra", "https://vault.example.com")); err == nil {
		t.Fatalf("entra transient failure should have returned an error")
	}
	if !entraGuard.Breaker.IsOpen() {
		t.Fatalf("precondition: entra breaker should be open")
	}
	if staticGuard.Breaker.IsOpen() {
		t.Fatalf("static breaker must not open from an entra failure")
	}

	// Static must still succeed despite Entra's open breaker.
	tok, err := d.Acquire(context.Background(), resolveProvider(t, "static", "openai-api-key"))
	if err != nil {
		t.Fatalf("static request denied while entra breaker open: %v", err)
	}
	if tok.Reveal() != "sk-static" {
		t.Fatalf("static returned wrong token")
	}
	if staticBase.callCount() != 1 {
		t.Fatalf("static base calls = %d, want 1 (static not gated by entra breaker)", staticBase.callCount())
	}
}

// TestProviderIsolation_StaticBreakerOpen_DoesNotBlockEntra is the symmetric
// case: a static outage must not deny Entra exchanges.
func TestProviderIsolation_StaticBreakerOpen_DoesNotBlockEntra(t *testing.T) {
	staticBase := &fakeBaseAcquirer{err: &token.AcquireError{Class: token.AcquireErrorTransient, Message: "mount flaky"}}
	entraBase := &fakeBaseAcquirer{token: token.NewToken("entra-tok", time.Now().Add(time.Hour))}

	entraGuard := guardedFor(entraBase, 1)
	staticGuard := guardedFor(staticBase, 1)
	d := providerDispatchAcquirer{Entra: entraGuard, Static: staticGuard}

	if _, err := d.Acquire(context.Background(), resolveProvider(t, "static", "openai-api-key")); err == nil {
		t.Fatalf("static transient failure should have returned an error")
	}
	if !staticGuard.Breaker.IsOpen() {
		t.Fatalf("precondition: static breaker should be open")
	}
	if entraGuard.Breaker.IsOpen() {
		t.Fatalf("entra breaker must not open from a static failure")
	}

	tok, err := d.Acquire(context.Background(), resolveProvider(t, "entra", "https://vault.example.com"))
	if err != nil {
		t.Fatalf("entra request denied while static breaker open: %v", err)
	}
	if tok.Reveal() != "entra-tok" {
		t.Fatalf("entra returned wrong token")
	}
}

// TestProviderIsolation_StaticPermanentFailure_DoesNotPoisonEntra proves the
// negative caches are isolated: a permanent static failure is cached for static
// only, and Entra continues to acquire successfully.
func TestProviderIsolation_StaticPermanentFailure_DoesNotPoisonEntra(t *testing.T) {
	staticBase := &fakeBaseAcquirer{err: &token.AcquireError{Class: token.AcquireErrorPermanent, Message: "empty token file"}}
	entraBase := &fakeBaseAcquirer{token: token.NewToken("entra-tok", time.Now().Add(time.Hour))}

	entraGuard := guardedFor(entraBase, 5)
	staticGuard := guardedFor(staticBase, 5)
	d := providerDispatchAcquirer{Entra: entraGuard, Static: staticGuard}

	staticRC := resolveProvider(t, "static", "openai-api-key")
	entraRC := resolveProvider(t, "entra", "https://vault.example.com")

	if _, err := d.Acquire(context.Background(), staticRC); err == nil {
		t.Fatalf("static permanent failure should have returned an error")
	}
	if staticGuard.Negative.Get(token.CredID(staticRC)) == nil {
		t.Fatalf("static permanent failure must populate the static negative cache")
	}
	if entraGuard.Negative.Get(token.CredID(staticRC)) != nil {
		t.Fatalf("static failure must not appear in entra's negative cache")
	}

	// Entra still works, unaffected by the static permanent failure.
	if _, err := d.Acquire(context.Background(), entraRC); err != nil {
		t.Fatalf("entra denied after static permanent failure: %v", err)
	}
	if entraBase.callCount() != 1 {
		t.Fatalf("entra base calls = %d, want 1", entraBase.callCount())
	}

	// A repeat static request is served from the static negative cache without
	// hitting its base again — confirming the cache is per-provider and live.
	if _, err := d.Acquire(context.Background(), staticRC); err == nil {
		t.Fatalf("repeat static request should deny from the negative cache")
	}
	if staticBase.callCount() != 1 {
		t.Fatalf("static base calls = %d, want 1 (second denied from cache)", staticBase.callCount())
	}
}

// TestNewGuardedAcquirer_ProducesIndependentInstances proves the assemble()
// helper hands each provider its own breaker and negative cache (distinct
// pointers), which is what makes the isolation above hold in production wiring.
func TestNewGuardedAcquirer_ProducesIndependentInstances(t *testing.T) {
	a := newGuardedAcquirer(&fakeBaseAcquirer{})
	b := newGuardedAcquirer(&fakeBaseAcquirer{})
	if a.Breaker == b.Breaker {
		t.Fatalf("guarded acquirers share a breaker instance")
	}
	if a.Negative == b.Negative {
		t.Fatalf("guarded acquirers share a negative cache instance")
	}
	if a.Breaker == nil || a.Negative == nil {
		t.Fatalf("newGuardedAcquirer must populate breaker and negative cache")
	}
}

// TestProviderIsolation_EntraSuccessDoesNotResetStaticBreaker proves a
// successful Entra exchange (which resets Entra's breaker) does not reset
// static's independent breaker state.
func TestProviderIsolation_EntraSuccessDoesNotResetStaticBreaker(t *testing.T) {
	entraBase := &fakeBaseAcquirer{token: token.NewToken("entra-tok", time.Now().Add(time.Hour))}
	staticBase := &fakeBaseAcquirer{err: &token.AcquireError{Class: token.AcquireErrorTransient, Message: "flaky"}}

	entraGuard := guardedFor(entraBase, 5)
	staticGuard := guardedFor(staticBase, 2)
	d := providerDispatchAcquirer{Entra: entraGuard, Static: staticGuard}

	staticRC := resolveProvider(t, "static", "openai-api-key")
	// One static transient failure: below threshold (2), breaker not yet open.
	if _, err := d.Acquire(context.Background(), staticRC); err == nil {
		t.Fatalf("static transient failure expected")
	}

	// A successful entra exchange resets entra's breaker only.
	if _, err := d.Acquire(context.Background(), resolveProvider(t, "entra", "https://vault.example.com")); err != nil {
		t.Fatalf("entra success expected: %v", err)
	}

	// A second static failure must still open static's breaker: entra's success
	// did not reset static's failure count.
	if _, err := d.Acquire(context.Background(), staticRC); err == nil {
		t.Fatalf("second static transient failure expected")
	}
	if !staticGuard.Breaker.IsOpen() {
		t.Fatalf("static breaker should be open after two failures; entra success must not reset it")
	}
}
