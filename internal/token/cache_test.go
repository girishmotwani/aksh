package token_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/token"
)

type mockProvider struct {
	mu        sync.Mutex
	callCount int64
	result    token.Token
	err       error
	delay     time.Duration
}

func (m *mockProvider) Acquire(ctx context.Context, rc token.ResolvedCredential) (token.Token, error) {
	atomic.AddInt64(&m.callCount, 1)
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.result, m.err
}

func (m *mockProvider) calls() int64 {
	return atomic.LoadInt64(&m.callCount)
}

func TestCache_Miss_TriggersAcquisition(t *testing.T) {
	prov := &mockProvider{result: token.NewToken("tok1", time.Now().Add(time.Hour))}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 256})
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{".default"}}
	res, err := cache.Get(context.Background(), sel)
	if err != nil {
		t.Fatal(err)
	}
	if res.CacheHit {
		t.Error("first call should be a cache miss")
	}
	if prov.calls() != 1 {
		t.Errorf("provider called %d times, want 1", prov.calls())
	}
}

func TestCache_Hit_NoCalls(t *testing.T) {
	prov := &mockProvider{result: token.NewToken("tok1", time.Now().Add(time.Hour))}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 256})
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{".default"}}
	cache.Get(context.Background(), sel)
	res, err := cache.Get(context.Background(), sel)
	if err != nil {
		t.Fatal(err)
	}
	if !res.CacheHit {
		t.Error("second call should be a cache hit")
	}
	if prov.calls() != 1 {
		t.Errorf("provider called %d times, want 1", prov.calls())
	}
}

func TestCache_Expired_ReAcquires(t *testing.T) {
	prov := &mockProvider{result: token.NewToken("tok1", time.Now().Add(-time.Minute))}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 256})
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{".default"}}
	cache.Get(context.Background(), sel)
	prov.mu.Lock()
	prov.result = token.NewToken("tok2", time.Now().Add(time.Hour))
	prov.mu.Unlock()
	res, err := cache.Get(context.Background(), sel)
	if err != nil {
		t.Fatal(err)
	}
	if res.CacheHit {
		t.Error("expired token should trigger re-acquisition")
	}
	if prov.calls() != 2 {
		t.Errorf("provider called %d times, want 2", prov.calls())
	}
}

func TestCache_RefreshAhead_ServesWhileRefreshing(t *testing.T) {
	expiry := time.Now().Add(2 * time.Minute)
	prov := &mockProvider{
		result: token.NewToken("tok1", expiry),
		delay:  50 * time.Millisecond,
	}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 256})
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{".default"}}
	cache.Get(context.Background(), sel)
	prov.mu.Lock()
	prov.result = token.NewToken("tok-refreshed", time.Now().Add(time.Hour))
	prov.mu.Unlock()
	res, err := cache.Get(context.Background(), sel)
	if err != nil {
		t.Fatal(err)
	}
	if res.Token.Reveal() != "tok1" {
		t.Errorf("should serve original token during refresh, got %q", res.Token.Reveal())
	}
}

func TestCache_SingleFlight_SameKey(t *testing.T) {
	prov := &mockProvider{
		result: token.NewToken("tok1", time.Now().Add(time.Hour)),
		delay:  50 * time.Millisecond,
	}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 256})
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{".default"}}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache.Get(context.Background(), sel)
		}()
	}
	wg.Wait()
	if prov.calls() != 1 {
		t.Errorf("single-flight: provider called %d times, want 1", prov.calls())
	}
}

func TestCache_SingleFlight_DifferentKeys(t *testing.T) {
	prov := &mockProvider{
		result: token.NewToken("tok1", time.Now().Add(time.Hour)),
		delay:  20 * time.Millisecond,
	}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 256})
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{fmt.Sprintf("scope%d", i)}}
		go func(s token.CredentialSelector) {
			defer wg.Done()
			cache.Get(context.Background(), s)
		}(sel)
	}
	wg.Wait()
	if prov.calls() < 5 {
		t.Errorf("different keys: provider called %d times, want >= 5", prov.calls())
	}
}

func TestCache_FailedAcquisition_ReturnsError(t *testing.T) {
	prov := &mockProvider{err: &token.AcquireError{Class: token.AcquireErrorTransient, Message: "timeout"}}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 256})
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{".default"}}
	_, err := cache.Get(context.Background(), sel)
	if err == nil {
		t.Error("expected error on failed acquisition")
	}
}

func TestCache_TokenResult_CacheHit(t *testing.T) {
	prov := &mockProvider{result: token.NewToken("tok1", time.Now().Add(time.Hour))}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 256})
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{".default"}}
	r1, _ := cache.Get(context.Background(), sel)
	r2, _ := cache.Get(context.Background(), sel)
	if r1.CacheHit {
		t.Error("first should be miss")
	}
	if !r2.CacheHit {
		t.Error("second should be hit")
	}
}

func TestCache_LRU_Eviction(t *testing.T) {
	prov := &mockProvider{result: token.NewToken("tok", time.Now().Add(time.Hour))}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 3})
	for i := 0; i < 3; i++ {
		sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{fmt.Sprintf("s%d", i)}}
		cache.Get(context.Background(), sel)
	}
	sel4 := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{"s99"}}
	cache.Get(context.Background(), sel4)
	sel0 := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{"s0"}}
	res, _ := cache.Get(context.Background(), sel0)
	if res.CacheHit {
		t.Error("expected eviction of oldest entry")
	}
}

func TestCache_UsableLifetime_SkewMargin(t *testing.T) {
	prov := &mockProvider{result: token.NewToken("tok1", time.Now().Add(50*time.Second))}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 256})
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{".default"}}
	cache.Get(context.Background(), sel)
	prov.mu.Lock()
	prov.result = token.NewToken("tok2", time.Now().Add(time.Hour))
	prov.mu.Unlock()
	res, _ := cache.Get(context.Background(), sel)
	if res.CacheHit {
		t.Error("token within skew margin should be treated as expired")
	}
}

func TestCache_TokenUnderSkewMargin_Unusable(t *testing.T) {
	prov := &mockProvider{result: token.NewToken("unusable", time.Now().Add(30*time.Second))}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 256})
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{".default"}}
	_, err := cache.Get(context.Background(), sel)
	if err == nil {
		t.Error("token with <=60s remaining should be reported as unusable")
	}
}

func TestCache_RefreshWindow_Calculation(t *testing.T) {
	expiry := time.Now().Add(11 * time.Minute)
	prov := &mockProvider{result: token.NewToken("tok1", expiry)}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 256})
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{".default"}}
	cache.Get(context.Background(), sel)
	time.Sleep(100 * time.Millisecond)
	res, _ := cache.Get(context.Background(), sel)
	if res.Token.Reveal() != "tok1" {
		t.Error("should still serve original token")
	}
}

func TestCache_BackgroundRefreshFailure_StillServes(t *testing.T) {
	expiry := time.Now().Add(3 * time.Minute)
	prov := &mockProvider{result: token.NewToken("tok1", expiry)}
	cache := token.NewTokenCache(prov, token.CacheOptions{MaxEntries: 256})
	sel := token.CredentialSelector{Provider: "entra", Resource: "https://r.com", Scopes: []string{".default"}}
	cache.Get(context.Background(), sel)
	prov.mu.Lock()
	prov.err = &token.AcquireError{Class: token.AcquireErrorTransient, Message: "fail"}
	prov.result = token.Token{}
	prov.mu.Unlock()
	res, err := cache.Get(context.Background(), sel)
	if err != nil {
		t.Fatal("should serve cached token even if refresh fails")
	}
	if res.Token.Reveal() != "tok1" {
		t.Errorf("expected cached token, got %q", res.Token.Reveal())
	}
}
