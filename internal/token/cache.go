package token

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"
)

const tokenSkewMargin = 60 * time.Second

// TokenAcquirer acquires a token for a resolved credential.
type TokenAcquirer interface {
	Acquire(ctx context.Context, rc ResolvedCredential) (Token, error)
}

// CacheOptions configures the token cache.
type CacheOptions struct {
	MaxEntries int
}

type cacheEntry struct {
	id          string
	resolved    ResolvedCredential
	token       Token
	usableUntil time.Time
	refreshAt   time.Time
}

type acquireCall struct {
	done     chan struct{}
	token    Token
	err      error
	resolved ResolvedCredential
}

// CachingTokenCache caches acquired tokens with refresh-ahead and single-flight behavior.
type CachingTokenCache struct {
	provider   TokenAcquirer
	maxEntries int

	mu sync.Mutex
	// entries points into ll; every mutation must update both while mu is held.
	ll      *list.List
	entries map[string]*list.Element
	// inflight and refreshing independently single-flight blocking misses and
	// best-effort refreshes for each canonical credential identity.
	inflight   map[string]*acquireCall
	refreshing map[string]bool
}

// NewTokenCache creates a caching token broker.
func NewTokenCache(provider TokenAcquirer, opts CacheOptions) *CachingTokenCache {
	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 1
	}
	return &CachingTokenCache{
		provider:   provider,
		maxEntries: maxEntries,
		ll:         list.New(),
		entries:    make(map[string]*list.Element, maxEntries),
		inflight:   make(map[string]*acquireCall),
		refreshing: make(map[string]bool),
	}
}

// Get returns a token for the given selector, acquiring and caching as needed.
func (c *CachingTokenCache) Get(ctx context.Context, sel CredentialSelector) (TokenResult, error) {
	resolved, err := Resolve(sel)
	if err != nil {
		return TokenResult{}, err
	}

	now := time.Now()
	if result, ok := c.getCached(resolved.Identity, now); ok {
		return c.maybeRefresh(ctx, resolved, result, now), nil
	}

	call, leader := c.startAcquire(resolved.Identity)
	if leader {
		c.finishAcquire(ctx, call, resolved)
	} else {
		// A waiter may abandon its own request without cancelling the shared
		// acquisition, which may still satisfy other callers for this identity.
		select {
		case <-ctx.Done():
			return TokenResult{}, ctx.Err()
		case <-call.done:
		}
	}

	if call.err != nil {
		return TokenResult{}, call.err
	}

	return TokenResult{
		Token:    call.token,
		Resolved: call.resolved,
		CacheHit: false,
	}, nil
}

func (c *CachingTokenCache) getCached(id string, now time.Time) (TokenResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem := c.entries[id]
	if elem == nil {
		return TokenResult{}, false
	}

	entry := elem.Value.(*cacheEntry)
	// usableUntil already includes the clock-skew margin. Removing the entry
	// here ensures no later path can accidentally serve the raw expiry window.
	if !now.Before(entry.usableUntil) {
		c.removeElement(elem)
		return TokenResult{}, false
	}

	c.ll.MoveToFront(elem)
	return TokenResult{
		Token:    entry.token,
		Resolved: entry.resolved,
		CacheHit: true,
	}, true
}

func (c *CachingTokenCache) maybeRefresh(ctx context.Context, resolved ResolvedCredential, result TokenResult, now time.Time) TokenResult {
	c.mu.Lock()
	elem := c.entries[resolved.Identity]
	shouldRefresh := false
	if elem != nil {
		entry := elem.Value.(*cacheEntry)
		shouldRefresh = !c.refreshing[resolved.Identity] && !now.Before(entry.refreshAt)
		if shouldRefresh {
			c.refreshing[resolved.Identity] = true
		}
	}
	c.mu.Unlock()

	if shouldRefresh {
		// Refresh is detached from the request: the caller already has a usable
		// token, and its cancellation should not discard work for future calls.
		go c.backgroundRefresh(resolved)
	}

	return result
}

func (c *CachingTokenCache) backgroundRefresh(resolved ResolvedCredential) {
	defer func() {
		c.mu.Lock()
		delete(c.refreshing, resolved.Identity)
		c.mu.Unlock()
	}()

	token, err := c.provider.Acquire(context.Background(), resolved)
	if err != nil {
		// A failed refresh must not evict the still-usable token that triggered it.
		return
	}

	usableUntil := token.ExpiresAt().Add(-tokenSkewMargin)
	now := time.Now()
	if !usableUntil.After(now) {
		return
	}

	c.store(resolved.Identity, resolved, token, usableUntil, now)
}

func (c *CachingTokenCache) startAcquire(id string) (*acquireCall, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if call := c.inflight[id]; call != nil {
		return call, false
	}

	// Lookup and reservation are one critical section; otherwise two misses can
	// both become leaders before either publishes its call.
	call := &acquireCall{done: make(chan struct{})}
	c.inflight[id] = call
	return call, true
}

func (c *CachingTokenCache) finishAcquire(ctx context.Context, call *acquireCall, resolved ResolvedCredential) {
	token, err := c.provider.Acquire(ctx, resolved)
	call.resolved = resolved
	if err == nil {
		usableUntil := token.ExpiresAt().Add(-tokenSkewMargin)
		now := time.Now()
		if !usableUntil.After(now) {
			err = fmt.Errorf("acquired token is unusable: expires within skew margin")
		} else {
			call.token = token
			c.store(resolved.Identity, resolved, token, usableUntil, now)
		}
	}
	call.err = err

	// Publish the result before closing done. Channel close synchronizes these
	// writes with every waiter, so all callers observe the same acquisition.
	c.mu.Lock()
	delete(c.inflight, resolved.Identity)
	c.mu.Unlock()
	close(call.done)
}

func (c *CachingTokenCache) store(id string, resolved ResolvedCredential, token Token, usableUntil, now time.Time) {
	// Refresh timing is derived from the skew-adjusted lifetime, not the token's
	// advertised expiry, so refresh-ahead never consumes the safety margin.
	refreshWindow := computeRefreshWindow(usableUntil.Sub(now))
	entry := &cacheEntry{
		id:          id,
		resolved:    resolved,
		token:       token,
		usableUntil: usableUntil,
		refreshAt:   usableUntil.Add(-refreshWindow),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if elem := c.entries[id]; elem != nil {
		elem.Value = entry
		c.ll.MoveToFront(elem)
	} else {
		c.entries[id] = c.ll.PushFront(entry)
	}

	for c.ll.Len() > c.maxEntries {
		c.removeElement(c.ll.Back())
	}
}

func computeRefreshWindow(usableLifetime time.Duration) time.Duration {
	if usableLifetime <= 0 {
		return 0
	}

	twentyPercent := usableLifetime / 5
	minWindow := 5 * time.Minute
	maxWindow := usableLifetime / 2

	window := twentyPercent
	if window < minWindow {
		window = minWindow
	}
	if window > maxWindow {
		window = maxWindow
	}
	return window
}

func (c *CachingTokenCache) removeElement(elem *list.Element) {
	if elem == nil {
		return
	}
	// Centralizing removal preserves the list/map one-to-one invariant used for
	// O(1) lookup, recency updates, and eviction.
	c.ll.Remove(elem)
	entry := elem.Value.(*cacheEntry)
	delete(c.entries, entry.id)
}
