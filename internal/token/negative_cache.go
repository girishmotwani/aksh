package token

import (
	"container/list"
	"sync"
	"time"
)

type negativeCacheEntry struct {
	id        string
	err       *AcquireError
	expiresAt time.Time
}

// NegativeCache stores recent acquisition failures with TTL and LRU eviction.
type NegativeCache struct {
	mu         sync.Mutex
	maxEntries int
	ttl        time.Duration
	// entries points into ll; keeping both in sync gives O(1) lookup and LRU
	// updates while bounding failure state an agent can cause us to retain.
	ll      *list.List
	entries map[string]*list.Element
}

// NewNegativeCache creates a new negative cache.
func NewNegativeCache(maxEntries int, ttl time.Duration) *NegativeCache {
	if maxEntries <= 0 {
		maxEntries = 1
	}
	return &NegativeCache{
		maxEntries: maxEntries,
		ttl:        ttl,
		ll:         list.New(),
		entries:    make(map[string]*list.Element, maxEntries),
	}
}

// Get returns a cached error if it is still valid.
func (nc *NegativeCache) Get(id string) *AcquireError {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	elem := nc.entries[id]
	if elem == nil {
		return nil
	}

	entry := elem.Value.(*negativeCacheEntry)
	if nc.ttl > 0 && time.Now().After(entry.expiresAt) {
		// Expired failures are removed eagerly so an operator's configuration
		// fix can be retried instead of remaining hidden behind stale state.
		nc.removeElement(elem)
		return nil
	}

	nc.ll.MoveToFront(elem)
	return entry.err
}

// Put stores an acquisition error in the cache.
func (nc *NegativeCache) Put(id string, err *AcquireError) {
	if id == "" || err == nil {
		return
	}

	nc.mu.Lock()
	defer nc.mu.Unlock()

	if elem := nc.entries[id]; elem != nil {
		entry := elem.Value.(*negativeCacheEntry)
		entry.err = err
		entry.expiresAt = time.Now().Add(nc.ttl)
		nc.ll.MoveToFront(elem)
		return
	}

	elem := nc.ll.PushFront(&negativeCacheEntry{
		id:        id,
		err:       err,
		expiresAt: time.Now().Add(nc.ttl),
	})
	nc.entries[id] = elem

	for nc.ll.Len() > nc.maxEntries {
		nc.removeElement(nc.ll.Back())
	}
}

func (nc *NegativeCache) removeElement(elem *list.Element) {
	if elem == nil {
		return
	}
	// Remove from both indexes together to preserve the LRU lookup invariant.
	nc.ll.Remove(elem)
	entry := elem.Value.(*negativeCacheEntry)
	delete(nc.entries, entry.id)
}
