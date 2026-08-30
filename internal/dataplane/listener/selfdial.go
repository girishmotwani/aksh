package listener

import (
	"net/netip"
	"sync"
)

// SelfDialRegistry tracks loopback tuples opened by the proxy itself so the
// accept loop can reject recursive self-dials before resolving the original
// destination.
type SelfDialRegistry struct {
	mu    sync.RWMutex
	addrs map[netip.AddrPort]struct{}
}

// NewSelfDialRegistry returns an empty registry.
func NewSelfDialRegistry() *SelfDialRegistry {
	return &SelfDialRegistry{
		addrs: make(map[netip.AddrPort]struct{}),
	}
}

// Add registers addr for future loop-guard checks. It lazily initializes the
// registry's internal map on first use, so a zero-value SelfDialRegistry{}
// (not constructed via NewSelfDialRegistry) is safe to call Add on rather
// than panicking with "assignment to entry in nil map".
func (r *SelfDialRegistry) Add(addr netip.AddrPort) error {
	if !addr.IsValid() {
		return ErrInvalidAddr
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.addrs == nil {
		r.addrs = make(map[netip.AddrPort]struct{})
	}
	r.addrs[addr] = struct{}{}
	return nil
}

// Contains reports whether addr is currently registered.
func (r *SelfDialRegistry) Contains(addr netip.AddrPort) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.addrs[addr]
	return ok
}

// Remove unregisters addr. Missing addresses are ignored.
func (r *SelfDialRegistry) Remove(addr netip.AddrPort) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.addrs, addr)
}
