package listener

import (
	"net/netip"
	"testing"
)

// TestSelfDialRegistry_RepeatedAddRemoveChurn_MapSizeStaysBounded is a
// regression test for the dev-review finding that the black-box
// Add_RepeatedAddRemoveChurn_MemoryDoesNotGrowUnbounded test (in
// selfdial_test.go) never actually measured memory or map size -- it only
// checked Contains() returns false after churn, which is consistent with
// (but does not prove) a bounded-size map. This white-box test directly
// inspects the unexported addrs map length after churn across many distinct
// addresses, proving the map does not retain stale entries.
func TestSelfDialRegistry_RepeatedAddRemoveChurn_MapSizeStaysBounded(t *testing.T) {
	reg := NewSelfDialRegistry()
	const distinctAddrs = 4
	const churnIterations = 1000

	for i := 0; i < churnIterations; i++ {
		port := uint16(15001 + i%distinctAddrs)
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port)
		if err := reg.Add(addr); err != nil {
			t.Fatalf("Add() error = %v, want nil", err)
		}
		reg.Remove(addr)
	}

	reg.mu.RLock()
	size := len(reg.addrs)
	reg.mu.RUnlock()

	if size != 0 {
		t.Fatalf("len(reg.addrs) = %d after churn, want 0 (no stale entries retained)", size)
	}
}
