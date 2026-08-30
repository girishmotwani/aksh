//go:build !race

package listener

import "testing"

// TestClassifyBytes_H2CPrefaceMatch_DoesNotAllocate is a regression test for
// the dev-review finding that classifyBytes's H2C-preface check did
// string(b[:len(h2cPreface)]) == h2cPreface, allocating a new heap string on
// every connection reaching this hot path. The comparison is now done via
// bytes.Equal against a package-level []byte instead, with zero
// allocations under the normal (non-race) build.
//
// This test is gated with `//go:build !race` (dev-review finding,
// discriminator_internal_test.go:82): -race's own instrumentation
// allocates bookkeeping state around every memory access, which made a
// tolerant `allocs > 1` threshold vacuous (unable to catch a real
// 1-alloc/op regression) while still risking flakes under -race. Confining
// this test to non-race builds lets it assert the strict `allocs > 0`
// bound directly, with no tolerance needed for either problem.
func TestClassifyBytes_H2CPrefaceMatch_DoesNotAllocate(t *testing.T) {
	b := []byte(h2cPreface)
	// The correctness check is deliberately outside the AllocsPerRun
	// closure: calling t.Fatalf from inside it would itself allocate
	// (formatting + panic/goroutine bookkeeping), poisoning the very
	// measurement this test exists to make.
	if classifyBytes(b) != ProtocolH2CPreface {
		t.Fatalf("classifyBytes(h2cPreface) != ProtocolH2CPreface")
	}
	allocs := testing.AllocsPerRun(100, func() {
		_ = classifyBytes(b)
	})
	if allocs > 0 {
		t.Fatalf("classifyBytes(h2cPreface) allocated %.0f times per call, want 0", allocs)
	}
}
