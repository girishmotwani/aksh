package listener_test

import (
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/listener"
)

func TestSelfDialRegistry(t *testing.T) {
	t.Run("NewSelfDialRegistry_DefaultConstruction_ReturnsEmptyRegistry", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		if reg == nil {
			t.Fatalf("NewSelfDialRegistry() = nil, want non-nil registry")
		}
		if reg.Contains(netip.MustParseAddrPort("127.0.0.1:15001")) {
			t.Fatalf("Contains() = true for empty registry, want false")
		}
	})

	t.Run("Add_ThenContains_ReturnsTrueForAddedAddress", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		addr := netip.MustParseAddrPort("127.0.0.1:15001")
		if err := reg.Add(addr); err != nil {
			t.Fatalf("Add() error = %v, want nil", err)
		}
		if !reg.Contains(addr) {
			t.Fatalf("Contains(%v) = false, want true", addr)
		}
	})

	t.Run("Contains_AddressNeverAdded_ReturnsFalse", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		if reg.Contains(netip.MustParseAddrPort("127.0.0.1:15001")) {
			t.Fatalf("Contains() = true, want false")
		}
	})

	t.Run("Remove_PreviouslyAddedAddress_ContainsReturnsFalseAfter", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		addr := netip.MustParseAddrPort("127.0.0.1:15001")
		if err := reg.Add(addr); err != nil {
			t.Fatalf("Add() error = %v, want nil", err)
		}
		reg.Remove(addr)
		if reg.Contains(addr) {
			t.Fatalf("Contains(%v) = true after Remove, want false", addr)
		}
	})

	t.Run("Remove_AddressNeverAdded_IsNoOpWithoutPanic", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		reg.Remove(netip.MustParseAddrPort("127.0.0.1:15001"))
	})

	t.Run("Add_ZeroValueAddrPort_ReturnsErrInvalidAddr", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		if err := reg.Add(netip.AddrPort{}); err != listener.ErrInvalidAddr {
			t.Fatalf("Add(zero) error = %v, want %v", err, listener.ErrInvalidAddr)
		}
	})

	t.Run("ZeroValueRegistry_AddThenContains_WorksWithoutPanic", func(t *testing.T) {
		// Regression test for the dev-review finding that a zero-value
		// SelfDialRegistry{} (constructed without NewSelfDialRegistry, e.g.
		// as a struct field default) panics with "assignment to entry in
		// nil map" on Add, because addrs is only initialized in the
		// constructor. Add must lazily initialize addrs so the zero value is
		// safe to use directly.
		var reg listener.SelfDialRegistry
		addr := netip.MustParseAddrPort("127.0.0.1:15099")
		if err := reg.Add(addr); err != nil {
			t.Fatalf("Add() on zero-value registry error = %v, want nil", err)
		}
		if !reg.Contains(addr) {
			t.Fatalf("Contains() = false after Add() on zero-value registry, want true")
		}
	})

	t.Run("Contains_ConcurrentReadsWhileWriting_NoDataRace", func(t *testing.T) {
		// This test only detects data races when run with `go test -race`;
		// without it, a genuine race in Contains/Add/Remove's synchronization
		// would pass silently. A readersReady barrier ensures all reader
		// goroutines are actively calling Contains before the writer begins
		// mutating, so the race window is exercised from the first write
		// rather than possibly completing before readers even start.
		reg := listener.NewSelfDialRegistry()
		addr := netip.MustParseAddrPort("127.0.0.1:15001")
		stop := make(chan struct{})
		var wg sync.WaitGroup
		numReaders := runtime.GOMAXPROCS(0)
		var readersReady sync.WaitGroup
		readersReady.Add(numReaders)

		for range numReaders {
			wg.Add(1)
			go func() {
				defer wg.Done()
				readersReady.Done()
				for {
					select {
					case <-stop:
						return
					default:
						_ = reg.Contains(addr)
					}
				}
			}()
		}

		readersReady.Wait()

		for i := 0; i < 1000; i++ {
			if err := reg.Add(addr); err != nil {
				t.Fatalf("Add() error = %v, want nil", err)
			}
			reg.Remove(addr)
		}

		close(stop)
		wg.Wait()
	})

	t.Run("Add_SameAddressTwice_IsIdempotent", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		addr := netip.MustParseAddrPort("127.0.0.1:15001")
		if err := reg.Add(addr); err != nil {
			t.Fatalf("first Add() error = %v, want nil", err)
		}
		if err := reg.Add(addr); err != nil {
			t.Fatalf("second Add() error = %v, want nil", err)
		}
		reg.Remove(addr)
		if reg.Contains(addr) {
			t.Fatalf("Contains(%v) = true after one Remove, want false", addr)
		}
	})

	t.Run("Contains_UsedByDirectDialerLoopGuard_ReturnsTrueBeforeSocketCreated", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		addr := netip.MustParseAddrPort("127.0.0.1:15001")
		if err := reg.Add(addr); err != nil {
			t.Fatalf("Add() error = %v, want nil", err)
		}
		if !reg.Contains(addr) {
			t.Fatalf("Contains(%v) = false, want true", addr)
		}
	})

	t.Run("Add_ManyDistinctAddresses_AllIndependentlyRetrievable", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		for i := 0; i < 100; i++ {
			addr := netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(20000+i))
			if err := reg.Add(addr); err != nil {
				t.Fatalf("Add(%v) error = %v, want nil", addr, err)
			}
		}
		for i := 0; i < 100; i++ {
			addr := netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(20000+i))
			if !reg.Contains(addr) {
				t.Fatalf("Contains(%v) = false, want true", addr)
			}
		}
		if reg.Contains(netip.MustParseAddrPort("127.0.0.1:31000")) {
			t.Fatalf("Contains(disjoint) = true, want false")
		}
	})

	t.Run("Remove_DuringConcurrentContainsCalls_EventuallyConsistent", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		addr := netip.MustParseAddrPort("127.0.0.1:15001")
		if err := reg.Add(addr); err != nil {
			t.Fatalf("Add() error = %v, want nil", err)
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_ = reg.Contains(addr)
			}()
		}
		close(start)
		reg.Remove(addr)
		wg.Wait()
		if reg.Contains(addr) {
			t.Fatalf("Contains(%v) = true after Remove returns, want false", addr)
		}
	})

	// Add_RepeatedAddRemoveChurn_MemoryDoesNotGrowUnbounded is the exact test
	// name specified in docs/design/S1a-dataplane-capture.md and
	// must not be renamed. Note that this
	// black-box test only proves Contains() correctness after churn, not
	// that memory/map size stays bounded -- that direct verification lives
	// in the white-box TestSelfDialRegistry_RepeatedAddRemoveChurn_MapSizeStaysBounded
	// test in selfdial_internal_test.go, which inspects the unexported
	// addrs map length directly.
	t.Run("Add_RepeatedAddRemoveChurn_MemoryDoesNotGrowUnbounded", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		addrs := []netip.AddrPort{
			netip.MustParseAddrPort("127.0.0.1:15001"),
			netip.MustParseAddrPort("127.0.0.1:15002"),
			netip.MustParseAddrPort("127.0.0.1:15003"),
			netip.MustParseAddrPort("127.0.0.1:15004"),
		}
		for i := 0; i < 1000; i++ {
			addr := addrs[i%len(addrs)]
			if err := reg.Add(addr); err != nil {
				t.Fatalf("Add(%v) error = %v, want nil", addr, err)
			}
			reg.Remove(addr)
		}
		for _, addr := range addrs {
			if reg.Contains(addr) {
				t.Fatalf("Contains(%v) = true after churn, want false", addr)
			}
		}
	})
}
