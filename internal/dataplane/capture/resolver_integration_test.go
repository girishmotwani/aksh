//go:build linux && ebpf_integration

package capture

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

// --- test doubles and helpers ---------------------------------------------

// fakeConn is a net.Conn whose only meaningful method is RemoteAddr; Resolve
// touches nothing else. The embedded nil net.Conn makes the remaining methods
// present without being exercised.
type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeConn) RemoteAddr() net.Addr { return c.remote }

func connFor(ap netip.AddrPort) net.Conn {
	return fakeConn{remote: net.TCPAddrFromAddrPort(ap)}
}

type decisionCall struct {
	disposition pipeline.Disposition
	reason      pipeline.DenyReason
	transport   audit.TransportKind
	fault       bool
}

// metricsSpy records Decisions calls so a test can assert the resolver reported
// a rejection quietly (fault=false) and never on the alerting path.
type metricsSpy struct {
	audit.NopMetricsRecorder
	mu        sync.Mutex
	decisions []decisionCall
}

func (m *metricsSpy) Decisions(d pipeline.Disposition, r pipeline.DenyReason, tr audit.TransportKind, fault bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions = append(m.decisions, decisionCall{d, r, tr, fault})
}

func (m *metricsSpy) calls() []decisionCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]decisionCall, len(m.decisions))
	copy(out, m.decisions)
	return out
}

// newPairMap creates a real LRU-hash map mirroring pair_orig_dst
// (key pair_key = 8 bytes, value orig_dst = 24 bytes; design §6.4.2).
func newPairMap(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "pair_orig_dst",
		Type:       ebpf.LRUHash,
		KeySize:    8,
		ValueSize:  24,
		MaxEntries: 16384,
	})
	if err != nil {
		t.Fatalf("ebpf.NewMap(pair_orig_dst): %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func pairKeyFor(peer netip.AddrPort) akshPairKey {
	a4 := peer.Addr().Unmap().As4()
	return akshPairKey{IP: binary.NativeEndian.Uint32(a4[:]), Port: uint32(peer.Port())}
}

// valueFor builds an orig_dst record: IPv4 destination, network-order port,
// DST_IPV4 flag set, the calling uid and a monotonic stamp.
func valueFor(dst netip.AddrPort, uid uint32, stampNS uint64) akshPairValue {
	a4 := dst.Addr().Unmap().As4()
	return akshPairValue{
		IP:      binary.NativeEndian.Uint32(a4[:]),
		Port:    htons(dst.Port()),
		Flags:   dstIPv4,
		UID:     uid,
		StampNS: stampNS,
	}
}

func putEntry(t *testing.T, m *ebpf.Map, peer netip.AddrPort, val akshPairValue) {
	t.Helper()
	key := pairKeyFor(peer)
	if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Fatalf("map update: %v", err)
	}
}

const (
	testProxyUID uint32 = 1774
	testMaxAge          = 15 * time.Second
	// testNow is a fixed CLOCK_MONOTONIC reading (1000 s) used as the freshness
	// reference so staleness is deterministic and never touches the wall clock.
	testNow uint64 = 1_000_000_000_000
)

func newResolver(t *testing.T, m *ebpf.Map, now func() uint64, metrics audit.MetricsRecorder) *BPFDestinationResolver {
	t.Helper()
	r, err := NewBPFDestinationResolver(m, Options{
		ProxyUID:   testProxyUID,
		DestMaxAge: testMaxAge,
		Metrics:    metrics,
	})
	if err != nil {
		t.Fatalf("NewBPFDestinationResolver: %v", err)
	}
	if now != nil {
		r.now = now
	}
	return r
}

func fixedNow(v uint64) func() uint64 { return func() uint64 { return v } }

// --- tests -----------------------------------------------------------------

func TestBPFDestinationResolver(t *testing.T) {
	t.Run("NewBPFDestinationResolver_NilPairMap_ReturnsErrMissingMap", func(t *testing.T) {
		r, err := NewBPFDestinationResolver(nil, Options{
			ProxyUID:   testProxyUID,
			DestMaxAge: testMaxAge,
			Metrics:    audit.NopMetricsRecorder{},
		})
		if !errors.Is(err, ErrMissingMap) {
			t.Fatalf("error = %v, want ErrMissingMap", err)
		}
		if r != nil {
			t.Fatalf("resolver = %+v, want nil", r)
		}
	})

	t.Run("NewBPFDestinationResolver_ZeroMaxAge_ReturnsErrInvalidMaxAge", func(t *testing.T) {
		m := newPairMap(t)
		r, err := NewBPFDestinationResolver(m, Options{
			ProxyUID:   testProxyUID,
			DestMaxAge: 0,
			Metrics:    audit.NopMetricsRecorder{},
		})
		if !errors.Is(err, ErrInvalidMaxAge) {
			t.Fatalf("error = %v, want ErrInvalidMaxAge", err)
		}
		if r != nil {
			t.Fatalf("resolver = %+v, want nil", r)
		}
	})

	t.Run("NewBPFDestinationResolver_NilMetricsRecorder_ReturnsErrMissingMetrics", func(t *testing.T) {
		m := newPairMap(t)
		r, err := NewBPFDestinationResolver(m, Options{
			ProxyUID:   testProxyUID,
			DestMaxAge: testMaxAge,
			Metrics:    nil,
		})
		if !errors.Is(err, ErrMissingMetrics) {
			t.Fatalf("error = %v, want ErrMissingMetrics", err)
		}
		if r != nil {
			t.Fatalf("resolver = %+v, want nil", r)
		}
	})

	t.Run("NewBPFDestinationResolver_ValidArgs_ReturnsResolver", func(t *testing.T) {
		m := newPairMap(t)
		r, err := NewBPFDestinationResolver(m, Options{
			ProxyUID:   testProxyUID,
			DestMaxAge: testMaxAge,
			Metrics:    audit.NopMetricsRecorder{},
		})
		if err != nil {
			t.Fatalf("error = %v, want nil", err)
		}
		if r == nil {
			t.Fatalf("resolver = nil, want non-nil")
		}
	})

	t.Run("Resolve_MapHit_ReturnsOriginalDestination", func(t *testing.T) {
		m := newPairMap(t)
		r := newResolver(t, m, fixedNow(testNow), audit.NopMetricsRecorder{})

		peer := netip.MustParseAddrPort("10.0.0.5:40000")
		dst := netip.MustParseAddrPort("93.184.216.34:443")
		putEntry(t, m, peer, valueFor(dst, 65534, testNow))

		got, err := r.Resolve(connFor(peer))
		if err != nil {
			t.Fatalf("Resolve error = %v, want nil", err)
		}
		if got != dst {
			t.Fatalf("Resolve = %v, want %v", got, dst)
		}
	})

	t.Run("Resolve_MapMiss_ReturnsErrNoOriginalDst", func(t *testing.T) {
		m := newPairMap(t)
		r := newResolver(t, m, fixedNow(testNow), audit.NopMetricsRecorder{})

		peer := netip.MustParseAddrPort("10.0.0.9:41000")
		_, err := r.Resolve(connFor(peer))
		if !errors.Is(err, ErrNoOriginalDestination) {
			t.Fatalf("Resolve error = %v, want ErrNoOriginalDst", err)
		}
	})

	t.Run("Resolve_UsesLookupAndDeleteNotLookup_EntryConsumedOnFirstCall", func(t *testing.T) {
		m := newPairMap(t)
		r := newResolver(t, m, fixedNow(testNow), audit.NopMetricsRecorder{})

		peer := netip.MustParseAddrPort("10.0.0.6:40001")
		dst := netip.MustParseAddrPort("93.184.216.34:443")
		putEntry(t, m, peer, valueFor(dst, 65534, testNow))

		if _, err := r.Resolve(connFor(peer)); err != nil {
			t.Fatalf("first Resolve error = %v, want nil", err)
		}
		if _, err := r.Resolve(connFor(peer)); !errors.Is(err, ErrNoOriginalDestination) {
			t.Fatalf("second Resolve error = %v, want ErrNoOriginalDst (entry not consumed)", err)
		}
	})

	t.Run("Resolve_StaleEntryOlderThanMaxAge_ReturnsErrNoOriginalDst", func(t *testing.T) {
		m := newPairMap(t)
		r := newResolver(t, m, fixedNow(testNow), audit.NopMetricsRecorder{})

		peer := netip.MustParseAddrPort("10.0.0.7:40002")
		dst := netip.MustParseAddrPort("93.184.216.34:443")
		stale := testNow - uint64(20*time.Second)
		putEntry(t, m, peer, valueFor(dst, 65534, stale))

		if _, err := r.Resolve(connFor(peer)); !errors.Is(err, ErrNoOriginalDestination) {
			t.Fatalf("Resolve error = %v, want ErrNoOriginalDst for stale entry", err)
		}
	})

	t.Run("Resolve_EntryWithinMaxAge_Succeeds", func(t *testing.T) {
		m := newPairMap(t)
		r := newResolver(t, m, fixedNow(testNow), audit.NopMetricsRecorder{})

		peer := netip.MustParseAddrPort("10.0.0.8:40003")
		dst := netip.MustParseAddrPort("93.184.216.34:443")
		fresh := testNow - uint64(14*time.Second)
		putEntry(t, m, peer, valueFor(dst, 65534, fresh))

		got, err := r.Resolve(connFor(peer))
		if err != nil {
			t.Fatalf("Resolve error = %v, want nil", err)
		}
		if got != dst {
			t.Fatalf("Resolve = %v, want %v", got, dst)
		}
	})

	t.Run("Resolve_BadFlagsOrZeroPortInMapValue_ReturnsErrNoOriginalDst", func(t *testing.T) {
		m := newPairMap(t)
		r := newResolver(t, m, fixedNow(testNow), audit.NopMetricsRecorder{})

		peer := netip.MustParseAddrPort("10.0.0.10:40004")
		// DST_IPV4 set but the decoded port is zero: defensively rejected.
		val := valueFor(netip.MustParseAddrPort("93.184.216.34:1"), 65534, testNow)
		val.Port = 0
		putEntry(t, m, peer, val)

		if _, err := r.Resolve(connFor(peer)); !errors.Is(err, ErrNoOriginalDestination) {
			t.Fatalf("Resolve error = %v, want ErrNoOriginalDst for zero port", err)
		}
	})

	t.Run("Resolve_NonIPv4AddressFamily_ReturnsErrNoOriginalDst", func(t *testing.T) {
		m := newPairMap(t)
		r := newResolver(t, m, fixedNow(testNow), audit.NopMetricsRecorder{})

		peer := netip.MustParseAddrPort("10.0.0.11:40005")
		// Flags lack DST_IPV4 (address family is not AF_INET): rejected.
		val := valueFor(netip.MustParseAddrPort("93.184.216.34:443"), 65534, testNow)
		val.Flags = 0
		putEntry(t, m, peer, val)

		if _, err := r.Resolve(connFor(peer)); !errors.Is(err, ErrNoOriginalDestination) {
			t.Fatalf("Resolve error = %v, want ErrNoOriginalDst for non-AF_INET value", err)
		}
	})

	t.Run("Resolve_MapUnreadableSyscallError_ReturnsWrappedError", func(t *testing.T) {
		m := newPairMap(t)
		r := newResolver(t, m, fixedNow(testNow), audit.NopMetricsRecorder{})

		// Close the map so the underlying bpf() syscall fails (EBADF) rather
		// than reporting a routine key-not-found miss.
		if err := m.Close(); err != nil {
			t.Fatalf("map close: %v", err)
		}

		peer := netip.MustParseAddrPort("10.0.0.12:40006")
		_, err := r.Resolve(connFor(peer))
		if err == nil {
			t.Fatalf("Resolve error = nil, want a wrapped map error")
		}
		if errors.Is(err, ErrNoOriginalDestination) {
			t.Fatalf("Resolve error = %v, want a map-unavailable error, not a benign miss", err)
		}
		if !errors.Is(err, ErrMapUnavailable) {
			t.Fatalf("Resolve error = %v, want wrapping ErrMapUnavailable", err)
		}
	})

	t.Run("Resolve_PodLocalReason_QuietRejectNoAlert", func(t *testing.T) {
		m := newPairMap(t)
		spy := &metricsSpy{}
		r := newResolver(t, m, fixedNow(testNow), spy)

		// A loopback (pod-local) destination should never appear in the pair
		// map because connect4 does not redirect 127.0.0.0/8 (design §6.2); when
		// one does it is an anomaly rejected as a *quiet* T1, recorded via the
		// metrics recorder with fault=false and without any loop-guard alert.
		peer := netip.MustParseAddrPort("10.0.0.13:40007")
		putEntry(t, m, peer, valueFor(netip.MustParseAddrPort("127.0.0.1:8080"), 65534, testNow))

		_, err := r.Resolve(connFor(peer))
		if !errors.Is(err, ErrNoOriginalDestination) {
			t.Fatalf("Resolve error = %v, want ErrNoOriginalDst", err)
		}

		calls := spy.calls()
		if len(calls) != 1 {
			t.Fatalf("Decisions call count = %d, want exactly 1", len(calls))
		}
		if calls[0].reason != pipeline.ReasonPodLocalDestination {
			t.Fatalf("Decisions reason = %v, want ReasonPodLocalDestination", calls[0].reason)
		}
		if calls[0].fault {
			t.Fatalf("Decisions fault = true, want false (a pod-local T1 must not alert)")
		}
		for _, c := range calls {
			if c.fault {
				t.Fatalf("an alerting decision (fault=true) was recorded: %+v", c)
			}
		}
	})

	t.Run("Resolve_InjectedClockForStaleness_UsesNowFuncNotWallClock", func(t *testing.T) {
		m := newPairMap(t)

		peer := netip.MustParseAddrPort("10.0.0.14:40008")
		dst := netip.MustParseAddrPort("93.184.216.34:443")

		// Same entry, same stamp: fresh under a now equal to the stamp, stale
		// under an injected now advanced past maxAge. Only the injected clock
		// changes, proving staleness is driven by the now seam, not time.Now.
		stamp := testNow

		rFresh := newResolver(t, m, fixedNow(stamp), audit.NopMetricsRecorder{})
		putEntry(t, m, peer, valueFor(dst, 65534, stamp))
		if got, err := rFresh.Resolve(connFor(peer)); err != nil || got != dst {
			t.Fatalf("fresh Resolve = (%v, %v), want (%v, nil)", got, err, dst)
		}

		rStale := newResolver(t, m, fixedNow(stamp+uint64(20*time.Second)), audit.NopMetricsRecorder{})
		putEntry(t, m, peer, valueFor(dst, 65534, stamp))
		if _, err := rStale.Resolve(connFor(peer)); !errors.Is(err, ErrNoOriginalDestination) {
			t.Fatalf("stale Resolve error = %v, want ErrNoOriginalDst under advanced injected clock", err)
		}
	})

	t.Run("Resolve_ConcurrentCallsDistinctConnections_EachResolvesIndependently", func(t *testing.T) {
		m := newPairMap(t)
		r := newResolver(t, m, fixedNow(testNow), audit.NopMetricsRecorder{})

		const n = 64
		peers := make([]netip.AddrPort, n)
		dsts := make([]netip.AddrPort, n)
		for i := 0; i < n; i++ {
			peers[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}), uint16(40000+i))
			dsts[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{93, 184, byte(i >> 8), byte(i)}), uint16(1000+i))
			putEntry(t, m, peers[i], valueFor(dsts[i], 65534, testNow))
		}

		got := make([]netip.AddrPort, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(i int) {
				defer wg.Done()
				got[i], errs[i] = r.Resolve(connFor(peers[i]))
			}(i)
		}
		wg.Wait()

		for i := 0; i < n; i++ {
			if errs[i] != nil {
				t.Fatalf("goroutine %d Resolve error = %v, want nil", i, errs[i])
			}
			if got[i] != dsts[i] {
				t.Fatalf("goroutine %d Resolve = %v, want %v (cross-talk)", i, got[i], dsts[i])
			}
		}
	})
}
