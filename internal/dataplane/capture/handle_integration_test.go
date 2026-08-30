//go:build linux && ebpf_integration

package capture

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	bpf "github.com/girishmotwani/aksh/internal/dataplane/bpf"
)

// mustHandle runs LoadAndAttach on a real kernel and registers Handle.Close as
// teardown, so a subtest can assert on live kernel objects without leaking them.
func mustHandle(t *testing.T, opts *Options) *Handle {
	t.Helper()
	h, err := LoadAndAttach(opts)
	if err != nil {
		t.Fatalf("LoadAndAttach() error = %v, want nil", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// forceDetachSeam installs a controllable ticker plus a checkAttachment that
// always proves detachment, so the health loop reaches its terminal loss
// dispatch on demand. It returns the tick channel to fire.
func forceDetachSeam(t *testing.T) chan time.Time {
	t.Helper()
	tick := make(chan time.Time, 1)
	loaderSeam.newHealthTicker = func(time.Duration) (<-chan time.Time, func()) { return tick, func() {} }
	loaderSeam.checkAttachment = func(*loaderState) error {
		return fmt.Errorf("program detached: %w", errAttachLost)
	}
	return tick
}

// #1
func TestLoadAndAttach_ValidOptions_ReturnsNonNilHandle(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	h := mustHandle(t, loaderBaseOptions(t, cg))
	if h == nil {
		t.Fatalf("LoadAndAttach() handle = nil, want non-nil")
	}
	if len(h.AttachInfo().ProgIDs) == 0 {
		t.Fatalf("Handle owns no attached programs")
	}
}

// #6
func TestLoadAndAttach_KernelLoadFailure_AbortsFailClosed(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	loaderSeam.newCollection = func(*ebpf.CollectionSpec) (*ebpf.Collection, error) {
		return nil, fmt.Errorf("forced load failure")
	}
	h, err := LoadAndAttach(loaderBaseOptions(t, cg))
	if err == nil {
		t.Fatalf("LoadAndAttach() error = nil, want a load failure")
	}
	if h != nil {
		t.Fatalf("LoadAndAttach() handle = %v, want nil on fail-closed abort", h)
	}
}

// #7
func TestPairMap_AfterSuccessfulAttach_ReturnsLiveMap(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	opts := loaderBaseOptions(t, cg)
	h := mustHandle(t, opts)

	pm := h.PairMap()
	if pm == nil {
		t.Fatalf("PairMap() = nil, want the live pair_orig_dst map")
	}
	if live := loaderFor(opts).coll.Maps[bpf.AkshbpfMapPairOrigDst]; pm != live {
		t.Fatalf("PairMap() returned a different *ebpf.Map than the live collection map")
	}
}

// #8
func TestPairMap_AfterClose_ReturnsNil(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	h := mustHandle(t, loaderBaseOptions(t, cg))
	if err := h.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if pm := h.PairMap(); pm != nil {
		t.Fatalf("PairMap() after Close = %v, want nil", pm)
	}
}

// #9
func TestPairMap_ConcurrentReaders_SingleShotSemanticsPreserved(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	h := mustHandle(t, loaderBaseOptions(t, cg))
	pm := h.PairMap()
	if pm == nil {
		t.Fatalf("PairMap() = nil")
	}

	const n = 256
	peerFor := func(i int) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, byte(i >> 8), byte(i)}), uint16(10000+i))
	}
	for i := 0; i < n; i++ {
		putEntry(t, pm, peerFor(i), valueFor(netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), 8080), testProxyUID, 1))
	}

	var consumed int64
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				key := pairKeyFor(peerFor(i))
				var val akshPairValue
				if err := pm.LookupAndDelete(&key, &val); err == nil {
					atomic.AddInt64(&consumed, 1)
				}
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&consumed); got != n {
		t.Fatalf("consumed %d entries, want exactly %d (LookupAndDelete single-shot violated)", got, n)
	}
}

// #10
func TestAttachInfo_AfterAttach_ReturnsNonZeroProgAndCgroupIDs(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	ai := mustHandle(t, loaderBaseOptions(t, cg)).AttachInfo()
	if len(ai.ProgIDs) == 0 {
		t.Fatalf("AttachInfo.ProgIDs = %v, want non-empty", ai.ProgIDs)
	}
	for _, id := range ai.ProgIDs {
		if id == 0 {
			t.Fatalf("AttachInfo.ProgIDs contains a zero id: %v", ai.ProgIDs)
		}
	}
	if ai.CgroupID == 0 {
		t.Fatalf("AttachInfo.CgroupID = 0, want a real cgroup id")
	}
}

// #11
func TestAttachInfo_PinLinksFalse_ReturnsEmptyPinPaths(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	opts := loaderBaseOptions(t, cg) // PinLinks defaults false
	ai := mustHandle(t, opts).AttachInfo()
	if len(ai.PinPaths) != 0 {
		t.Fatalf("AttachInfo.PinPaths = %v, want empty when PinLinks is false", ai.PinPaths)
	}
}

// #12
func TestAttachInfo_AfterClose_ReturnsImmutableSnapshot(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	h := mustHandle(t, loaderBaseOptions(t, cg))
	before := h.AttachInfo()
	if err := h.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	after := h.AttachInfo()

	if after.CgroupID != before.CgroupID {
		t.Fatalf("AttachInfo().CgroupID after Close = %d, want %d", after.CgroupID, before.CgroupID)
	}
	if len(after.ProgIDs) != len(before.ProgIDs) {
		t.Fatalf("AttachInfo().ProgIDs len after Close = %d, want %d", len(after.ProgIDs), len(before.ProgIDs))
	}
	for i := range before.ProgIDs {
		if after.ProgIDs[i] != before.ProgIDs[i] {
			t.Fatalf("AttachInfo().ProgIDs[%d] after Close = %d, want %d", i, after.ProgIDs[i], before.ProgIDs[i])
		}
	}
}

// #13
func TestClose_AfterAttach_DetachesLinksAndClosesCollection(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	opts := loaderBaseOptions(t, cg)
	h, err := LoadAndAttach(opts)
	if err != nil {
		t.Fatalf("LoadAndAttach() error = %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })

	st := loaderFor(opts)
	if st == nil || len(st.links) == 0 {
		t.Fatalf("loader state missing attached links before Close")
	}
	lk := st.links[0].link

	if err := h.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := lk.Info(); err == nil {
		t.Fatalf("link still queryable after Close; it was not detached/closed")
	}
	if loaderFor(opts) != nil {
		t.Fatalf("loader state retained after Close; kernel objects leaked")
	}
}

// #16
func TestClose_AfterClose_PairMapReturnsNil(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	h := mustHandle(t, loaderBaseOptions(t, cg))
	if err := h.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if pm := h.PairMap(); pm != nil {
		t.Fatalf("PairMap() after Close = %v, want nil", pm)
	}
}

// #17
func TestOnAttachLoss_RegisteredThenLossFires_CallbackInvokedExactlyOnce(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	tick := forceDetachSeam(t)
	h := mustHandle(t, loaderBaseOptions(t, cg))

	var count int32
	fired := make(chan error, 4)
	h.OnAttachLoss(func(e error) {
		atomic.AddInt32(&count, 1)
		fired <- e
	})

	tick <- time.Now()
	select {
	case e := <-fired:
		if !errors.Is(e, errAttachLost) {
			t.Fatalf("callback error = %v, want errAttachLost", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("attach-loss callback did not fire on a detached program")
	}
	time.Sleep(300 * time.Millisecond)
	if got := atomic.LoadInt32(&count); got != 1 {
		t.Fatalf("callback invoked %d times, want exactly 1", got)
	}
}

// #19
func TestOnAttachLoss_AttachLost_DoesNotCallOsExit(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	tick := forceDetachSeam(t)
	exited := make(chan int, 1)
	loaderSeam.exit = func(code int) { exited <- code }

	h := mustHandle(t, loaderBaseOptions(t, cg))
	fired := make(chan error, 1)
	h.OnAttachLoss(func(e error) { fired <- e })

	tick <- time.Now()
	select {
	case <-fired:
	case <-time.After(5 * time.Second):
		t.Fatalf("attach-loss callback did not fire")
	}
	select {
	case code := <-exited:
		t.Fatalf("health loop called os.Exit(%d); DD-2 anti-pattern was not removed", code)
	case <-time.After(500 * time.Millisecond):
		// Success: the serve-path terminal action no longer calls the exit hook.
	}
}

// #22
func TestAttachLoss_LossOccurs_ChannelFiresExactlyOnce(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	tick := forceDetachSeam(t)
	h := mustHandle(t, loaderBaseOptions(t, cg))

	tick <- time.Now()
	select {
	case e := <-h.AttachLoss():
		if !errors.Is(e, errAttachLost) {
			t.Fatalf("AttachLoss() error = %v, want errAttachLost", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("AttachLoss() channel did not deliver the loss")
	}
	select {
	case e := <-h.AttachLoss():
		t.Fatalf("AttachLoss() delivered a second value %v, want exactly one", e)
	case <-time.After(500 * time.Millisecond):
	}
}

// #26
func TestPairMap_ConcurrentWithClose_NoDataRace(t *testing.T) {
	saveLoaderSeam(t)
	cg := mountCgroup2(t)
	h := mustHandle(t, loaderBaseOptions(t, cg))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = h.PairMap() // must observe a live map or nil, never a torn pointer
				}
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	if err := h.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	if pm := h.PairMap(); pm != nil {
		t.Fatalf("PairMap() after Close = %v, want nil", pm)
	}
}
