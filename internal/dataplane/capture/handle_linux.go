//go:build linux

package capture

import (
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"

	bpf "github.com/girishmotwani/aksh/internal/dataplane/bpf"
)

// Handle owns the kernel objects and health loop of a successful LoadAndAttach.
// It is the single point of ownership for eBPF teardown (SIGTERM drain) and the
// live pair_orig_dst map (destination resolution). It replaces the health
// loop's os.Exit(1) with a fail-closed attach-loss signal (callback + buffered
// channel). Close is idempotent and safe on a partially built Handle.
type Handle struct {
	// st is the retained loader state; nil on a partially built Handle.
	st *loaderState
	// pairMap retains the live pair_orig_dst map, nil-ed under Close so a stale
	// post-teardown resolver read cannot dereference a closed map. The atomic
	// pointer keeps PairMap reads data-race-free against Close.
	pairMap atomic.Pointer[ebpf.Map]
	// info is the immutable attach snapshot captured at construction; it stays
	// valid after Close.
	info AttachInfo

	// onLoss is the attach-loss callback registered via OnAttachLoss.
	onLoss atomic.Pointer[func(error)]
	// lossCh is the buffered(1) channel alternative to the callback.
	lossCh chan error

	// lossMu guards the loss latch and single-delivery of the callback.
	lossMu        sync.Mutex
	lost          bool
	lostErr       error
	callbackFired bool

	closeOnce sync.Once
	closeErr  error
}

// newHandle wraps a completed loaderState in an owner Handle, capturing the live
// pair map and the immutable attach snapshot at construction time.
func newHandle(st *loaderState, info *AttachInfo) *Handle {
	h := &Handle{st: st, lossCh: make(chan error, 1)}
	if info != nil {
		h.info = *info
	}
	if st != nil && st.coll != nil {
		if pm := st.coll.Maps[bpf.AkshbpfMapPairOrigDst]; pm != nil {
			h.pairMap.Store(pm)
		}
	}
	return h
}

// PairMap returns the live pair_orig_dst *ebpf.Map for the resolver, or nil
// after Close (or on a partially built Handle). The map is not pinned; the live
// handle is authoritative (DD-3).
func (h *Handle) PairMap() *ebpf.Map {
	if h == nil {
		return nil
	}
	return h.pairMap.Load()
}

// AttachInfo returns the immutable attach snapshot captured at construction. It
// remains valid after Close; a partially built Handle returns the zero value.
func (h *Handle) AttachInfo() AttachInfo {
	if h == nil {
		return AttachInfo{}
	}
	return h.info
}

// Close detaches every link, unpins (when pinned), cancels the health loop and
// closes the collection. It is idempotent (sync.Once) and safe on a partially
// built Handle, and nils the retained pair map so post-teardown reads see nil.
func (h *Handle) Close() error {
	if h == nil {
		return nil
	}
	h.closeOnce.Do(func() {
		h.pairMap.Store(nil)
		if h.st != nil {
			h.st.closeAll()
		}
	})
	return h.closeErr
}

// OnAttachLoss registers a fail-closed callback invoked once on a proof of
// detachment (or three inconclusive checks), replacing the removed os.Exit(1).
// fn must be non-blocking; it runs on the health goroutine. A nil fn is
// tolerated. Registering after loss has already occurred delivers immediately.
func (h *Handle) OnAttachLoss(fn func(error)) {
	h.onLoss.Store(&fn)

	h.lossMu.Lock()
	deliver := h.lost && fn != nil && !h.callbackFired
	if deliver {
		h.callbackFired = true
	}
	lerr := h.lostErr
	h.lossMu.Unlock()

	if deliver {
		fn(lerr)
	}
}

// AttachLoss is the buffered(1) channel alternative to OnAttachLoss; it receives
// the loss error exactly once.
func (h *Handle) AttachLoss() <-chan error {
	return h.lossCh
}

// AttachLost reports whether the attach-loss latch has fired. It reads the same
// latch that powers OnAttachLoss late-delivery, so productionPreflight can use
// it as a validate-only "attach already lost" predicate without re-attaching
// (S5 seam, UT #100). Safe for concurrent use with signalAttachLoss/Close.
func (h *Handle) AttachLost() bool {
	if h == nil {
		return false
	}
	h.lossMu.Lock()
	defer h.lossMu.Unlock()
	return h.lost
}

// signalAttachLoss latches the first loss, sends non-blocking on the buffered
// channel and invokes the registered callback at most once. It is idempotent
// per loss event and safe for concurrent use with OnAttachLoss and Close.
func (h *Handle) signalAttachLoss(err error) {
	h.lossMu.Lock()
	if h.lost {
		h.lossMu.Unlock()
		return
	}
	h.lost = true
	h.lostErr = err
	fnp := h.onLoss.Load()
	deliver := fnp != nil && *fnp != nil && !h.callbackFired
	if deliver {
		h.callbackFired = true
	}
	h.lossMu.Unlock()

	if h.lossCh != nil {
		select {
		case h.lossCh <- err:
		default:
		}
	}
	if deliver {
		(*fnp)(err)
	}
}
