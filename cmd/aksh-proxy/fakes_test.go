package main

import (
	"sync"

	"github.com/cilium/ebpf"

	"github.com/girishmotwani/aksh/internal/dataplane/capture"
)

// fakeHandle is a genuine captureHandle test double used by the preflight
// (#97-#101) and run-lifecycle (#102-#109) tests. It owns no kernel object: it
// records lifecycle calls, latches Close teardown via sync.Once (mirroring the
// real Handle's idempotency), stores the OnAttachLoss callback, and lets a test
// fire an attach-loss.
type fakeHandle struct {
	pairMap    *ebpf.Map
	attachInfo capture.AttachInfo
	attachLost bool

	mu            sync.Mutex
	closeCalls    int
	teardownCount int
	pairMapCalls  int
	lossCallback  func(error)
	closeOnce     sync.Once
	onTeardown    func()
}

func (f *fakeHandle) PairMap() *ebpf.Map {
	f.mu.Lock()
	f.pairMapCalls++
	f.mu.Unlock()
	return f.pairMap
}

func (f *fakeHandle) AttachInfo() capture.AttachInfo { return f.attachInfo }

func (f *fakeHandle) Close() error {
	f.mu.Lock()
	f.closeCalls++
	f.mu.Unlock()
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.teardownCount++
		hook := f.onTeardown
		f.mu.Unlock()
		if hook != nil {
			hook()
		}
	})
	return nil
}

func (f *fakeHandle) OnAttachLoss(fn func(error)) {
	f.mu.Lock()
	f.lossCallback = fn
	f.mu.Unlock()
}

func (f *fakeHandle) AttachLoss() <-chan error { return nil }

func (f *fakeHandle) AttachLost() bool { return f.attachLost }

// fireLoss invokes the stored attach-loss callback, simulating the health
// loop's detachment signal (#107/#108).
func (f *fakeHandle) fireLoss(err error) {
	f.mu.Lock()
	fn := f.lossCallback
	f.mu.Unlock()
	if fn != nil {
		fn(err)
	}
}

func (f *fakeHandle) closes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closeCalls
}

func (f *fakeHandle) teardowns() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.teardownCount
}

func (f *fakeHandle) pairMaps() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pairMapCalls
}

// healthyAttach returns an AttachInfo describing a live attach (one program, a
// real cgroup id).
func healthyAttach() capture.AttachInfo {
	return capture.AttachInfo{ProgIDs: []uint32{42}, CgroupID: 99}
}
