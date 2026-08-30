//go:build linux && ebpf_integration

package bpf

import (
	"os"
	"runtime"
	"testing"
	"time"
)

func TestAkshbpfObjects_ImplementsCloserOrHasClose_NoLeakedFDsOnRepeatedLoad(t *testing.T) {
	var warmup AkshbpfObjects
	if err := LoadAkshbpfObjects(&warmup, nil); err != nil {
		t.Fatalf("warm-up LoadAkshbpfObjects() error = %v", err)
	}
	if err := warmup.Close(); err != nil {
		t.Fatalf("warm-up Close() error = %v", err)
	}

	// runtime.GC() before sampling flushes any pending finalizer-driven fd
	// closes so the baseline/final samples reflect only this test's own fds,
	// not ambient process churn (dev-review iter2 finding).
	runtime.GC()
	baseline, err := fdCount()
	if err != nil {
		t.Fatalf("fdCount() baseline error = %v", err)
	}

	for i := 0; i < 100; i++ {
		var objs AkshbpfObjects
		if err := LoadAkshbpfObjects(&objs, nil); err != nil {
			t.Fatalf("iteration %d: LoadAkshbpfObjects() error = %v", i, err)
		}
		if err := objs.Close(); err != nil {
			t.Fatalf("iteration %d: Close() error = %v", i, err)
		}
	}

	// A single fdCount() sample is susceptible to transient ambient fd
	// churn unrelated to AkshbpfObjects (e.g. another goroutine's socket
	// briefly open at the moment of measurement). Retry a bounded number of
	// times with a short backoff before failing, so only a fd count that
	// stays out of range settles as a genuine leak rather than a flake.
	const (
		maxAttempts = 5
		retryDelay  = 20 * time.Millisecond
	)
	var finalCount int
	var diff int
	inRange := false
	for attempt := 0; attempt < maxAttempts; attempt++ {
		runtime.GC()
		finalCount, err = fdCount()
		if err != nil {
			t.Fatalf("fdCount() final error = %v", err)
		}
		diff = finalCount - baseline
		if diff >= 0 && diff <= 1 {
			inRange = true
			break
		}
		time.Sleep(retryDelay)
	}

	if !inRange {
		// diff==1 is tolerated for the transient fd os.ReadDir itself opens
		// while enumerating /proc/self/fd for the "final" measurement (see
		// BPF-43's baseline/measurement protocol in the eBPF UT-spec
		// addendum §8). A negative diff would indicate fdCount() itself is
		// unstable (e.g. concurrent fd churn from something else in this
		// process) rather than a genuine leak, so it is flagged too rather
		// than silently passing.
		t.Fatalf("fd count diff = %d (baseline=%d final=%d) after %d attempts, want in [0, 1]", diff, baseline, finalCount, maxAttempts)
	}
}

func fdCount() (int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}
