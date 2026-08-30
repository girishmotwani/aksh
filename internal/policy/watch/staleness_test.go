package watch

import (
	"context"
	"testing"
	"time"

	kwatch "k8s.io/apimachinery/pkg/watch"
)

func TestWatcherRun_StaleSnapshotMetric_EmittedAtDenyBoundary(t *testing.T) {
	client := newFakeClient("app-ns")
	store := &Store{}
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	counter := &countingStaleDeny{}
	w.metrics = counter

	snap := mustSnapshot(t, allowPolicy("a", "example.com"))

	// Fresh snapshot: observing staleness must not emit.
	store.Swap(snap, time.Now())
	w.observeStaleness()
	if counter.count() != 0 {
		t.Fatalf("stale-deny emitted for a fresh snapshot: %d", counter.count())
	}

	// Cross the boundary: age >= 45s. Exactly one emit on the transition.
	store.Swap(snap, time.Now().Add(-45*time.Second))
	w.observeStaleness()
	if counter.count() != 1 {
		t.Fatalf("stale-deny count after crossing boundary = %d, want 1", counter.count())
	}
	// Still stale, no new transition: count must not grow.
	w.observeStaleness()
	if counter.count() != 1 {
		t.Fatalf("stale-deny emitted more than once per transition: %d", counter.count())
	}
}

func TestWatcherRun_ReconnectWithin45s_StaleSnapshotServed(t *testing.T) {
	client := newFakeClient("app-ns")
	// Every swap is stamped 30s in the past (a fake clock backdating the
	// publication time), modelling an outage shorter than the staleness bound.
	client.listFn = func(n int) (*listType, error) { return listOf("rv"+itoa(n), allowPolicy("a", "example.com")), nil }
	fw1 := newFakeWatch()
	client.watchFn = func(n int) (kwatch.Interface, error) {
		if n == 1 {
			return fw1, nil
		}
		return newFakeWatch(), nil
	}
	store := &Store{}
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	w.now = func() time.Time { return time.Now().Add(-30 * time.Second) }
	w.reconnectBackoff = time.Millisecond
	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	mustWaitReady(t, w)
	<-client.watchSig
	// Force a reconnect; it completes (relist+re-swap) well within 45s.
	fw1.sendGone()
	if !waitFor(func() bool { return client.watchCount() >= 2 }, 2*time.Second) {
		t.Fatalf("reconnect did not complete")
	}
	// Last good snapshot, aged ~30s, is still fresh and served.
	if _, ok := store.Fresh(45 * time.Second); !ok {
		t.Fatalf("Fresh(45s) = false after a sub-45s reconnect, want true")
	}
}

func TestWatcherRun_ReconnectExceeds45s_DenyAll(t *testing.T) {
	client := newFakeClient("app-ns")
	// The initial good snapshot compiles once; the reconnect outage then never
	// re-swaps (List keeps failing), so the last good snapshot ages in real time
	// past the 45s boundary while served, and the store denies all.
	client.listFn = func(n int) (*listType, error) {
		if n == 1 {
			return listOf("1", allowPolicy("a", "example.com")), nil
		}
		return nil, context.DeadlineExceeded // outage continues
	}
	fw1 := newFakeWatch()
	client.watchFn = func(n int) (kwatch.Interface, error) {
		if n == 1 {
			return fw1, nil
		}
		return newFakeWatch(), nil
	}
	store := &Store{}
	// A single fake clock drives both the watcher's stamp time and the store's
	// age measurement, so the 45s boundary is crossed by advancing the clock
	// (honouring the UT spec's "with a fake clock" contract) rather than racing
	// real time.
	fc := newFakeClock()
	store.now = fc.now
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	w.now = fc.now
	w.reconnectBackoff = time.Millisecond
	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	mustWaitReady(t, w)
	// Precondition: the last good snapshot is fresh before the boundary is
	// crossed (age 0 under the fake clock -- deterministic, no timing margin).
	if _, ok := store.Fresh(45 * time.Second); !ok {
		t.Fatalf("Fresh(45s) = false immediately after first snapshot, want true")
	}
	<-client.watchSig
	fw1.sendGone() // reconnect starts; relists keep failing, no re-swap

	// Advance the fake clock past the 45s boundary during the outage. With no
	// successful re-swap, the aged last-good snapshot is denied (deny all).
	fc.advance(46 * time.Second)
	if _, ok := store.Fresh(45 * time.Second); ok {
		t.Fatalf("Fresh(45s) = true, want false (deny all) after age crossed 45s during the outage")
	}
	if !w.Live() {
		t.Fatalf("liveness dropped during a stale outage; the process can continue")
	}
}

func TestWatcherRun_CompileFailureUntilAge45_DenyAllLivenessTrue(t *testing.T) {
	client := newFakeClient("app-ns")
	client.listFn = func(n int) (*listType, error) {
		if n == 1 {
			return listOf("1", allowPolicy("a", "example.com")), nil
		}
		// Every subsequent relist fails to compile → retain last good.
		return listOf("2", allowPolicy("a", "example.com"), denyPolicy("bad")), nil
	}
	fw1 := newFakeWatch()
	client.watchFn = func(n int) (kwatch.Interface, error) {
		if n == 1 {
			return fw1, nil
		}
		return newFakeWatch(), nil
	}
	store := &Store{}
	// One fake clock for both the stamp and the age read, so the boundary is
	// crossed deterministically by advancing it (UT spec "with a fake clock").
	fc := newFakeClock()
	store.now = fc.now
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	w.now = fc.now
	w.reconnectBackoff = time.Millisecond
	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	mustWaitReady(t, w)
	<-client.watchSig

	// Phase 1: last good served (age 0 < 45s), liveness true, even as compile
	// failures accumulate from watch events.
	fw1.sendModify()
	if !waitFor(func() bool { return client.listCount() >= 2 }, 2*time.Second) {
		t.Fatalf("relist after event never happened")
	}
	if _, ok := store.Fresh(45 * time.Second); !ok {
		t.Fatalf("Fresh(45s) = false before crossing the boundary, want true")
	}
	if !w.Live() {
		t.Fatalf("liveness dropped while serving last good")
	}

	// Phase 2: advance the fake clock past the boundary. No successful re-swap
	// has occurred (relists compile-fail), so the last good snapshot ages past
	// 45s -> deny all, liveness still true.
	fc.advance(46 * time.Second)
	if _, ok := store.Fresh(45 * time.Second); ok {
		t.Fatalf("Fresh(45s) = true past the boundary, want false (deny all)")
	}
	if !w.Live() {
		t.Fatalf("liveness dropped after deny-all; the process can continue")
	}
}
