package watch

import (
	"log/slog"
	"testing"
	"time"

	kwatch "k8s.io/apimachinery/pkg/watch"
)

// TestResyncInterval_DerivesAndClampsAgainstMaxStaleness pins the rule that the
// effective relist interval is always strictly shorter than MaxStaleness, so a
// snapshot cannot reach the deny-all boundary between two relists.
func TestResyncInterval_DerivesAndClampsAgainstMaxStaleness(t *testing.T) {
	cases := []struct {
		name         string
		maxStaleness time.Duration
		resyncPeriod time.Duration
		want         time.Duration
	}{
		{"unset derives from max staleness", 45 * time.Second, 0, 15 * time.Second},
		{"negative derives from max staleness", 45 * time.Second, -time.Second, 15 * time.Second},
		{"explicit shorter value honoured", 45 * time.Second, 5 * time.Second, 5 * time.Second},
		{"equal to max staleness clamped", 45 * time.Second, 45 * time.Second, 15 * time.Second},
		{"longer than max staleness clamped", 45 * time.Second, 10 * time.Minute, 15 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := mustWatcher(t, Options{
				Namespace:    "app-ns",
				MaxStaleness: tc.maxStaleness,
				ResyncPeriod: tc.resyncPeriod,
			}, newFakeClient("app-ns"), &Store{})
			if got := w.resyncInterval(); got != tc.want {
				t.Fatalf("resyncInterval() = %v, want %v", got, tc.want)
			}
			if got := w.resyncInterval(); got >= tc.maxStaleness {
				t.Fatalf("resyncInterval() = %v, must be shorter than MaxStaleness %v", got, tc.maxStaleness)
			}
		})
	}
}

// TestWatcherRun_NoWatchEvents_ResyncRefreshesSnapshot is the regression test
// for the production failure where an unedited AkshPolicy produced no watch
// events, the snapshot aged past MaxStaleness, and the request path denied
// every request with reason=policy_cache_stale. The watch here never emits an
// event, so only the periodic resync can restore freshness.
func TestWatcherRun_NoWatchEvents_ResyncRefreshesSnapshot(t *testing.T) {
	client := newFakeClient("app-ns")
	client.listFn = func(n int) (*listType, error) {
		return listOf("1", allowPolicy("a", "example.com")), nil
	}
	// A watch that stays open and silent for the whole test: no Add/Modify/
	// Delete and no error, exactly like a policy nobody edits.
	silent := newFakeWatch()
	client.watchFn = func(n int) (kwatch.Interface, error) { return silent, nil }

	store := &Store{}
	fc := newFakeClock()
	store.now = fc.now
	w := mustWatcher(t, Options{
		Namespace:    "app-ns",
		MaxStaleness: 45 * time.Second,
		ResyncPeriod: 10 * time.Millisecond,
	}, client, store)
	w.now = fc.now
	w.reconnectBackoff = time.Millisecond

	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	mustWaitReady(t, w)

	// Age the snapshot past the deny-all boundary without any watch traffic.
	fc.advance(46 * time.Second)

	// Wait for a full resync cycle to complete after the advance. Two signals
	// are required: the first List may have been issued before fc.advance and
	// would therefore stamp a pre-advance time.
	drainListSig(client)
	waitListSignals(t, client, 2)

	if _, ok := store.Fresh(45 * time.Second); !ok {
		_, age, _ := store.Current()
		t.Fatalf("Fresh(45s) = false after a periodic resync (age %v); an unedited policy must not go stale", age)
	}
	if client.listCount() < 2 {
		t.Fatalf("expected periodic relists with no watch events, got %d", client.listCount())
	}
	if silent.isStopped() {
		t.Fatalf("watch was stopped; the resync must not disturb the open watch")
	}
}

// TestResyncLoop_RelistFailureRetainsLastGoodAndStaysFailClosed proves a failing
// resync does not clear or refresh the snapshot: the last good set is retained
// and keeps ageing, so the request-time deny boundary still applies.
func TestResyncLoop_RelistFailureRetainsLastGoodAndStaysFailClosed(t *testing.T) {
	client := newFakeClient("app-ns")
	client.listFn = func(n int) (*listType, error) {
		if n == 1 {
			return listOf("1", allowPolicy("a", "example.com")), nil
		}
		return nil, errListFailed
	}
	silent := newFakeWatch()
	client.watchFn = func(n int) (kwatch.Interface, error) { return silent, nil }

	store := &Store{}
	fc := newFakeClock()
	store.now = fc.now
	w := mustWatcher(t, Options{
		Namespace:    "app-ns",
		MaxStaleness: 45 * time.Second,
		ResyncPeriod: 10 * time.Millisecond,
	}, client, store)
	w.now = fc.now
	w.reconnectBackoff = time.Millisecond
	w.log = slog.New(slog.DiscardHandler)

	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	mustWaitReady(t, w)

	snap, _, ok := store.Current()
	if !ok {
		t.Fatalf("Current() reported no snapshot after the first publish")
	}
	if len(snap.Rules()) != 1 {
		t.Fatalf("Rules() = %d, want 1", len(snap.Rules()))
	}

	drainListSig(client)
	waitListSignals(t, client, 2)

	// Last good retained across failing resyncs.
	if _, _, ok := store.Current(); !ok {
		t.Fatalf("Current() reported no snapshot; a failed resync must retain the last good set")
	}
	// Still fail-closed: age is not refreshed by a failed resync.
	fc.advance(46 * time.Second)
	if _, fresh := store.Fresh(45 * time.Second); fresh {
		t.Fatalf("Fresh(45s) = true after failing resyncs; a failed relist must not refresh freshness")
	}
}

// errListFailed is the List transport failure used by the resync failure test.
var errListFailed = errFake("list failed")

type errFake string

func (e errFake) Error() string { return string(e) }

// drainListSig empties the buffered List signal channel so a subsequent wait
// only observes calls made after this point.
func drainListSig(f *fakeClient) {
	for {
		select {
		case <-f.listSig:
		default:
			return
		}
	}
}

// waitListSignals blocks until n List calls are signalled or the test times out.
func waitListSignals(t *testing.T, f *fakeClient, n int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case <-f.listSig:
		case <-deadline:
			t.Fatalf("timed out waiting for List call %d of %d (total calls %d)", i+1, n, f.listCount())
		}
	}
}
