package watch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kwatch "k8s.io/apimachinery/pkg/watch"
)

func TestWatcherRun_WatchReconnect410_PerformsFullRelist(t *testing.T) {
	client := newFakeClient("app-ns")
	client.listFn = func(n int) (*listType, error) {
		return listOf("rv"+itoa(n), allowPolicy("a", "example.com")), nil
	}
	fw1, fw2 := newFakeWatch(), newFakeWatch()
	client.watchFn = func(n int) (kwatch.Interface, error) {
		switch n {
		case 1:
			return fw1, nil
		case 2:
			return fw2, nil
		default:
			return newFakeWatch(), nil
		}
	}
	store := &Store{}
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	w.reconnectBackoff = time.Millisecond
	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	mustWaitReady(t, w)
	<-client.watchSig // watch #1 established

	listsBefore := client.listCount()
	fw1.sendGone()

	// A full relist must happen (List count grows) and a new watch established.
	if !waitFor(func() bool { return client.listCount() > listsBefore }, 2*time.Second) {
		t.Fatalf("410 did not trigger a full relist")
	}
	<-client.watchSig // watch #2 established after relist
	if client.watchCount() < 2 {
		t.Fatalf("watch not re-established after 410")
	}
}

func TestWatcherRun_RelistAfterReconnect_ResumesWatch(t *testing.T) {
	client := newFakeClient("app-ns")
	client.listFn = func(n int) (*listType, error) {
		rv := "100"
		if n >= 2 {
			rv = "200"
		}
		return listOf(rv, allowPolicy("a", "example.com")), nil
	}
	fw1, fw2 := newFakeWatch(), newFakeWatch()
	client.watchFn = func(n int) (kwatch.Interface, error) {
		if n == 1 {
			return fw1, nil
		}
		if n == 2 {
			return fw2, nil
		}
		return newFakeWatch(), nil
	}
	store := &Store{}
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	w.reconnectBackoff = time.Millisecond
	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	mustWaitReady(t, w)
	<-client.watchSig
	if opts, _ := client.lastWatchOpts(); opts.ResourceVersion != "100" {
		t.Fatalf("watch #1 ResourceVersion = %q, want 100", opts.ResourceVersion)
	}
	fw1.sendGone()

	<-client.watchSig // watch #2
	if !waitFor(func() bool {
		opts, ok := client.lastWatchOpts()
		return ok && opts.ResourceVersion == "200"
	}, 2*time.Second) {
		opts, _ := client.lastWatchOpts()
		t.Fatalf("watch #2 ResourceVersion = %q, want 200 (relisted RV)", opts.ResourceVersion)
	}
}

func TestWatcherRun_StartStop_ClosesWatchOnContextCancel(t *testing.T) {
	client := newFakeClient("app-ns")
	client.listFn = func(n int) (*listType, error) { return listOf("1", allowPolicy("a", "example.com")), nil }
	fw := newFakeWatch()
	client.watchFn = func(n int) (kwatch.Interface, error) {
		if n == 1 {
			return fw, nil
		}
		return newFakeWatch(), nil
	}
	store := &Store{}
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	cancel, done := startRun(t, w)

	mustWaitReady(t, w)
	<-client.watchSig
	verBefore, _, _ := store.Current()

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want nil/canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not exit on context cancel")
	}
	if !waitFor(fw.isStopped, time.Second) {
		t.Fatalf("watch was not stopped on context cancel")
	}
	// Last good snapshot remains after shutdown.
	snap, _, ok := store.Current()
	if !ok || snap.Version() != verBefore.Version() {
		t.Fatalf("last good snapshot not retained after shutdown")
	}
}

func TestWatcherRun_WatchErrorAfterGoodSnapshot_LivenessRemainsTrue(t *testing.T) {
	client := newFakeClient("app-ns")
	client.listFn = func(n int) (*listType, error) { return listOf("1", allowPolicy("a", "example.com")), nil }
	fw1 := newFakeWatch()
	client.watchFn = func(n int) (kwatch.Interface, error) {
		if n == 1 {
			return fw1, nil
		}
		return newFakeWatch(), nil
	}
	store := &Store{}
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	w.reconnectBackoff = time.Millisecond
	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	mustWaitReady(t, w)
	good, _, _ := store.Current()
	<-client.watchSig

	// A watch error (not 410) after a good snapshot: reconnect, liveness stays true.
	fw1.ch <- kwatch.Event{Type: kwatch.Error, Object: &metav1.Status{Code: 500, Reason: metav1.StatusReasonInternalError}}

	if !waitFor(func() bool { return client.watchCount() >= 2 }, 2*time.Second) {
		t.Fatalf("watcher did not reconnect after watch error")
	}
	if !w.Live() {
		t.Fatalf("liveness dropped after a recoverable watch outage")
	}
	snap, _, ok := store.Current()
	if !ok || snap.Version() != good.Version() {
		t.Fatalf("good snapshot not retained across watch outage")
	}
}

func TestWatcherRun_ConcurrentEvents_SerializesCompileAndSwap(t *testing.T) {
	pA := allowPolicy("a", "a.example.com")
	pB := allowPolicy("b", "b.example.com")
	pC := allowPolicy("c", "c.example.com")
	client := newFakeClient("app-ns")
	client.listFn = func(n int) (*listType, error) { return listOf("1", pA, pB, pC), nil }
	store := &Store{}
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)

	want := mustSnapshot(t, pA, pB, pC)

	var wg sync.WaitGroup
	readErr := make(chan error, 1)
	stop := make(chan struct{})
	// Reader: the store must always expose the complete-set version, never a
	// partial one, while relists run concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if snap, _, ok := store.Current(); ok && snap.Version() != want.Version() {
				select {
				case readErr <- errors.New("observed partial snapshot version " + snap.Version()):
				default:
				}
				return
			}
		}
	}()

	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = w.relistAndSwap(context.Background())
		}()
	}
	// Let readers race a bit past the writers.
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	select {
	case err := <-readErr:
		t.Fatal(err)
	default:
	}
	snap, _, ok := store.Current()
	if !ok || snap.Version() != want.Version() {
		t.Fatalf("final snapshot = %v, want complete-set version %q", snap, want.Version())
	}
}

func TestWatcherRun_CompileFailureRetainsLastGoodSnapshot(t *testing.T) {
	client := newFakeClient("app-ns")
	client.listFn = func(n int) (*listType, error) {
		if n == 1 {
			return listOf("1", allowPolicy("a", "good.example.com")), nil
		}
		// Subsequent relists include an uncompilable policy.
		return listOf("2", allowPolicy("a", "good.example.com"), denyPolicy("bad")), nil
	}
	fw1 := newFakeWatch()
	client.watchFn = func(n int) (kwatch.Interface, error) {
		if n == 1 {
			return fw1, nil
		}
		return newFakeWatch(), nil
	}
	store := &Store{}
	w := mustWatcher(t, Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	mustWaitReady(t, w)
	good, _, _ := store.Current()
	<-client.watchSig

	// A watch event triggers a relist that fails to compile.
	fw1.sendModify()
	if !waitFor(func() bool { return client.listCount() >= 2 }, 2*time.Second) {
		t.Fatalf("relist after event never happened")
	}
	// Give the failing compile a moment; the store must keep the last good.
	time.Sleep(50 * time.Millisecond)
	snap, _, ok := store.Current()
	if !ok {
		t.Fatalf("store cleared on compile failure; want retain last good")
	}
	if snap.Version() != good.Version() {
		t.Fatalf("snapshot changed on compile failure: got %q, want %q", snap.Version(), good.Version())
	}
}

// itoa avoids importing strconv in a way that clutters the fake closures.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
