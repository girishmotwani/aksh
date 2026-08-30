package watch

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// startRun launches w.Run on a cancelable context and returns a cancel func and
// a channel delivering Run's return value.
func startRun(t *testing.T, w *Watcher) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	return cancel, done
}

func TestWatcherRun_ListsOwnNamespaceOnly(t *testing.T) {
	client := newFakeClient("app-ns")
	client.listFn = func(n int) (*listType, error) { return listOf("1", allowPolicy("a", "example.com")), nil }
	store := &Store{}
	w, err := NewWatcher(Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	if err := w.WaitFirstSnapshot(waitCtx); err != nil {
		t.Fatalf("WaitFirstSnapshot: %v", err)
	}
	// Wait until a watch has also been established.
	if !waitFor(func() bool { return client.watchCount() >= 1 }, 2*time.Second) {
		t.Fatalf("watch was never established")
	}
	if client.listCount() < 1 {
		t.Fatalf("List was never called")
	}
	if client.namespace != "app-ns" {
		t.Fatalf("client namespace = %q, want app-ns", client.namespace)
	}
}

func TestWatcherRun_InitialListCompileSuccess_SwapsFirstSnapshot(t *testing.T) {
	client := newFakeClient("app-ns")
	client.listFn = func(n int) (*listType, error) {
		return listOf("7", allowPolicy("a", "one.example.com"), allowPolicy("b", "two.example.com")), nil
	}
	store := &Store{}
	w, err := NewWatcher(Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	if err := w.WaitFirstSnapshot(waitCtx); err != nil {
		t.Fatalf("WaitFirstSnapshot: %v", err)
	}
	snap, _, ok := store.Current()
	if !ok {
		t.Fatalf("store has no snapshot after first compile")
	}
	want := mustSnapshot(t, allowPolicy("a", "one.example.com"), allowPolicy("b", "two.example.com"))
	if snap.Version() != want.Version() {
		t.Fatalf("snapshot version = %q, want %q", snap.Version(), want.Version())
	}
	if len(snap.Rules()) != 2 {
		t.Fatalf("rule count = %d, want 2", len(snap.Rules()))
	}
}

func TestWatcherRun_FirstSnapshotLog_IncludesVersionAndRuleCount(t *testing.T) {
	client := newFakeClient("app-ns")
	client.listFn = func(n int) (*listType, error) {
		return listOf("1", allowPolicy("a", "secret-host.example.com")), nil
	}
	store := &Store{}
	w, err := NewWatcher(Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	var buf syncBuffer
	w.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	if err := w.WaitFirstSnapshot(waitCtx); err != nil {
		t.Fatalf("WaitFirstSnapshot: %v", err)
	}
	// Give the log line time to flush (published just before ready close on same goroutine).
	waitFor(func() bool { return strings.Contains(buf.String(), "version=") }, 2*time.Second)

	want := mustSnapshot(t, allowPolicy("a", "secret-host.example.com"))
	logged := buf.String()
	if !strings.Contains(logged, want.Version()) {
		t.Fatalf("log missing version %q: %s", want.Version(), logged)
	}
	if !strings.Contains(logged, "rules=1") {
		t.Fatalf("log missing rule count: %s", logged)
	}
	if strings.Contains(logged, "secret-host.example.com") {
		t.Fatalf("log leaked raw policy content: %s", logged)
	}
	if strings.Contains(strings.ToLower(logged), "yaml") {
		t.Fatalf("log leaked raw YAML: %s", logged)
	}
}

func TestWatcherRun_NoSnapshot_DenyAllUntilFirstCompile(t *testing.T) {
	client := newFakeClient("app-ns")
	// Initial list compiles to an error (unsupported effect) so no snapshot
	// is ever published.
	client.listFn = func(n int) (*listType, error) { return listOf("1", denyPolicy("bad")), nil }
	store := &Store{}
	w, err := NewWatcher(Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	// Wait until the initial list has been attempted at least once.
	select {
	case <-client.listSig:
	case <-time.After(2 * time.Second):
		t.Fatalf("initial List never happened")
	}
	// Give the compile a moment; it must fail and publish nothing.
	if !waitFor(func() bool {
		_, ok := store.Fresh(45 * time.Second)
		_, _, cur := store.Current()
		return !ok && !cur
	}, time.Second) {
		t.Fatalf("store should be empty and deny-all before first successful compile")
	}
	if _, ok := store.Fresh(45 * time.Second); ok {
		t.Fatalf("Fresh(45s) = true, want false (deny all) before first compile")
	}
	// WaitFirstSnapshot must still be blocking.
	quick, qcancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer qcancel()
	if err := w.WaitFirstSnapshot(quick); err == nil {
		t.Fatalf("WaitFirstSnapshot returned nil before any successful compile")
	}
}

// waitFor polls cond until true or the timeout elapses.
func waitFor(cond func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

// syncBuffer is a goroutine-safe bytes.Buffer for capturing log output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
