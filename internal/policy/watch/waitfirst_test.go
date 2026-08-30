package watch

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitFirstSnapshot_BlocksUntilCompiledSnapshot(t *testing.T) {
	client := newFakeClient("app-ns")
	release := make(chan struct{})
	client.listFn = func(n int) (*listType, error) {
		<-release
		return listOf("1", allowPolicy("a", "example.com")), nil
	}
	store := &Store{}
	w, err := NewWatcher(Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	cancel, done := startRun(t, w)
	defer func() { cancel(); <-done }()

	// Before the list is released, no snapshot exists → WaitFirstSnapshot blocks.
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shortCancel()
	if err := w.WaitFirstSnapshot(shortCtx); err == nil {
		t.Fatalf("WaitFirstSnapshot returned nil before any compiled snapshot")
	}

	close(release)

	longCtx, longCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer longCancel()
	if err := w.WaitFirstSnapshot(longCtx); err != nil {
		t.Fatalf("WaitFirstSnapshot after swap = %v, want nil", err)
	}
	if _, _, ok := store.Current(); !ok {
		t.Fatalf("store has no snapshot after WaitFirstSnapshot returned nil")
	}
}

func TestWaitFirstSnapshot_ContextCanceled_ReturnsContextError(t *testing.T) {
	client := newFakeClient("app-ns")
	store := &Store{}
	w, err := NewWatcher(Options{Namespace: "app-ns", MaxStaleness: 45 * time.Second}, client, store)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	// Do not start Run: no snapshot will ever be published.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = w.WaitFirstSnapshot(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitFirstSnapshot = %v, want context.Canceled", err)
	}
	if w.firstDone {
		t.Fatalf("readiness marked despite no snapshot")
	}
}

func TestWaitFirstSnapshot_AlreadyReady_ReturnsImmediately(t *testing.T) {
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
		t.Fatalf("first WaitFirstSnapshot: %v", err)
	}
	listsAfterReady := client.listCount()

	// A second call must return immediately and must not trigger another list.
	start := time.Now()
	if err := w.WaitFirstSnapshot(context.Background()); err != nil {
		t.Fatalf("second WaitFirstSnapshot = %v, want nil", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("second WaitFirstSnapshot took %v, want ~immediate", elapsed)
	}
	if client.listCount() != listsAfterReady {
		t.Fatalf("second WaitFirstSnapshot triggered %d extra lists", client.listCount()-listsAfterReady)
	}
}
