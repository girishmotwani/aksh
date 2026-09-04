package collector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func addValid(store *Store, n int) {
	for i := 0; i < n; i++ {
		store.Add(Event{
			RequestID:       fmt.Sprintf("r%d", i),
			SourceNamespace: "ns",
			SourcePod:       "p",
			ClusterID:       "c1",
			Summary:         "s",
			PayloadSize:     10,
		})
	}
}

func TestStoreBounded(t *testing.T) {
	store := NewStore(5)
	addValid(store, 12)
	if store.Count() != 5 {
		t.Fatalf("count = %d, want 5", store.Count())
	}
	snap := store.Snapshot()
	// Oldest retained should be seq 8 (events 1..7 evicted), newest seq 12.
	if snap[0].Seq != 8 || snap[len(snap)-1].Seq != 12 {
		t.Fatalf("retained window seqs = [%d..%d], want [8..12]", snap[0].Seq, snap[len(snap)-1].Seq)
	}
}

func TestStoreResetPreservesSeq(t *testing.T) {
	store := NewStore(10)
	addValid(store, 3)
	store.Reset()
	if store.Count() != 0 {
		t.Fatalf("count after reset = %d, want 0", store.Count())
	}
	e := store.Add(Event{ClusterID: "c", SourceNamespace: "n", SourcePod: "p"})
	if e.Seq != 4 {
		t.Fatalf("seq after reset = %d, want 4 (monotonic across reset)", e.Seq)
	}
}

func TestStoreZeroCapCoerced(t *testing.T) {
	store := NewStore(0)
	e := store.Add(Event{ClusterID: "c", SourceNamespace: "n", SourcePod: "p"})
	if e.Seq != 1 || store.Count() != 1 {
		t.Fatalf("zero-cap store did not coerce to 1: seq=%d count=%d", e.Seq, store.Count())
	}
}

func TestStoreSignalAndPullDelivery(t *testing.T) {
	store := NewStore(10)
	id, sig := store.Subscribe()
	defer store.Unsubscribe(id)

	store.Add(Event{ClusterID: "c", SourceNamespace: "n", SourcePod: "p", RequestID: "live-1"})
	select {
	case <-sig:
		got := store.EventsAfter(0)
		if len(got) != 1 || got[0].RequestID != "live-1" {
			t.Fatalf("EventsAfter(0) = %+v, want one live-1 event", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for change signal")
	}
}

func TestStoreEventsAfterWatermark(t *testing.T) {
	store := NewStore(10)
	addValid(store, 5) // seqs 1..5
	got := store.EventsAfter(3)
	if len(got) != 2 || got[0].Seq != 4 || got[1].Seq != 5 {
		t.Fatalf("EventsAfter(3) = %+v, want seqs [4,5]", got)
	}
	if n := store.EventsAfter(5); n != nil {
		t.Fatalf("EventsAfter(latest) = %+v, want nil", n)
	}
	if n := store.EventsAfter(0); len(n) != 5 {
		t.Fatalf("EventsAfter(0) len = %d, want 5", len(n))
	}
	if store.LatestSeq() != 5 {
		t.Fatalf("LatestSeq = %d, want 5", store.LatestSeq())
	}
}

func TestStoreSlowSubscriberDoesNotBlock(t *testing.T) {
	store := NewStore(10000)
	// Subscribe but never consume the signal; the coalescing buffer-1 channel
	// stays full and further signals must be dropped rather than blocking Add.
	id, _ := store.Subscribe()
	defer store.Unsubscribe(id)

	done := make(chan struct{})
	go func() {
		addValid(store, 500)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Add blocked on a slow subscriber")
	}
}

func TestStoreConcurrentAddSnapshotRace(t *testing.T) {
	store := NewStore(100)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				store.Add(Event{ClusterID: "c", SourceNamespace: "n", SourcePod: "p"})
			}
		}()
	}
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = store.Snapshot()
				_ = store.Count()
			}
		}()
	}
	wg.Wait()
	if store.Count() != 100 {
		t.Fatalf("count = %d, want cap 100", store.Count())
	}
}

// --- observer / harness endpoint tests ---

func TestObserverCountAndEventsJSON(t *testing.T) {
	store := NewStore(10)
	addValid(store, 3)
	h := NewObserver(store).Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/internal/count", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("count status = %d", rr.Code)
	}
	var c struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &c)
	if c.Count != 3 {
		t.Fatalf("count = %d, want 3", c.Count)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/internal/events", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("events status = %d", rr.Code)
	}
	var events []Event
	if err := json.Unmarshal(rr.Body.Bytes(), &events); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("events len = %d, want 3", len(events))
	}
}

func TestObserverReset(t *testing.T) {
	store := NewStore(10)
	addValid(store, 5)
	h := NewObserver(store).Handler()

	// Reset requires POST; GET must not be allowed.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/internal/reset", nil))
	if rr.Code == http.StatusOK {
		t.Fatalf("GET /internal/reset returned 200; reset must be POST-only")
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/internal/reset", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("POST reset status = %d, want 200", rr.Code)
	}
	if store.Count() != 0 {
		t.Fatalf("count after reset = %d, want 0", store.Count())
	}
}

func TestObserverIndexServesHTML(t *testing.T) {
	h := NewObserver(NewStore(10)).Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("index status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct == "" || ct[:9] != "text/html" {
		t.Fatalf("index content-type = %q, want text/html", ct)
	}
}

func TestObserverSSEReplaysSnapshot(t *testing.T) {
	store := NewStore(10)
	addValid(store, 2)
	srv := httptest.NewServer(NewObserver(store).Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/events", nil)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("SSE content-type = %q", ct)
	}

	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	got := string(buf[:n])
	if !containsAll(got, "event: diagnostic", "data:") {
		t.Fatalf("SSE stream did not replay snapshot frames: %q", got)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
