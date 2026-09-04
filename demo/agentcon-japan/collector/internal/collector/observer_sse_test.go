package collector

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// sseFrame is a parsed Server-Sent-Events frame.
type sseFrame struct {
	id    string
	event string
	data  string
}

// openSSE connects to the observer /events stream with an optional Last-Event-ID
// and returns a channel of parsed frames plus a cancel func. The reader runs
// until cancelled or the connection closes.
func openSSE(t *testing.T, baseURL, lastEventID string) (<-chan sseFrame, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/events", nil)
	if err != nil {
		cancel()
		t.Fatalf("new request: %v", err)
	}
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("connect SSE: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		t.Fatalf("SSE status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		resp.Body.Close()
		cancel()
		t.Fatalf("SSE content-type = %q", ct)
	}

	out := make(chan sseFrame, 1024)
	go func() {
		defer resp.Body.Close()
		defer close(out)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		var f sseFrame
		var have bool
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if have {
					select {
					case out <- f:
					case <-ctx.Done():
						return
					}
				}
				f, have = sseFrame{}, false
			case strings.HasPrefix(line, ":"):
				// comment / keepalive; ignore
			case strings.HasPrefix(line, "id:"):
				f.id = strings.TrimSpace(line[len("id:"):])
				have = true
			case strings.HasPrefix(line, "event:"):
				f.event = strings.TrimSpace(line[len("event:"):])
				have = true
			case strings.HasPrefix(line, "data:"):
				f.data = strings.TrimSpace(line[len("data:"):])
				have = true
			}
		}
	}()
	return out, cancel
}

// collect reads up to n frames or fails after the timeout.
func collect(t *testing.T, ch <-chan sseFrame, n int, timeout time.Duration) []sseFrame {
	t.Helper()
	frames := make([]sseFrame, 0, n)
	deadline := time.After(timeout)
	for len(frames) < n {
		select {
		case f, ok := <-ch:
			if !ok {
				t.Fatalf("SSE stream closed after %d frames, want %d", len(frames), n)
			}
			frames = append(frames, f)
		case <-deadline:
			t.Fatalf("timed out after %d frames, want %d", len(frames), n)
		}
	}
	return frames
}

// TestSSEFramesCarrySeqIDsInOrder verifies every frame has an id: equal to its
// seq, delivered oldest-first, with no duplicates.
func TestSSEFramesCarrySeqIDsInOrder(t *testing.T) {
	store := NewStore(100)
	addValid(store, 4) // seqs 1..4
	srv := httptest.NewServer(NewObserver(store).Handler())
	defer srv.Close()

	ch, cancel := openSSE(t, srv.URL, "")
	defer cancel()

	frames := collect(t, ch, 4, 3*time.Second)
	for i, f := range frames {
		wantSeq := strconv.Itoa(i + 1)
		if f.id != wantSeq {
			t.Fatalf("frame %d id = %q, want %q", i, f.id, wantSeq)
		}
		if f.event != "diagnostic" {
			t.Fatalf("frame %d event = %q, want diagnostic", i, f.event)
		}
		if !strings.Contains(f.data, `"seq":`+wantSeq) {
			t.Fatalf("frame %d data missing seq %s: %s", i, wantSeq, f.data)
		}
	}
}

// TestSSEReconnectResumesFromLastEventID verifies a reconnect replays only
// events after the acknowledged watermark, so a reconnect never re-delivers what
// the client already received.
func TestSSEReconnectResumesFromLastEventID(t *testing.T) {
	store := NewStore(100)
	addValid(store, 5) // seqs 1..5
	srv := httptest.NewServer(NewObserver(store).Handler())
	defer srv.Close()

	// Reconnect having last seen seq 3: must receive only 4 and 5.
	ch, cancel := openSSE(t, srv.URL, "3")
	defer cancel()
	frames := collect(t, ch, 2, 3*time.Second)
	if frames[0].id != "4" || frames[1].id != "5" {
		t.Fatalf("resume ids = [%s,%s], want [4,5]", frames[0].id, frames[1].id)
	}

	// A watermark at or beyond the latest yields no replay; a subsequent live
	// event still arrives exactly once.
	ch2, cancel2 := openSSE(t, srv.URL, "5")
	defer cancel2()
	store.Add(Event{ClusterID: "c", SourceNamespace: "n", SourcePod: "p"}) // seq 6
	live := collect(t, ch2, 1, 3*time.Second)
	if live[0].id != "6" {
		t.Fatalf("post-resume live id = %s, want 6", live[0].id)
	}
	// Nothing older than 6 should have been delivered on this connection.
	select {
	case extra, ok := <-ch2:
		if ok {
			t.Fatalf("unexpected extra frame id=%s on resumed-at-latest stream", extra.id)
		}
	case <-time.After(150 * time.Millisecond):
	}
}

// TestSSEConcurrentIngestOrderedNoDuplicates streams to a live subscriber while
// events are ingested concurrently, then asserts the subscriber saw every seq
// exactly once and in strictly increasing order. This is the regression guard
// for the old subscribe-before-snapshot duplication and post-unlock reordering.
func TestSSEConcurrentIngestOrderedNoDuplicates(t *testing.T) {
	const total = 300
	store := NewStore(total + 10) // large enough that nothing is evicted
	srv := httptest.NewServer(NewObserver(store).Handler())
	defer srv.Close()

	// Connect first so the subscriber is registered before ingest begins; the
	// initial drain plus signal-driven pulls must still yield no duplicates.
	ch, cancel := openSSE(t, srv.URL, "")
	defer cancel()

	var wg sync.WaitGroup
	for w := 0; w < 10; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < total/10; i++ {
				store.Add(Event{
					ClusterID:       "c",
					SourceNamespace: "ns",
					SourcePod:       fmt.Sprintf("p%d", w),
				})
			}
		}(w)
	}
	wg.Wait()

	frames := collect(t, ch, total, 10*time.Second)

	seen := make(map[int64]bool, total)
	var prev int64
	for i, f := range frames {
		seq, err := strconv.ParseInt(f.id, 10, 64)
		if err != nil {
			t.Fatalf("frame %d has non-numeric id %q", i, f.id)
		}
		if seen[seq] {
			t.Fatalf("duplicate seq %d delivered", seq)
		}
		seen[seq] = true
		if seq <= prev {
			t.Fatalf("out-of-order delivery at %d: %d after %d", i, seq, prev)
		}
		prev = seq
	}
	if len(seen) != total {
		t.Fatalf("distinct seqs = %d, want %d", len(seen), total)
	}
	// Contiguous 1..total: ordered and complete within the retained window.
	for s := int64(1); s <= total; s++ {
		if !seen[s] {
			t.Fatalf("missing seq %d", s)
		}
	}
}

// TestSSENoDuplicateWhenEventArrivesDuringSubscribe exercises the window between
// Subscribe and the initial drain: an event added there must be delivered
// exactly once (either by the initial drain or the follow-up signal, never
// both).
func TestSSENoDuplicateWhenEventArrivesDuringSubscribe(t *testing.T) {
	for trial := 0; trial < 50; trial++ {
		store := NewStore(100)
		srv := httptest.NewServer(NewObserver(store).Handler())

		// Race a single ingest against the SSE connect/drain.
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Add(Event{ClusterID: "c", SourceNamespace: "n", SourcePod: "p"})
		}()

		ch, cancel := openSSE(t, srv.URL, "")
		frames := collect(t, ch, 1, 3*time.Second)
		if frames[0].id != "1" {
			t.Fatalf("trial %d: first id = %s, want 1", trial, frames[0].id)
		}
		// Assert no second copy of seq 1 arrives.
		select {
		case f, ok := <-ch:
			if ok && f.id == "1" {
				t.Fatalf("trial %d: seq 1 delivered twice", trial)
			}
		case <-time.After(50 * time.Millisecond):
		}
		cancel()
		wg.Wait()
		srv.Close()
	}
}
