package collector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Observer is the plain-HTTP surface: a human-facing dashboard plus the
// harness-facing internal endpoints. It is served on a separate listener from
// ingest so that read, enumerate, and reset can never be reached over the
// HTTPS ingest port. In the demo this listener is cluster-internal (operator
// eyes and the test harness), which is why /internal/reset lives here.
type Observer struct {
	store *Store
}

// NewObserver builds the observer over the shared store.
func NewObserver(store *Store) *Observer {
	return &Observer{store: store}
}

// Handler returns the observer mux.
func (o *Observer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", o.handleIndex)
	mux.HandleFunc("GET /events", o.handleSSE)
	mux.HandleFunc("GET /api/events", o.handleEventsJSON)

	// Harness-facing endpoints. These are the assertion surface for the
	// integration script and are only reachable on this HTTP listener.
	mux.HandleFunc("GET /internal/events", o.handleEventsJSON)
	mux.HandleFunc("GET /internal/count", o.handleCount)
	mux.HandleFunc("POST /internal/reset", o.handleReset)

	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/readyz", handleHealth)
	return mux
}

func (o *Observer) handleEventsJSON(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, o.store.Snapshot())
}

func (o *Observer) handleCount(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"count": o.store.Count()})
}

func (o *Observer) handleReset(w http.ResponseWriter, _ *http.Request) {
	o.store.Reset()
	writeJSON(w, http.StatusOK, map[string]any{"status": "reset"})
}

// handleSSE streams stored events to the browser dashboard using a
// signal-and-pull loop over a monotonic sequence watermark. On connect it
// resumes from the client's Last-Event-ID (set automatically by EventSource on
// reconnect) if present, else from the beginning of the retained window, so a
// reconnect replays only events the client has not already acknowledged. Every
// frame carries an SSE "id:" equal to the event seq, and the loop only ever
// advances the watermark, so no event is delivered twice or out of order even
// across concurrent ingest and reconnects. The write deadline is cleared because
// an SSE response is intentionally long-lived.
func (o *Observer) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	if rc := http.NewResponseController(w); rc != nil {
		// Best-effort: disable the write deadline for this streaming response.
		_ = rc.SetWriteDeadline(time.Time{})
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	// Flush the response headers immediately so the client's connection opens
	// (and EventSource fires onopen) without waiting for the first event or the
	// keepalive tick. Without this, a connect against an empty resume point
	// would stall until a frame is produced.
	flusher.Flush()

	// Subscribe before the first pull so no event added between the initial
	// drain and entering the select loop can be missed: any such event both
	// lands in the buffer (seen by EventsAfter) and raises the signal (a
	// redundant wake that the watermark then makes a no-op).
	id, sig := o.store.Subscribe()
	defer o.store.Unsubscribe(id)

	// watermark is the seq of the last event written to this client. It only
	// increases, which is what guarantees no duplicate and no reordering.
	watermark := lastEventID(r)

	drain := func() bool {
		for _, e := range o.store.EventsAfter(watermark) {
			if !writeSSE(w, flusher, e) {
				return false
			}
			watermark = e.Seq
		}
		return true
	}

	if !drain() { // initial replay from the resume point
		return
	}

	ctx := r.Context()
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case _, open := <-sig:
			if !open {
				return
			}
			if !drain() {
				return
			}
		case <-keepalive.C:
			// Comment frame keeps intermediaries from timing out an idle stream.
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// lastEventID returns the resume watermark for an SSE connection. EventSource
// replays its last seen "id:" in the Last-Event-ID header on reconnect; a
// missing or malformed value resumes from the start of the retained window (0).
func lastEventID(r *http.Request) int64 {
	v := r.Header.Get("Last-Event-ID")
	if v == "" {
		v = r.URL.Query().Get("lastEventId") // convenience for manual/testing use
	}
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// writeSSE emits one event as an SSE frame carrying its seq as the event id. The
// id lets a reconnecting client tell the server exactly where to resume. It
// returns false if the write failed (client gone), signalling the caller to
// stop.
func writeSSE(w http.ResponseWriter, flusher http.Flusher, e Event) bool {
	b, err := json.Marshal(e)
	if err != nil {
		return true // skip a single un-marshalable event rather than tearing down
	}
	if _, err := fmt.Fprintf(w, "id: %d\nevent: diagnostic\ndata: %s\n\n", e.Seq, b); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func (o *Observer) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dashboardHTML)
}
