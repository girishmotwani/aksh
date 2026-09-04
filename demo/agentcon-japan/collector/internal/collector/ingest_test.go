package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// newTestIngest returns an ingest handler over a fresh store with the given cap.
func newTestIngest(t *testing.T, cap int) (*Ingest, *Store) {
	t.Helper()
	store := NewStore(cap)
	return NewIngest(store, MaxBodyBytes, nil), store
}

func postDiagnostics(h http.Handler, body string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, IngestPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(req)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

const validBody = `{"cluster_id":"prod-tokyo-1","namespace":"kagent","pod":"agent-0","summary":"node list and secrets"}`

func TestIngestSuccess(t *testing.T) {
	ingest, store := newTestIngest(t, 10)
	h := ingest.Handler()

	rr := postDiagnostics(h, validBody, nil)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Status    string `json:"status"`
		Seq       int64  `json:"seq"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "accepted" || resp.Seq != 1 || resp.RequestID == "" {
		t.Fatalf("unexpected response %+v", resp)
	}

	if store.Count() != 1 {
		t.Fatalf("store count = %d, want 1", store.Count())
	}
	e := store.Snapshot()[0]
	if e.ClusterID != "prod-tokyo-1" || e.SourceNamespace != "kagent" || e.SourcePod != "agent-0" {
		t.Fatalf("stored event has wrong fields: %+v", e)
	}
	if e.Summary != "node list and secrets" {
		t.Fatalf("summary = %q", e.Summary)
	}
	if e.PayloadSize != len(validBody) {
		t.Fatalf("payload size = %d, want %d", e.PayloadSize, len(validBody))
	}
	if e.Timestamp == "" {
		t.Fatalf("timestamp not set")
	}
}

func TestIngestRequestIDPrecedence(t *testing.T) {
	ingest, store := newTestIngest(t, 10)
	h := ingest.Handler()

	// Body request_id wins over header.
	body := `{"cluster_id":"c1","namespace":"ns","pod":"p","request_id":"body-id"}`
	rr := postDiagnostics(h, body, func(r *http.Request) { r.Header.Set("X-Request-Id", "header-id") })
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rr.Code)
	}
	if got := store.Snapshot()[0].RequestID; got != "body-id" {
		t.Fatalf("request_id = %q, want body-id", got)
	}

	// Header used when body omits it.
	store.Reset()
	rr = postDiagnostics(h, `{"cluster_id":"c1","namespace":"ns","pod":"p"}`, func(r *http.Request) {
		r.Header.Set("X-Request-Id", "header-id")
	})
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rr.Code)
	}
	if got := store.Snapshot()[0].RequestID; got != "header-id" {
		t.Fatalf("request_id = %q, want header-id", got)
	}

	// Neither present -> server mints an id.
	store.Reset()
	rr = postDiagnostics(h, `{"cluster_id":"c1","namespace":"ns","pod":"p"}`, nil)
	if got := store.Snapshot()[0].RequestID; !strings.HasPrefix(got, "req-") {
		t.Fatalf("minted request_id = %q, want req- prefix", got)
	}

	// An invalid client id is ignored in favour of a minted one, not rejected.
	store.Reset()
	rr = postDiagnostics(h, `{"cluster_id":"c1","namespace":"ns","pod":"p","request_id":"bad id!"}`, nil)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (invalid id should degrade, not reject)", rr.Code)
	}
	if got := store.Snapshot()[0].RequestID; !strings.HasPrefix(got, "req-") {
		t.Fatalf("request_id = %q, want minted req-", got)
	}
}

func TestIngestMethodNotAllowed(t *testing.T) {
	ingest, _ := newTestIngest(t, 10)
	h := ingest.Handler()
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(m, IngestPath, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status = %d, want 405", m, rr.Code)
		}
		if allow := rr.Header().Get("Allow"); allow != http.MethodPost {
			t.Fatalf("%s Allow = %q, want POST", m, allow)
		}
	}
}

func TestIngestContentType(t *testing.T) {
	ingest, store := newTestIngest(t, 10)
	h := ingest.Handler()

	// Rejected content types.
	for _, ct := range []string{"", "text/plain", "application/xml", "multipart/form-data"} {
		rr := postDiagnostics(h, validBody, func(r *http.Request) { r.Header.Set("Content-Type", ct) })
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("content-type %q status = %d, want 415", ct, rr.Code)
		}
	}
	// Accepted with a charset parameter.
	rr := postDiagnostics(h, validBody, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
	})
	if rr.Code != http.StatusAccepted {
		t.Fatalf("charset content-type status = %d, want 202", rr.Code)
	}
	if store.Count() != 1 {
		t.Fatalf("count = %d, want 1", store.Count())
	}
}

func TestIngestValidation(t *testing.T) {
	ingest, store := newTestIngest(t, 10)
	h := ingest.Handler()

	cases := map[string]string{
		"not json":            `not json at all`,
		"missing cluster_id":  `{"namespace":"ns","pod":"p"}`,
		"missing namespace":   `{"cluster_id":"c","pod":"p"}`,
		"missing pod":         `{"cluster_id":"c","namespace":"ns"}`,
		"bad namespace upper": `{"cluster_id":"c","namespace":"NotALabel","pod":"p"}`,
		"bad namespace char":  `{"cluster_id":"c","namespace":"ns_underscore","pod":"p"}`,
		"bad pod char":        `{"cluster_id":"c","namespace":"ns","pod":"pod/slash"}`,
		"bad cluster char":    `{"cluster_id":"c id","namespace":"ns","pod":"p"}`,
		"too long namespace":  fmt.Sprintf(`{"cluster_id":"c","namespace":"%s","pod":"p"}`, strings.Repeat("a", 64)),
		"too long cluster":    fmt.Sprintf(`{"cluster_id":"%s","namespace":"ns","pod":"p"}`, strings.Repeat("a", 129)),
	}
	for name, body := range cases {
		rr := postDiagnostics(h, body, nil)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body=%s", name, rr.Code, rr.Body.String())
		}
	}
	if store.Count() != 0 {
		t.Fatalf("store count = %d, want 0 after all-invalid inputs", store.Count())
	}
}

func TestIngestUnknownFieldsIgnoredNotEchoed(t *testing.T) {
	ingest, store := newTestIngest(t, 10)
	h := ingest.Handler()

	body := `{"cluster_id":"c1","namespace":"ns","pod":"p","secret":"AKIA-TOPSECRET","token":"hunter2","nested":{"k":"v"}}`
	rr := postDiagnostics(h, body, nil)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rr.Code)
	}
	e := store.Snapshot()[0]
	blob, _ := json.Marshal(e)
	if bytes.Contains(blob, []byte("AKIA-TOPSECRET")) || bytes.Contains(blob, []byte("hunter2")) {
		t.Fatalf("stored event echoed unknown/secret fields: %s", blob)
	}
	if e.PayloadSize != len(body) {
		t.Fatalf("payload size = %d, want %d", e.PayloadSize, len(body))
	}
}

func TestIngestSummarySanitizedAndBounded(t *testing.T) {
	ingest, store := newTestIngest(t, 10)
	h := ingest.Handler()

	long := strings.Repeat("x", 1000)
	body, _ := json.Marshal(map[string]string{
		"cluster_id": "c1", "namespace": "ns", "pod": "p",
		"summary": "line1\nline2\x07\ttabbed " + long,
	})
	rr := postDiagnostics(h, string(body), nil)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rr.Code)
	}
	s := store.Snapshot()[0].Summary
	if len(s) > maxSummaryLen {
		t.Fatalf("summary length = %d, want <= %d", len(s), maxSummaryLen)
	}
	if strings.ContainsAny(s, "\n\x07") {
		t.Fatalf("summary retained control characters: %q", s)
	}
}

func TestIngestBodyLimit(t *testing.T) {
	store := NewStore(10)
	// Small limit to make the test fast and deterministic.
	ingest := NewIngest(store, 128, nil)
	h := ingest.Handler()

	big := fmt.Sprintf(`{"cluster_id":"c1","namespace":"ns","pod":"p","summary":"%s"}`, strings.Repeat("a", 512))
	if len(big) <= 128 {
		t.Fatal("test body is not larger than the limit")
	}
	rr := postDiagnostics(h, big, nil)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", rr.Code, rr.Body.String())
	}
	if store.Count() != 0 {
		t.Fatalf("oversized body was stored: count = %d", store.Count())
	}
}

func TestProbeFilteredNotStored(t *testing.T) {
	ingest, store := newTestIngest(t, 10)
	h := ingest.Handler()

	for _, m := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(m, ProbePath, strings.NewReader(validBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("%s %s status = %d, want 204", m, ProbePath, rr.Code)
		}
	}
	if store.Count() != 0 {
		t.Fatalf("probe traffic became events: count = %d", store.Count())
	}
}

func TestIngestListenerHasNoResetOrEnumerate(t *testing.T) {
	ingest, _ := newTestIngest(t, 10)
	h := ingest.Handler()

	// The ingest listener must not expose read/reset surfaces.
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/internal/reset"},
		{http.MethodGet, "/internal/events"},
		{http.MethodGet, "/internal/count"},
		{http.MethodGet, "/api/events"},
		{http.MethodGet, "/"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s %s on ingest listener = %d, want 404 (must not be exposed)", tc.method, tc.path, rr.Code)
		}
	}
}

func TestIngestConcurrentAndBounded(t *testing.T) {
	const cap = 50
	const workers = 16
	const perWorker = 40
	store := NewStore(cap)
	ingest := NewIngest(store, MaxBodyBytes, nil)
	h := ingest.Handler()

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				body := fmt.Sprintf(`{"cluster_id":"c1","namespace":"ns","pod":"p","request_id":"w%d-i%d"}`, w, i)
				rr := postDiagnostics(h, body, nil)
				if rr.Code != http.StatusAccepted {
					t.Errorf("status = %d", rr.Code)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if got := store.Count(); got != cap {
		t.Fatalf("store count = %d, want cap %d after %d writes", got, cap, workers*perWorker)
	}
	// Sequence numbers must be unique and monotonic across the retained window.
	snap := store.Snapshot()
	for i := 1; i < len(snap); i++ {
		if snap[i].Seq <= snap[i-1].Seq {
			t.Fatalf("seq not strictly increasing at %d: %d then %d", i, snap[i-1].Seq, snap[i].Seq)
		}
	}
}
