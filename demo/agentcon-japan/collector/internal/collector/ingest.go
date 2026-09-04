package collector

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
)

// IngestPath is the single diagnostic ingest endpoint.
const IngestPath = "/api/v1/cluster-diagnostics"

// ProbePath is the aksh dataplane keepalive/redirect-probe path. Traffic to it
// must never become a diagnostic event, otherwise every keepalive would show up
// in the observer UI and pollute the demo.
const ProbePath = "/__aksh_probe"

// Ingest is the HTTPS-facing handler set. It accepts sanitized diagnostic
// reports and answers health/probe traffic. It deliberately exposes no way to
// read, enumerate, or reset stored events: the ingest listener is write-only so
// an agent that reaches it cannot exfiltrate what the collector has seen or
// tamper with the harness's view.
type Ingest struct {
	store        *Store
	maxBodyBytes int64
	logger       *log.Logger
}

// NewIngest builds the ingest handler. A non-positive maxBodyBytes falls back to
// MaxBodyBytes so the body limit is always enforced.
func NewIngest(store *Store, maxBodyBytes int64, logger *log.Logger) *Ingest {
	if maxBodyBytes <= 0 {
		maxBodyBytes = MaxBodyBytes
	}
	return &Ingest{store: store, maxBodyBytes: maxBodyBytes, logger: logger}
}

// Handler returns the HTTPS ingest mux. Only the ingest, probe, and health
// routes exist; every other path is a 404. Reset is intentionally absent here.
func (in *Ingest) Handler() http.Handler {
	mux := http.NewServeMux()
	// The probe is filtered first-class so keepalive traffic is a cheap 204 and
	// never touches the store or the report parser.
	mux.HandleFunc(ProbePath, in.handleProbe)
	mux.HandleFunc(IngestPath, in.handleDiagnostics)
	mux.HandleFunc("/healthz", handleHealth)
	mux.HandleFunc("/readyz", handleHealth)
	return mux
}

func (in *Ingest) handleProbe(w http.ResponseWriter, _ *http.Request) {
	// No body, no storage: a keepalive is not a diagnostic event.
	w.WriteHeader(http.StatusNoContent)
}

func (in *Ingest) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !hasJSONContentType(r) {
		writeError(w, http.StatusUnsupportedMediaType, "content-type must be application/json")
		return
	}

	// Bound the body before reading a single byte of it. MaxBytesReader also
	// causes reads past the limit to fail, so a lying Content-Length cannot
	// slip an oversized body through.
	r.Body = http.MaxBytesReader(w, r.Body, in.maxBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds limit")
			return
		}
		writeError(w, http.StatusBadRequest, "could not read request body")
		return
	}

	var report diagnosticReport
	if err := json.Unmarshal(raw, &report); err != nil {
		// The parser error is not echoed; it can contain body fragments.
		writeError(w, http.StatusBadRequest, "request body is not valid JSON")
		return
	}

	event, err := sanitize(report, r.Header.Get("X-Request-Id"), len(raw))
	if err != nil {
		var ve *validationError
		if errors.As(err, &ve) {
			writeError(w, http.StatusBadRequest, ve.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	stored := in.store.Add(event)
	if in.logger != nil {
		// Log only bounded, already-sanitized fields, never the raw body.
		in.logger.Printf("ingest accepted seq=%d request_id=%s namespace=%s pod=%s cluster=%s bytes=%d",
			stored.Seq, stored.RequestID, stored.SourceNamespace, stored.SourcePod, stored.ClusterID, stored.PayloadSize)
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":     "accepted",
		"seq":        stored.Seq,
		"request_id": stored.RequestID,
	})
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

// hasJSONContentType accepts application/json with an optional parameter such as
// a charset, and nothing else. Strictly typing the ingest keeps form posts and
// opaque blobs out of the parser.
func hasJSONContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/json")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
