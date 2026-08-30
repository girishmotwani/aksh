package entra_test

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/girishmotwani/aksh/internal/token"
	"github.com/girishmotwani/aksh/internal/token/entra"
)

// Supplementary (non-binding) regression tests covering dev-review iter0 fixes:
//   - HTTP 408 Request Timeout must classify as Transient (was Permanent).
//   - A truncated/aborted response body read must classify as Transient rather
//     than falling through to a Permanent empty-access-token failure.

// TestAcquire_HTTP408_ReturnsTransientAcquireError verifies 408 is retryable.
func TestAcquire_HTTP408_ReturnsTransientAcquireError(t *testing.T) {
	f := newFakeEntra(t, func(w http.ResponseWriter, _ string) {
		w.WriteHeader(http.StatusRequestTimeout)
		_, _ = w.Write([]byte(`{"error":"request_timeout"}`))
	})
	opts := validOptions()
	opts.Authority = f.server.URL
	opts.SATokenPath = writeSAToken(t, "assertion")
	opts.HTTPClient = f.server.Client()
	a, err := entra.NewAcquirer(opts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Acquire(context.Background(), entraRC())
	ae := asAcquireError(t, err)
	if ae.Class != token.AcquireErrorTransient {
		t.Fatalf("class = %v, want Transient", ae.Class)
	}
}

// TestAcquire_TruncatedBody_ReturnsTransientAcquireError verifies that a body
// read error on an otherwise-200 response is not misclassified as a permanent
// empty-token failure. The server announces a large Content-Length then aborts.
func TestAcquire_TruncatedBody_ReturnsTransientAcquireError(t *testing.T) {
	f := newFakeEntra(t, func(w http.ResponseWriter, _ string) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("ResponseWriter is not a Hijacker")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		writeTruncatedResponse(conn, buf)
	})
	opts := validOptions()
	opts.Authority = f.server.URL
	opts.SATokenPath = writeSAToken(t, "assertion")
	opts.HTTPClient = f.server.Client()
	a, err := entra.NewAcquirer(opts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Acquire(context.Background(), entraRC())
	ae := asAcquireError(t, err)
	if ae.Class != token.AcquireErrorTransient {
		t.Fatalf("class = %v, want Transient", ae.Class)
	}
}

// writeTruncatedResponse sends a 200 response whose already-written bytes are
// VALID JSON with an empty access_token, but declares far more Content-Length
// than it delivers and then closes the connection. Without the read-error check
// the client would decode the partial `{}` successfully and misclassify the
// empty token as a Permanent failure; with the check it must be Transient.
func writeTruncatedResponse(conn net.Conn, buf *bufio.ReadWriter) {
	_, _ = buf.WriteString("HTTP/1.1 200 OK\r\n")
	_, _ = buf.WriteString("Content-Type: application/json\r\n")
	_, _ = buf.WriteString("Content-Length: 4096\r\n\r\n")
	_, _ = buf.WriteString(`{}`)
	_ = buf.Flush()
	_ = conn.Close()
}
