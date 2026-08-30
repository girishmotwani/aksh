package runtime

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/dataplane/listener"
)

// syncBuffer is a concurrency-safe log sink. The connection-handling goroutine
// writes WARN records through slog while the test goroutine reads the captured
// output, so an unguarded strings.Builder would be a data race.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// plaintextResolver stands in for the BPF destination resolver, reporting a
// fixed original destination so the listener's fail-closed T1 check passes and
// the connection reaches the TLS handler.
type plaintextResolver struct{}

func (plaintextResolver) Resolve(net.Conn) (netip.AddrPort, error) {
	return netip.MustParseAddrPort("10.0.0.7:8083"), nil
}

// TestListener_RealPlaintextConnection_ClassifiedAsPlaintextExactlyOnce is the
// end-to-end regression test required by issue #83's final acceptance
// criterion: drive a real plaintext connection through a real listener and
// assert the labels, so the classification cannot silently regress.
//
// Driving it through the listener rather than calling Handle directly is the
// whole point. The listener's post-Handle rollup is what produced the second,
// contradictory sample: the TLS handler returns an error for a refused
// connection, so the rollup recorded internal/fault=true on top of the
// terminator's own decision. One connection, two counters, both labelled
// transport="tls" -- exactly what #83 measured on a kind cluster:
//
//	handshake_failed{transport="tls",fault="true"} 2 -> 3
//	internal{transport="tls",fault="true"}         2 -> 3
func TestListener_RealPlaintextConnection_ClassifiedAsPlaintextExactlyOnce(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	metrics := &fakeTLSMetrics{}
	term := newTestTerminator(t, source, metrics)

	next := &recordingNext{}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	logBuf := &syncBuffer{}
	h.Log = slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	lopts := listener.DefaultOptions()
	lopts.ListenAddr = netip.MustParseAddrPort("127.0.0.1:0")
	lopts.Handler = h
	lopts.Metrics = metrics

	l, err := listener.New(lopts, plaintextResolver{}, lopts.Handler, lopts.Metrics,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("listener.New() error = %v", err)
	}
	if err := l.Bind(); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- l.Serve(ctx) }()
	defer func() {
		cancel()
		<-serveDone
	}()

	deadline := time.Now().Add(3 * time.Second)
	for l.State() != listener.StateServing && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if l.State() != listener.StateServing {
		t.Fatal("listener did not reach StateServing")
	}

	// A plaintext HTTP request, exactly as a captured agent speaking to an
	// in-cluster control plane would send (the #80 failure mode).
	conn, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	if _, err := io.WriteString(conn, "GET /api/sessions HTTP/1.1\r\nHost: controller\r\n\r\n"); err != nil {
		t.Fatalf("write plaintext request: %v", err)
	}
	_, _ = io.Copy(io.Discard, conn)
	conn.Close()

	// The decision is recorded by the dispatch goroutine, which is not ordered
	// against the client's read returning, so poll.
	var got []tlsDecision
	for i := 0; i < 300 && len(got) == 0; i++ {
		got = metrics.allDecisions()
		if len(got) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if len(got) != 1 {
		t.Fatalf("decisions for one plaintext connection = %+v, want exactly 1. Two samples "+
			"means the listener's post-Handle rollup fired on top of the terminator's "+
			"decision (#83 problem 4, #89)", got)
	}
	d := got[0]
	if d.disposition != "deny" || d.reason != "unsupported_protocol" {
		t.Fatalf("decision = %+v, want deny/unsupported_protocol", d)
	}
	if d.transport != "plaintext" {
		t.Fatalf("decision transport = %q, want \"plaintext\" (#83 problem 1)", d.transport)
	}
	if d.fault {
		t.Fatalf("decision fault = true, want false (#83 problem 2): decision = %+v", d)
	}
	if classes := metrics.rejectClasses(); len(classes) != 1 || classes[0] != "plaintext_registry_unavailable" {
		t.Fatalf("transport reject classes = %v, want [plaintext_registry_unavailable] (#83 problem 3)", classes)
	}
	if next.callCount() != 0 {
		t.Fatalf("Next.Handle calls = %d, want 0: a plaintext connection must never reach the request path", next.callCount())
	}

	// #83 problem 5: the destination is the single most useful field for
	// answering "what got refused, and where was it going?". The WARN record is
	// emitted by the dispatch goroutine and is not ordered against the metric
	// recording above, so poll for it (reads go through syncBuffer's mutex).
	var logged string
	for i := 0; i < 300; i++ {
		logged = logBuf.String()
		if strings.Contains(logged, "10.0.0.7:8083") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logged, "10.0.0.7:8083") {
		t.Fatalf("WARN log = %q, want it to name the destination 10.0.0.7:8083", logged)
	}
}
