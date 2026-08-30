package requestpath

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	iaudit "github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/girishmotwani/aksh/internal/policy"
)

// tlsMarkingHandler stands in, in tests, for the production
// tls-terminating handler (internal/runtime.tlsTerminatingConnHandler): it
// marks the ConnContext as already TLS-terminated before delegating to the
// request path, exactly as the real terminator does once the handshake
// completes, without requiring a real certificate/handshake in this test.
type tlsMarkingHandler struct {
	next listener.ConnHandler
}

func (h tlsMarkingHandler) Handle(ctx context.Context, cc *listener.ConnContext) error {
	cc.Protocol = listener.ProtocolTLS
	cc.Transport = policy.TransportTLS
	return h.next.Handle(ctx, cc)
}

// e2eResolver stands in for the BPF-based destination resolver: it reports a
// fixed, valid original destination for every accepted connection so the
// listener's fail-closed T1 resolve check never rejects the test's dials.
type e2eResolver struct{}

func (e2eResolver) Resolve(net.Conn) (netip.AddrPort, error) {
	return netip.MustParseAddrPort("10.0.0.7:443"), nil
}

// TestListenerToHandler_RealAcceptedConnection_RequestIDUsesGeneratedConnID
// is the end-to-end regression test for issue #61: ConnContext.ConnID was
// never assigned by the listener's accept loop, so requestID() always fell
// back to its "req-N" branch instead of "<connid>-N", making every audited
// request indistinguishable by connection. This wires a real
// *listener.Listener to a real *requestpath.Handler (the same seam
// production uses), dials a real TCP connection, and asserts that the
// RequestID recorded by the pipeline's audit sink took the ConnID-based
// branch of requestID(), not the fallback.
func TestListenerToHandler_RealAcceptedConnection_RequestIDUsesGeneratedConnID(t *testing.T) {
	sink := &recordingSink{}
	p := pipeline.NewPipeline([]pipeline.Stage{
		stageFunc{name: "match", fn: func(*pipeline.RequestContext) pipeline.Decision {
			return pipeline.Allow()
		}},
	}, sink)
	handler, err := NewHandler(p, testDialer{}, &recordingSink{}, testMetrics{}, DefaultOptions())
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	lopts := listener.DefaultOptions()
	lopts.ListenAddr = netip.MustParseAddrPort("127.0.0.1:0")
	lopts.Handler = tlsMarkingHandler{next: handler}
	lopts.Metrics = iaudit.NopMetricsRecorder{}

	l, err := listener.New(lopts, e2eResolver{}, lopts.Handler, lopts.Metrics, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("listener.New() error = %v", err)
	}
	if err := l.Bind(); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- l.Serve(ctx) }()
	waitForServingE2E(t, l)

	conn, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}

	waitAuditCount(t, sink, 1)
	cancel()
	<-serveDone

	got := sink.last().RequestID
	if got == "" {
		t.Fatal("RequestID is empty")
	}
	if got == "req-1" {
		t.Fatalf("RequestID = %q, took the connID-less fallback branch of requestID() instead of the ConnID-based branch", got)
	}
	wantSuffix := "-1"
	if len(got) < len(wantSuffix) || got[len(got)-len(wantSuffix):] != wantSuffix {
		t.Fatalf("RequestID = %q, want it to end in %q", got, wantSuffix)
	}
	connID := got[:len(got)-len(wantSuffix)]
	if len(connID) != 32 {
		t.Fatalf("RequestID = %q; connID prefix %q has length %d, want 32", got, connID, len(connID))
	}
	for _, r := range connID {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("RequestID = %q; connID prefix %q contains non-lowercase-hex char %q", got, connID, r)
		}
	}
}

func waitForServingE2E(t *testing.T, l *listener.Listener) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if l.State() == listener.StateServing {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("listener did not reach StateServing within the deadline")
}
