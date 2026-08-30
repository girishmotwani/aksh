package requestpath

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	iaudit "github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/pipeline"
	dto "github.com/prometheus/client_model/go"

	"github.com/prometheus/client_golang/prometheus"
)

// sumByDisposition totals every aksh_decisions_total series carrying the
// given disposition, regardless of its other labels. The point of these
// tests is the *count* of decisions per connection, so a bug that merely
// shifts the reason label must not be able to hide from them.
func sumByDisposition(fam *dto.MetricFamily, disposition string) float64 {
	if fam == nil {
		return 0
	}
	var total float64
	for _, m := range fam.GetMetric() {
		for _, lp := range m.GetLabel() {
			if lp.GetName() == "disposition" && lp.GetValue() == disposition {
				total += m.GetCounter().GetValue()
			}
		}
	}
	return total
}

// latchE2E wires a real *listener.Listener to a real *requestpath.Handler --
// the same seam production uses -- with a single Prometheus recorder shared
// by both layers, which is what makes cross-layer double counting visible.
type latchE2E struct {
	addr string
	reg  *prometheus.Registry
	stop func()
}

func newLatchE2E(t *testing.T, p *pipeline.Pipeline, dialer dataplane.UpstreamDialer, sink *recordingSink) *latchE2E {
	t.Helper()

	reg := prometheus.NewRegistry()
	metrics, err := iaudit.NewPromMetricsRecorder(reg)
	if err != nil {
		t.Fatalf("NewPromMetricsRecorder() error = %v", err)
	}

	handler, err := NewHandler(p, dialer, sink, metrics, DefaultOptions())
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	lopts := listener.DefaultOptions()
	lopts.ListenAddr = netip.MustParseAddrPort("127.0.0.1:0")
	lopts.Handler = tlsMarkingHandler{next: handler}
	lopts.Metrics = metrics

	l, err := listener.New(lopts, e2eResolver{}, lopts.Handler, lopts.Metrics,
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
	waitForServingE2E(t, l)

	var stopOnce sync.Once
	return &latchE2E{
		addr: l.Addr().String(),
		reg:  reg,
		stop: func() {
			// Idempotent: serveDone is drained exactly once. A second
			// receive would block forever, since Serve only ever sends one
			// value.
			stopOnce.Do(func() {
				cancel()
				<-serveDone
			})
		},
	}
}

// waitDecisions polls until the summed aksh_decisions_total for the given
// disposition reaches want, or the deadline expires. Polling rather than
// stopping the listener is deliberate: the listener's rollup is recorded by
// the per-connection dispatch goroutine after Handle returns, so it is not
// ordered against the client seeing its response, and shutting the listener
// down to force ordering would couple these assertions to drain semantics
// that are not what is under test.
func waitDecisions(t *testing.T, reg *prometheus.Registry, disposition string, want float64) float64 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var got float64
	for time.Now().Before(deadline) {
		got = sumByDisposition(famDecisions(t, reg), disposition)
		if got >= want {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	return got
}

// TestListenerToHandler_ExactlyOneDecisionPerConnection is the regression
// test for issue #89.
//
// aksh_decisions_total is specified as one sample per terminal connection
// outcome (docs/design/S9b-production-wiring.md; UnitTests spec row 174
// requires "exactly one RecordDecision call reflecting its eventual
// disposition"). Before the decision latch, every layer recorded
// independently and the listener added an unconditional rollup on top, so a
// 6-hour soak at a steady 10 allowed + 10 denied req/s produced
// allow=687847 deny=229038 -- exactly 3.005x the true allow rate.
//
// The single worst symptom is asserted first: a policy-DENIED connection was
// counted as an ALLOW. The handler writes its 403 to the wire and returns nil
// from Handle, so the rollup's else-branch treated the connection as
// successful. Alerting on the allow/deny ratio was therefore not merely
// noisy, it was inverted for denials.
func TestListenerToHandler_ExactlyOneDecisionPerConnection(t *testing.T) {
	const conns = 3

	t.Run("PolicyDeniedConnections_RecordOneDenyEachAndNeverAnAllow", func(t *testing.T) {
		sink := &recordingSink{}
		dialer := &scriptedDialer{fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			t.Error("DialUpstream must not be called for a denied request")
			return nil, io.EOF
		}}
		e := newLatchE2E(t, denyPipeline(sink, pipeline.ReasonNoMatch), dialer, sink)
		defer e.stop()

		for i := 0; i < conns; i++ {
			conn, err := net.Dial("tcp4", e.addr)
			if err != nil {
				t.Fatalf("net.Dial() error = %v", err)
			}
			if _, err := io.WriteString(conn, "GET /deny HTTP/1.1\r\nHost: api.example.com\r\n\r\n"); err != nil {
				t.Fatalf("write request: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("ReadResponse() error = %v", err)
			}
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("StatusCode = %d, want 403", resp.StatusCode)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			conn.Close()
		}
		waitAuditCount(t, sink, conns)

		if got := waitDecisions(t, e.reg, "deny", conns); got != conns {
			t.Fatalf("deny decisions = %v, want %d (exactly one per denied connection)", got, conns)
		}
		fam := famDecisions(t, e.reg)
		if got := sumByDisposition(fam, "allow"); got != 0 {
			t.Fatalf("allow decisions = %v, want 0. Denied connections were counted as ALLOWS: "+
				"the handler writes its 403 to the wire and returns nil from Handle, so the "+
				"listener's post-Handle rollup took its success branch (issue #89)", got)
		}
	})

	t.Run("AllowedConnections_RecordOneAllowEachAndNoDeny", func(t *testing.T) {
		sink := &recordingSink{}
		dialer := &scriptedDialer{fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					return
				}
				_, _ = upstreamConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
			}()
			return handlerConn, nil
		}}
		e := newLatchE2E(t, allowRelayPipeline(sink, "cred-1"), dialer, sink)
		defer e.stop()

		for i := 0; i < conns; i++ {
			conn, err := net.Dial("tcp4", e.addr)
			if err != nil {
				t.Fatalf("net.Dial() error = %v", err)
			}
			if _, err := io.WriteString(conn, "GET /resource HTTP/1.1\r\nHost: api.example.com\r\n\r\n"); err != nil {
				t.Fatalf("write request: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("ReadResponse() error = %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("StatusCode = %d, want 200", resp.StatusCode)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			conn.Close()
		}
		waitAuditCount(t, sink, conns)

		// Exactly one allow per connection, contributed by the listener's
		// end-of-connection fallback. The other half of the allowed-request
		// double count lived in the upstream dialer, which this test cannot
		// see because it uses a scripted dialer; that half is pinned by
		// upstream.TestDialUpstream_DecisionMetricInvariant's
		// SuccessfulDial_RecordsNoDecision case.
		if got := waitDecisions(t, e.reg, "allow", conns); got != conns {
			t.Fatalf("allow decisions = %v, want %d (exactly one per allowed connection)", got, conns)
		}
		fam := famDecisions(t, e.reg)
		if got := sumByDisposition(fam, "deny"); got != 0 {
			t.Fatalf("deny decisions = %v, want 0 for fully allowed connections", got)
		}
	})
}
