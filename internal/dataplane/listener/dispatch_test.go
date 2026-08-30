package listener

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
)

// resolveFakeResolver is a dataplane.DestinationResolver test double whose
// Resolve outcome (a success AddrPort or a T1 error) is injected per-test.
type resolveFakeResolver struct {
	dst   netip.AddrPort
	err   error
	sleep time.Duration
}

func (r resolveFakeResolver) Resolve(conn net.Conn) (netip.AddrPort, error) {
	if r.sleep > 0 {
		time.Sleep(r.sleep)
	}
	return r.dst, r.err
}

// capturingHandler records whether Handle was called and the OriginalDst it
// observed on the ConnContext.
type capturingHandler struct {
	mu              sync.Mutex
	called          int
	lastOriginalDst netip.AddrPort
}

func (h *capturingHandler) Handle(ctx context.Context, cc *ConnContext) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.called++
	h.lastOriginalDst = cc.OriginalDst
	return nil
}

func (h *capturingHandler) calledCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.called
}

// closeRecordingConn is a net.Conn test double recording whether Close ran.
type closeRecordingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeRecordingConn) Close() error               { c.closed.Store(true); return nil }
func (c *closeRecordingConn) Read(b []byte) (int, error) { return 0, io.EOF }

func newResolveListener(resolver resolveFakeResolver, h ConnHandler, m audit.MetricsRecorder, log *slog.Logger) *Listener {
	return &Listener{
		resolver: resolver,
		handler:  h,
		metrics:  m,
		log:      log,
		sem:      make(chan struct{}, 1),
	}
}

// firstStageDuration returns the recorded duration of the first StageDuration
// call for stage and whether one was found.
func firstStageDuration(m *recordingMetrics, stage audit.StageName) (time.Duration, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, s := range m.stageNames {
		if s == stage {
			return m.latencies[i], true
		}
	}
	return 0, false
}

// firstStageIndex returns the index of the first StageDuration call for stage,
// or -1.
func firstStageIndex(m *recordingMetrics, stage audit.StageName) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, s := range m.stageNames {
		if s == stage {
			return i
		}
	}
	return -1
}

// Test #56: on a successful Resolve, cc.OriginalDst is set to the returned
// AddrPort and the handler is called.
func TestResolve_Success_SetsOriginalDstAndCallsHandler(t *testing.T) {
	dst := netip.MustParseAddrPort("10.0.0.9:443")
	h := &capturingHandler{}
	m := &recordingMetrics{}
	l := newResolveListener(resolveFakeResolver{dst: dst}, h, m, discardLogger())

	l.dispatch(context.Background(), &closeRecordingConn{}, time.Now())
	l.wg.Wait()

	if got := h.calledCount(); got != 1 {
		t.Fatalf("handler called %d times, want 1", got)
	}
	h.mu.Lock()
	gotDst := h.lastOriginalDst
	h.mu.Unlock()
	if gotDst != dst {
		t.Fatalf("cc.OriginalDst = %v, want %v", gotDst, dst)
	}
}

// Test #57: on a resolve error (T1) the connection is closed and the handler
// is NOT called (fail-closed; never dispatch with a zero OriginalDst).
func TestResolve_Error_ClosesConnAndDoesNotCallHandler(t *testing.T) {
	h := &capturingHandler{}
	m := &recordingMetrics{}
	l := newResolveListener(resolveFakeResolver{err: errors.New("no original destination")}, h, m, discardLogger())
	conn := &closeRecordingConn{}

	l.dispatch(context.Background(), conn, time.Now())
	l.wg.Wait()

	if got := h.calledCount(); got != 0 {
		t.Fatalf("handler called %d times, want 0 (fail-closed)", got)
	}
	if !conn.closed.Load() {
		t.Fatalf("connection was not closed on resolve error")
	}
}

// Test #58: on a resolve error, Decisions(Deny, ReasonNoOriginalDst,
// TransportTLS, false) is recorded.
func TestResolve_Error_RecordsDenyDecisionWithReasonNoOriginalDst(t *testing.T) {
	m := &recordingMetrics{}
	l := newResolveListener(resolveFakeResolver{err: errors.New("no original destination")}, &capturingHandler{}, m, discardLogger())

	l.dispatch(context.Background(), &closeRecordingConn{}, time.Now())
	l.wg.Wait()

	tk, found := m.transportFor("deny/no_original_dst")
	if !found {
		m.mu.Lock()
		got := m.decisions
		m.mu.Unlock()
		t.Fatalf("decisions = %v, want one entry \"deny/no_original_dst\"", got)
	}
	if tk != audit.TransportTLS {
		t.Fatalf("deny/no_original_dst transport = %v, want %v", tk, audit.TransportTLS)
	}
	if fault, _ := m.faultFor("deny/no_original_dst"); fault {
		t.Fatalf("deny/no_original_dst fault = true, want false (a missing original dst is not a runtime fault)")
	}
}

// Test #59: on a resolve error, TransportReject(RejectClassNoOriginalDst,
// BoundNone) is recorded (a missing original destination is not a bound).
func TestResolve_Error_RecordsTransportRejectNoOriginalDstBoundNone(t *testing.T) {
	m := &recordingMetrics{}
	l := newResolveListener(resolveFakeResolver{err: errors.New("no original destination")}, &capturingHandler{}, m, discardLogger())

	l.dispatch(context.Background(), &closeRecordingConn{}, time.Now())
	l.wg.Wait()

	want := audit.RejectClassNoOriginalDst.String() + ":" + audit.BoundNone.String()
	if !m.hasReject(want) {
		m.mu.Lock()
		got := m.transportRejects
		m.mu.Unlock()
		t.Fatalf("TransportReject calls = %v, want one entry %q", got, want)
	}
}

// Test #60: StageAcceptDispatch is recorded before the new resolve step with
// unchanged semantics -- its duration excludes resolve latency.
func TestDispatch_AcceptDispatchStage_RecordedBeforeResolveWithUnchangedSemantics(t *testing.T) {
	m := &recordingMetrics{}
	// A slow resolver makes StageResolve latency clearly larger than the
	// (near-zero) accept-to-dispatch gap, proving StageAcceptDispatch does
	// not include resolve latency.
	l := newResolveListener(resolveFakeResolver{dst: netip.MustParseAddrPort("10.0.0.9:443"), sleep: 200 * time.Millisecond}, &capturingHandler{}, m, discardLogger())

	l.dispatch(context.Background(), &closeRecordingConn{}, time.Now())
	l.wg.Wait()

	adIdx := firstStageIndex(m, audit.StageAcceptDispatch)
	resIdx := firstStageIndex(m, audit.StageResolve)
	if adIdx < 0 {
		t.Fatalf("StageAcceptDispatch was never recorded")
	}
	if resIdx < 0 {
		t.Fatalf("StageResolve was never recorded")
	}
	if adIdx >= resIdx {
		t.Fatalf("StageAcceptDispatch index = %d, StageResolve index = %d; want accept-dispatch recorded first", adIdx, resIdx)
	}
	adDur, _ := firstStageDuration(m, audit.StageAcceptDispatch)
	resDur, _ := firstStageDuration(m, audit.StageResolve)
	if adDur >= resDur {
		t.Fatalf("StageAcceptDispatch duration = %v, StageResolve duration = %v; accept-dispatch must exclude resolve latency", adDur, resDur)
	}
}

// Test #61: on success, StageDuration(StageResolve, ...) is observed.
func TestResolve_Success_RecordsStageResolveLatency(t *testing.T) {
	m := &recordingMetrics{}
	l := newResolveListener(resolveFakeResolver{dst: netip.MustParseAddrPort("10.0.0.9:443")}, &capturingHandler{}, m, discardLogger())

	l.dispatch(context.Background(), &closeRecordingConn{}, time.Now())
	l.wg.Wait()

	if _, found := firstStageDuration(m, audit.StageResolve); !found {
		t.Fatalf("StageResolve latency was not recorded on success")
	}
}

// Test #62: on a resolve error, a WARN is logged for the rejected connection.
func TestResolve_Error_LogsWarnNoOriginalDst(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	m := &recordingMetrics{}
	l := newResolveListener(resolveFakeResolver{err: errors.New("no original destination")}, &capturingHandler{}, m, log)

	l.dispatch(context.Background(), &closeRecordingConn{}, time.Now())
	l.wg.Wait()

	out := buf.String()
	if !strings.Contains(out, "no_original_dst") {
		t.Fatalf("log output = %q, want a WARN mentioning \"no_original_dst\"", out)
	}
	if !strings.Contains(out, "level=WARN") {
		t.Fatalf("log output = %q, want a WARN-level record", out)
	}
}

// Test #63: with a nil (noop) metrics recorder, the resolve-error reject path
// does not panic.
func TestResolve_NilMetricsRecorder_NoPanicOnReject(t *testing.T) {
	h := &capturingHandler{}
	l := &Listener{
		resolver: resolveFakeResolver{err: errors.New("no original destination")},
		handler:  h,
		metrics:  nil,
		log:      discardLogger(),
		sem:      make(chan struct{}, 1),
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("dispatch panicked with nil metrics recorder: %v", r)
		}
	}()
	l.dispatch(context.Background(), &closeRecordingConn{}, time.Now())
	l.wg.Wait()

	if got := h.calledCount(); got != 0 {
		t.Fatalf("handler called %d times, want 0", got)
	}
}

// Test #64: the listener maps every resolve error to exactly one T1 reject;
// the T2 loop-guard is recorded inside the resolver, so the listener does not
// re-classify or double-count.
func TestResolve_LoopGuardError_MappedToSingleT1NoDoubleCount(t *testing.T) {
	m := &recordingMetrics{}
	// A loop-guard (T2) surfaces to the listener as a plain resolve error.
	l := newResolveListener(resolveFakeResolver{err: errors.New("loop guard")}, &capturingHandler{}, m, discardLogger())

	l.dispatch(context.Background(), &closeRecordingConn{}, time.Now())
	l.wg.Wait()

	m.mu.Lock()
	rejects := append([]string(nil), m.transportRejects...)
	decisions := append([]string(nil), m.decisions...)
	m.mu.Unlock()

	if len(rejects) != 1 {
		t.Fatalf("TransportReject calls = %v, want exactly one (single T1, no double-count)", rejects)
	}
	want := audit.RejectClassNoOriginalDst.String() + ":" + audit.BoundNone.String()
	if rejects[0] != want {
		t.Fatalf("TransportReject = %q, want %q", rejects[0], want)
	}
	n := 0
	for _, d := range decisions {
		if d == "deny/no_original_dst" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("deny/no_original_dst decisions = %d, want exactly 1", n)
	}
}

// Test #65: even on a resolve failure, StageResolve latency is observed (the
// stage timing brackets the resolve attempt regardless of outcome).
func TestResolve_Error_ObservesResolveStageLatencyEvenOnFailure(t *testing.T) {
	m := &recordingMetrics{}
	l := newResolveListener(resolveFakeResolver{err: errors.New("no original destination")}, &capturingHandler{}, m, discardLogger())

	l.dispatch(context.Background(), &closeRecordingConn{}, time.Now())
	l.wg.Wait()

	if _, found := firstStageDuration(m, audit.StageResolve); !found {
		t.Fatalf("StageResolve latency was not recorded on resolve failure")
	}
}
