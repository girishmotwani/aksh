package listener_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

// fakeDialer is a test double for dataplane.UpstreamDialer used by
// PassthroughHandler tests.
type fakeDialer struct {
	mu       sync.Mutex
	conn     net.Conn
	err      error
	dialedAt []netip.AddrPort
}

func (d *fakeDialer) DialUpstream(ctx context.Context, addr netip.AddrPort, serverName string, credID string) (net.Conn, error) {
	d.mu.Lock()
	d.dialedAt = append(d.dialedAt, addr)
	d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

// passthroughMetrics captures Decisions calls.
type passthroughMetrics struct {
	audit.NopMetricsRecorder
	mu         sync.Mutex
	decisions  []string
	transports map[string]audit.TransportKind
	faults     map[string]bool
}

func (m *passthroughMetrics) Decisions(d pipeline.Disposition, r pipeline.DenyReason, transport audit.TransportKind, fault bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := d.String() + ":" + r.String()
	m.decisions = append(m.decisions, key)
	if m.transports == nil {
		m.transports = make(map[string]audit.TransportKind)
	}
	if m.faults == nil {
		m.faults = make(map[string]bool)
	}
	m.transports[key] = transport
	m.faults[key] = fault
}

func (m *passthroughMetrics) transportFor(s string) (audit.TransportKind, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.transports[s]
	return t, ok
}

func (m *passthroughMetrics) faultFor(s string) (bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.faults[s]
	return f, ok
}

func (m *passthroughMetrics) has(s string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.decisions {
		if d == s {
			return true
		}
	}
	return false
}

// countingLogHandler is a minimal slog.Handler test double that increments
// count for every Handle call, used to assert a log line was emitted
// without depending on log-record formatting.
type countingLogHandler struct {
	count *atomic.Int32
}

func (h countingLogHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h countingLogHandler) Handle(context.Context, slog.Record) error {
	h.count.Add(1)
	return nil
}
func (h countingLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h countingLogHandler) WithGroup(name string) slog.Handler       { return h }

// to assert idempotent-close behaviour and completion ordering.
type countingCloseConn struct {
	net.Conn
	mu     sync.Mutex
	closes int
}

func (c *countingCloseConn) Close() error {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()
	return c.Conn.Close()
}

func (c *countingCloseConn) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

// failingCloseWriteConn wraps a net.Conn and implements the halfCloser
// interface (CloseWrite() error), returning a caller-supplied non-nil,
// non-closed-conn error to exercise the path where closeWrite's error was
// previously silently discarded.
type failingCloseWriteConn struct {
	net.Conn
	closeWriteErr error
	closeWriteN   atomic.Int32
}

func (c *failingCloseWriteConn) CloseWrite() error {
	c.closeWriteN.Add(1)
	return c.closeWriteErr
}

// discardConn is a net.Conn whose Read blocks (returning EOF-shaped wrapped
// errors on demand via wrappedCloseErrConn) and whose Write discards.
// discardConn's Read blocks until Close is called (not unconditionally, so a
// test using it can reliably unblock it rather than depend on scheduling or
// risk deadlocking the whole test run if the code under test never closes
// it).
type discardConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func newDiscardConn() *discardConn { return &discardConn{closed: make(chan struct{})} }

func (d *discardConn) Read(b []byte) (int, error) {
	<-d.closed
	return 0, net.ErrClosed
}
func (d *discardConn) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardConn) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

// wrappedCloseErrConn returns a *net.OpError wrapping net.ErrClosed from
// Read, simulating what real closed sockets typically return (never a bare
// net.ErrClosed/io.EOF value).
type wrappedCloseErrConn struct{ net.Conn }

func (w *wrappedCloseErrConn) Read(b []byte) (int, error) {
	return 0, &net.OpError{Op: "read", Err: net.ErrClosed}
}
func (w *wrappedCloseErrConn) Write(b []byte) (int, error) { return len(b), nil }
func (w *wrappedCloseErrConn) Close() error {
	if w.Conn != nil {
		return w.Conn.Close()
	}
	return nil
}

// eofOnReadFailOnWriteConn returns io.EOF immediately from Read (so the
// up<-down copy direction finishes cleanly at once) but returns a genuine,
// non-closed-conn error from Write (so the down<-up copy direction fails for
// a real reason, not because anything was closed).
type eofOnReadFailOnWriteConn struct{ net.Conn }

func (c *eofOnReadFailOnWriteConn) Read(b []byte) (int, error) {
	return 0, io.EOF
}
func (c *eofOnReadFailOnWriteConn) Write(b []byte) (int, error) {
	return 0, errors.New("simulated write failure")
}
func (c *eofOnReadFailOnWriteConn) Close() error { return nil }

// failWriteConn yields data bytes once from Read (then io.EOF), and always
// fails Write with a distinct, genuine (non-closed-conn) error, so both
// io.Copy directions in Handle can be driven to a real Write failure
// simultaneously.
type failWriteConn struct {
	net.Conn
	data     []byte
	done     atomic.Bool
	writeErr error
}

func (c *failWriteConn) Read(b []byte) (int, error) {
	if c.done.Swap(true) {
		return 0, io.EOF
	}
	n := copy(b, c.data)
	return n, nil
}
func (c *failWriteConn) Write(b []byte) (int, error) { return 0, c.writeErr }
func (c *failWriteConn) Close() error                { return nil }

// oneShotDataConn yields data bytes once from Read, then returns io.EOF.
// Read blocks on ready until it's closed, giving the down<-up copy direction
// data to write (and thus a chance to hit eofOnReadFailOnWriteConn's Write
// failure) only after the other copy direction has already completed --
// determinism via explicit signalling instead of a fixed sleep.
type oneShotDataConn struct {
	net.Conn
	data  []byte
	ready chan struct{}
	done  atomic.Bool
}

func (c *oneShotDataConn) Read(b []byte) (int, error) {
	if c.done.Swap(true) {
		return 0, io.EOF
	}
	if c.ready != nil {
		<-c.ready
	}
	n := copy(b, c.data)
	return n, nil
}
func (c *oneShotDataConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *oneShotDataConn) Close() error                { return nil }

// signalOnEOFConn wraps a net.Conn and closes ready the first time its Read
// returns io.EOF, letting a test deterministically observe "this copy
// direction has completed" without a fixed sleep.
type signalOnEOFConn struct {
	net.Conn
	ready chan struct{}
	fired atomic.Bool
}

func (c *signalOnEOFConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == io.EOF && c.fired.CompareAndSwap(false, true) {
		close(c.ready)
	}
	return n, err
}

func newTCPFreeConnContext(down net.Conn) *listener.ConnContext {
	return &listener.ConnContext{
		ConnID:       "test-conn",
		Downstream:   down,
		OriginalDst:  netip.MustParseAddrPort("10.0.0.5:443"),
		Protocol:     listener.ProtocolTLS,
		CandidateSNI: "example.internal",
		AcceptedAt:   time.Now(),
	}
}

func TestPassthroughHandler(t *testing.T) {
	t.Run("Handle_FrozenInterfaceSignature_MatchesConnHandler", func(t *testing.T) {
		var _ listener.ConnHandler = (*listener.PassthroughHandler)(nil)
	})

	t.Run("Handle_NilConnContext_ReturnsErrorWithoutPanic", func(t *testing.T) {
		// Regression test for the dev-review finding that a nil
		// *ConnContext (as opposed to a non-nil ConnContext with a nil
		// Downstream, covered above) silently returned nil (success),
		// hiding a caller bug the same way errNilDownstream now does for
		// the Downstream case.
		h := &listener.PassthroughHandler{
			Dialer:  &fakeDialer{},
			Metrics: &passthroughMetrics{},
			Log:     slog.Default(),
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Handle panicked with nil ConnContext: %v", r)
			}
		}()
		err := h.Handle(context.Background(), nil)
		if err == nil {
			t.Fatalf("Handle() error = nil, want non-nil error for nil ConnContext")
		}
	})

	t.Run("Handle_NilConn_ReturnsWithoutPanic", func(t *testing.T) {
		// Regression test for the dev-review finding that a non-nil
		// ConnContext with a nil Downstream silently returned nil
		// (success), hiding what is almost certainly a caller bug. Handle
		// must now return a descriptive error instead of swallowing it.
		h := &listener.PassthroughHandler{
			Dialer:  &fakeDialer{},
			Metrics: &passthroughMetrics{},
			Log:     slog.Default(),
		}
		cc := &listener.ConnContext{ConnID: "nil-conn", Downstream: nil, Protocol: listener.ProtocolTLS}
		var err error
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Handle panicked with nil Downstream: %v", r)
			}
		}()
		err = h.Handle(context.Background(), cc)
		if err == nil {
			t.Fatalf("Handle() error = nil, want non-nil error for nil Downstream")
		}
	})

	t.Run("Handle_UnsupportedProtocol_RecordsRejectionDecision", func(t *testing.T) {
		// Regression test for the dev-review finding that the
		// unsupported-protocol early return closed the connection and
		// returned ErrUnsupportedProtocol without ever calling
		// RecordDecision, unlike the dial-failure path just below it
		// (which does), leaving this rejection reason invisible in
		// metrics.
		metrics := &passthroughMetrics{}
		h := &listener.PassthroughHandler{
			Dialer:  &fakeDialer{},
			Metrics: metrics,
			Log:     slog.Default(),
		}
		down, downPeer := net.Pipe()
		defer downPeer.Close()
		cc := newTCPFreeConnContext(down)
		cc.Protocol = listener.ProtocolUnknown

		err := h.Handle(context.Background(), cc)
		if !errors.Is(err, listener.ErrUnsupportedProtocol) {
			t.Fatalf("Handle() error = %v, want ErrUnsupportedProtocol", err)
		}
		if !metrics.has("deny:unsupported_protocol") {
			t.Fatalf("RecordDecision calls = %v, want one entry \"deny:unsupported_protocol\"", metrics.decisions)
		}
		// ProtocolUnknown/ProtocolH2CPreface never presented a TLS
		// handshake, so the rejection must not be labelled tls.
		if tk, _ := metrics.transportFor("deny:unsupported_protocol"); tk != audit.TransportPlaintext {
			t.Fatalf("unsupported-protocol transport = %v, want %v", tk, audit.TransportPlaintext)
		}
	})

	t.Run("Handle_NilDialer_ReturnsErrorWithoutPanic", func(t *testing.T) {
		// Regression test for the dev-review finding that Handle
		// dereferences h.Dialer without a nil check: a zero-value or
		// partially initialized PassthroughHandler (Dialer left nil)
		// previously panicked instead of returning a descriptive error.
		h := &listener.PassthroughHandler{Metrics: &passthroughMetrics{}, Log: slog.Default()}
		down, downPeer := net.Pipe()
		defer downPeer.Close()
		cc := newTCPFreeConnContext(down)

		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Handle panicked with nil Dialer: %v", r)
				}
			}()
			err = h.Handle(context.Background(), cc)
		}()
		if err == nil {
			t.Fatalf("Handle() error = nil, want a non-nil error for nil Dialer")
		}
	})

	t.Run("Handle_CloseWriteFails_LogsErrorInsteadOfSilentlyDiscarding", func(t *testing.T) {
		// Regression test for the dev-review finding that closeWrite's
		// CloseWrite() error return was discarded entirely: a failed FIN
		// (e.g. because the connection was already reset) could leave the
		// peer's reverse-direction read blocked forever with no signal
		// that half-close never actually happened.
		var logged atomic.Int32
		h := &listener.PassthroughHandler{
			Dialer:  &fakeDialer{},
			Metrics: &passthroughMetrics{},
			Log:     slog.New(countingLogHandler{count: &logged}),
		}
		downBase, downPeer := net.Pipe()
		down := &failingCloseWriteConn{Conn: downBase, closeWriteErr: errors.New("simulated CloseWrite failure")}
		up, upPeer := net.Pipe()
		h.Dialer.(*fakeDialer).conn = up
		cc := newTCPFreeConnContext(down)

		downPeer.Close()
		upPeer.Close()

		if err := h.Handle(context.Background(), cc); err != nil {
			t.Fatalf("Handle() error = %v, want nil", err)
		}

		if logged.Load() == 0 {
			t.Fatalf("CloseWrite failure was not logged, want at least one ERROR log entry")
		}
	})

	t.Run("Handle_SuccessfulForward_ClosesBothConnsOnCompletion", func(t *testing.T) {
		downA, downB := net.Pipe()
		upA, upB := net.Pipe()
		down := &countingCloseConn{Conn: downA}
		up := &countingCloseConn{Conn: upA}

		dialer := &fakeDialer{conn: up}
		h := &listener.PassthroughHandler{Dialer: dialer, Metrics: &passthroughMetrics{}, Log: slog.Default()}
		cc := newTCPFreeConnContext(down)

		done := make(chan error, 1)
		go func() { done <- h.Handle(context.Background(), cc) }()

		// Simulate the downstream client sending one byte, the upstream
		// server echoing it, and both peers then closing so Handle's
		// bidirectional copy naturally reaches EOF on both sides. Report
		// any unexpected Read/Write failure via echoErrCh instead of
		// silently discarding it, since a failure here would otherwise
		// just make Handle time out with no indication why.
		echoErrCh := make(chan error, 1)
		go func() {
			buf := make([]byte, 1)
			if _, err := downB.Write([]byte("x")); err != nil {
				echoErrCh <- fmt.Errorf("downB.Write: %w", err)
				return
			}
			if _, err := upB.Read(buf); err != nil {
				echoErrCh <- fmt.Errorf("upB.Read: %w", err)
				return
			}
			if _, err := upB.Write(buf); err != nil {
				echoErrCh <- fmt.Errorf("upB.Write: %w", err)
				return
			}
			if _, err := downB.Read(buf); err != nil {
				echoErrCh <- fmt.Errorf("downB.Read: %w", err)
				return
			}
			downB.Close()
			upB.Close()
			echoErrCh <- nil
		}()

		select {
		case err := <-done:
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("Handle() error = %v, want nil/EOF", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Handle() did not complete")
		}
		if err := <-echoErrCh; err != nil {
			t.Fatalf("echo goroutine failed: %v", err)
		}

		if down.closeCount() == 0 {
			t.Fatal("downstream conn was not closed")
		}
		if up.closeCount() == 0 {
			t.Fatal("upstream conn was not closed")
		}
	})

	t.Run("PassthroughHandler_NonTCPProtocol_ClosesConnWithoutForwarding", func(t *testing.T) {
		downA, downB := net.Pipe()
		defer downB.Close()
		down := &countingCloseConn{Conn: downA}
		dialer := &fakeDialer{}
		h := &listener.PassthroughHandler{Dialer: dialer, Metrics: &passthroughMetrics{}, Log: slog.Default()}
		cc := newTCPFreeConnContext(down)
		cc.Protocol = listener.ProtocolUnknown // not TCP-forwardable

		if err := h.Handle(context.Background(), cc); err == nil {
			t.Fatal("Handle() error = nil, want non-nil for non-forwardable protocol")
		}
		if down.closeCount() == 0 {
			t.Fatal("downstream conn was not closed for non-forwardable protocol")
		}
		if len(dialer.dialedAt) != 0 {
			t.Fatal("DialUpstream was called for a non-forwardable protocol")
		}
	})

	t.Run("PassthroughHandler_UpstreamDialFails_RecordsRejectionAndCloses", func(t *testing.T) {
		downA, downB := net.Pipe()
		defer downB.Close()
		down := &countingCloseConn{Conn: downA}
		dialer := &fakeDialer{err: errors.New("dial failed")}
		metrics := &passthroughMetrics{}
		h := &listener.PassthroughHandler{Dialer: dialer, Metrics: metrics, Log: slog.Default()}
		cc := newTCPFreeConnContext(down)

		if err := h.Handle(context.Background(), cc); err == nil {
			t.Fatal("Handle() error = nil, want non-nil on dial failure")
		}
		if down.closeCount() == 0 {
			t.Fatal("downstream conn was not closed on dial failure")
		}
		if !metrics.has("deny:dial_failed") {
			t.Fatalf("RecordDecision not called with deny:dial_failed, got %v", metrics.decisions)
		}
	})

	t.Run("PassthroughHandler_UpstreamDialFailsPlaintext_LabelsPlaintextTransport", func(t *testing.T) {
		downA, downB := net.Pipe()
		defer downB.Close()
		down := &countingCloseConn{Conn: downA}
		dialer := &fakeDialer{err: errors.New("dial failed")}
		metrics := &passthroughMetrics{}
		h := &listener.PassthroughHandler{Dialer: dialer, Metrics: metrics, Log: slog.Default()}
		cc := newTCPFreeConnContext(down)
		cc.Protocol = listener.ProtocolHTTP1

		if err := h.Handle(context.Background(), cc); err == nil {
			t.Fatal("Handle() error = nil, want non-nil on dial failure")
		}
		if !metrics.has("deny:dial_failed") {
			t.Fatalf("RecordDecision not called with deny:dial_failed, got %v", metrics.decisions)
		}
		// The dial-failed rejection must carry the connection's real
		// transport (plaintext here) rather than a hardcoded tls label.
		if tk, _ := metrics.transportFor("deny:dial_failed"); tk != audit.TransportPlaintext {
			t.Fatalf("dial-failed transport = %v, want %v", tk, audit.TransportPlaintext)
		}
		// A dial failure is a dependency fault, not a clean policy denial.
		if f, _ := metrics.faultFor("deny:dial_failed"); !f {
			t.Fatalf("dial-failed fault = false, want true")
		}
	})

	t.Run("Handle_ContextCancelledMidForward_ClosesConnsPromptly", func(t *testing.T) {
		downA, downB := net.Pipe()
		upA, upB := net.Pipe()
		defer downB.Close()
		defer upB.Close()
		down := &countingCloseConn{Conn: downA}
		up := &countingCloseConn{Conn: upA}
		dialer := &fakeDialer{conn: up}
		h := &listener.PassthroughHandler{Dialer: dialer, Metrics: &passthroughMetrics{}, Log: slog.Default()}
		cc := newTCPFreeConnContext(down)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- h.Handle(ctx, cc) }()

		// Deterministically confirm forwarding has started before
		// cancelling, instead of a fixed time.Sleep (dev-review finding:
		// a bare sleep is timing-dependent and can flake on a loaded CI
		// machine if Handle's copy goroutines have not yet been
		// scheduled). Push one byte through the downstream pipe and read
		// it back out on upB, which only succeeds once Handle's
		// downstream->upstream io.Copy is actively running.
		started := make(chan struct{})
		go func() {
			downB.Write([]byte("x"))
			buf := make([]byte, 1)
			upB.Read(buf)
			close(started)
		}()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("forwarding did not start within 2s")
		}
		cancel()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Handle() did not return promptly after context cancellation")
		}
		if down.closeCount() == 0 {
			t.Fatal("downstream conn was not closed after context cancellation")
		}
		if up.closeCount() == 0 {
			t.Fatal("upstream conn was not closed after context cancellation")
		}
	})

	t.Run("Handle_CopyReturnsWrappedClosedConnError_TreatsAsNormalCompletionNotError", func(t *testing.T) {
		// io.Copy's returned error for a closed connection is frequently
		// wrapped (e.g. by *net.OpError), not a bare io.EOF/net.ErrClosed
		// value. Handle must recognise it via errors.Is/errors.As rather
		// than direct == comparison, or a routine shutdown is misreported
		// as a forwarding failure.
		downA, downB := net.Pipe()
		up := &wrappedCloseErrConn{Conn: newDiscardConn()}
		dialer := &fakeDialer{conn: up}
		h := &listener.PassthroughHandler{Dialer: dialer, Metrics: &passthroughMetrics{}, Log: slog.Default()}
		cc := newTCPFreeConnContext(&countingCloseConn{Conn: downA})

		done := make(chan error, 1)
		go func() { done <- h.Handle(context.Background(), cc) }()
		downB.Close()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Handle() error = %v, want nil for a wrapped closed-conn error", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Handle() did not complete")
		}
	})

	t.Run("Handle_SecondCopyDirectionErrorsAfterFirstCompletesCleanly_ErrorIsNotSilentlyDiscarded", func(t *testing.T) {
		// down.Read returns io.EOF immediately, so io.Copy(up, down)
		// completes with a nil error. up's Read blocks until that direction
		// signals completion (via the ready channel below), so up's data
		// (and thus down.Write's genuine failure) is only produced after
		// the first direction has deterministically finished -- no fixed
		// sleep needed either way, since Handle must surface a genuine
		// second-direction error regardless of arrival order.
		ready := make(chan struct{})
		down := &signalOnEOFConn{Conn: &eofOnReadFailOnWriteConn{}, ready: ready}
		up := &oneShotDataConn{data: []byte("hello"), ready: ready}
		dialer := &fakeDialer{conn: up}
		h := &listener.PassthroughHandler{Dialer: dialer, Metrics: &passthroughMetrics{}, Log: slog.Default()}
		cc := newTCPFreeConnContext(down)

		err := h.Handle(context.Background(), cc)
		if err == nil {
			t.Fatal("Handle() error = nil, want the genuine write error from the second copy direction")
		}
	})

	t.Run("Handle_BothCopyDirectionsErrorGenuinely_BothErrorsAreObservable", func(t *testing.T) {
		// Regression test for the dev-review finding that when both copy
		// directions produce genuine (non-closed-conn) errors, Handle
		// returned only the first one received from errCh and silently
		// discarded the second, making asymmetric dual-failure scenarios
		// hard to debug. Both down and up produce data (so both
		// io.Copy(up, down) and io.Copy(down, up) reach a Write call) and
		// both Writes fail with distinct, identifiable errors; both
		// errors must be observable in Handle's returned error regardless
		// of which direction's error arrives on errCh first.
		downErr := errors.New("down write failed")
		upErr := errors.New("up write failed")
		down := &failWriteConn{data: []byte("down-data"), writeErr: downErr}
		up := &failWriteConn{data: []byte("up-data"), writeErr: upErr}
		dialer := &fakeDialer{conn: up}
		h := &listener.PassthroughHandler{Dialer: dialer, Metrics: &passthroughMetrics{}, Log: slog.Default()}
		cc := newTCPFreeConnContext(down)

		err := h.Handle(context.Background(), cc)
		if err == nil {
			t.Fatal("Handle() error = nil, want both copy-direction errors to be observable")
		}
		if !errors.Is(err, downErr) {
			t.Fatalf("Handle() error = %v, want it to contain downErr (%v)", err, downErr)
		}
		if !errors.Is(err, upErr) {
			t.Fatalf("Handle() error = %v, want it to contain upErr (%v)", err, upErr)
		}
	})

	t.Run("Handle_OneConnectionErrorsDuringCopy_DoesNotAffectOtherActiveHandlers", func(t *testing.T) {
		// Handler A: upstream dial fails immediately.
		downA1, downA2 := net.Pipe()
		defer downA2.Close()
		downConnA := &countingCloseConn{Conn: downA1}
		dialerA := &fakeDialer{err: errors.New("dial failed")}
		hA := &listener.PassthroughHandler{Dialer: dialerA, Metrics: &passthroughMetrics{}, Log: slog.Default()}
		ccA := newTCPFreeConnContext(downConnA)

		// Handler B: succeeds normally, run concurrently with A.
		downB1, downB2 := net.Pipe()
		upB1, upB2 := net.Pipe()
		downConnB := &countingCloseConn{Conn: downB1}
		upConnB := &countingCloseConn{Conn: upB1}
		dialerB := &fakeDialer{conn: upConnB}
		hB := &listener.PassthroughHandler{Dialer: dialerB, Metrics: &passthroughMetrics{}, Log: slog.Default()}
		ccB := newTCPFreeConnContext(downConnB)

		var wg sync.WaitGroup
		var errA, errB error
		wg.Add(2)
		go func() { defer wg.Done(); errA = hA.Handle(context.Background(), ccA) }()
		go func() {
			defer wg.Done()
			go func() {
				// Regression fix for the dev-review finding that this
				// echo goroutine discarded all Read/Write return values
				// and had no deferred Close: if any call failed, the
				// goroutine returned early without ever closing downB2/
				// upB2, which could leave Handle's io.Copy blocked
				// forever waiting on a connection nobody closes. Both
				// connections are now closed via defer regardless of
				// which step fails.
				defer downB2.Close()
				defer upB2.Close()
				buf := make([]byte, 1)
				if _, err := downB2.Write([]byte("y")); err != nil {
					return
				}
				if _, err := upB2.Read(buf); err != nil {
					return
				}
				if _, err := upB2.Write(buf); err != nil {
					return
				}
				downB2.Read(buf)
			}()
			errB = hB.Handle(context.Background(), ccB)
		}()

		// Regression fix for the dev-review finding that wg.Wait() had no
		// timeout guard: if the echo goroutine above ever hung (e.g. a
		// future regression reintroducing a discarded-error early
		// return without the defers), this test would hang indefinitely
		// instead of failing with a clear diagnostic.
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("handlers did not complete within 5s")
		}

		if errA == nil {
			t.Fatal("handler A error = nil, want non-nil (dial failure)")
		}
		if errB != nil && !errors.Is(errB, io.EOF) {
			t.Fatalf("handler B error = %v, want nil/EOF (should be unaffected by A's failure)", errB)
		}
	})

	t.Run("Handle_DoubleCloseOfDownstreamConn_IsIdempotent", func(t *testing.T) {
		downA, downB := net.Pipe()
		down := &countingCloseConn{Conn: downA}
		dialer := &fakeDialer{err: errors.New("dial failed")}
		h := &listener.PassthroughHandler{Dialer: dialer, Metrics: &passthroughMetrics{}, Log: slog.Default()}
		cc := newTCPFreeConnContext(down)

		_ = h.Handle(context.Background(), cc)
		defer downB.Close()

		// A second, independent Close() on the same downstream conn (as would
		// happen if a second goroutine also attempted to close it) must not
		// panic or return an unexpected error type.
		if err := down.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("second Close() error = %v, want nil or net.ErrClosed", err)
		}
	})

	t.Run("Handle_ReverseDirectionStillFlowing_NotTruncatedWhenForwardDirectionFinishesFirst", func(t *testing.T) {
		// Regression test for the dev-review finding that closing both
		// sockets as soon as the first copy direction completes could
		// truncate the other, still-in-flight direction. Use real TCP
		// loopback connections (which support CloseWrite/half-close,
		// unlike net.Pipe) so down->up can reach EOF first while up->down
		// still has unread data queued; that data must still arrive at
		// down intact rather than being cut off by an early full Close.
		downLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen() error = %v", err)
		}
		defer downLn.Close()
		upLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen() error = %v", err)
		}
		defer upLn.Close()

		// downClient <-> down (Handle's Downstream side).
		downAcceptCh := make(chan net.Conn, 1)
		downAcceptErrCh := make(chan error, 1)
		go func() {
			c, err := downLn.Accept()
			if err != nil {
				downAcceptErrCh <- err
				return
			}
			downAcceptCh <- c
		}()
		downClient, err := net.Dial("tcp4", downLn.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial() error = %v", err)
		}
		defer downClient.Close()
		var down net.Conn
		select {
		case down = <-downAcceptCh:
		case acceptErr := <-downAcceptErrCh:
			t.Fatalf("downLn.Accept() error = %v", acceptErr)
		}

		// upClient <-> up (Handle's dialed upstream side, via fakeDialer).
		upAcceptCh := make(chan net.Conn, 1)
		upAcceptErrCh := make(chan error, 1)
		go func() {
			c, err := upLn.Accept()
			if err != nil {
				upAcceptErrCh <- err
				return
			}
			upAcceptCh <- c
		}()
		upClient, err := net.Dial("tcp4", upLn.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial() error = %v", err)
		}
		defer upClient.Close()
		var up net.Conn
		select {
		case up = <-upAcceptCh:
		case acceptErr := <-upAcceptErrCh:
			t.Fatalf("upLn.Accept() error = %v", acceptErr)
		}

		dialer := &fakeDialer{conn: up}
		h := &listener.PassthroughHandler{Dialer: dialer, Metrics: &passthroughMetrics{}, Log: slog.Default()}
		cc := newTCPFreeConnContext(down)

		done := make(chan error, 1)
		go func() { done <- h.Handle(context.Background(), cc) }()

		// downClient signals EOF on the down->up direction immediately by
		// half-closing its own write side (down->up copy reaches EOF and
		// completes with a nil error).
		if tc, ok := downClient.(*net.TCPConn); ok {
			tc.CloseWrite()
		} else {
			t.Fatal("downClient is not *net.TCPConn")
		}

		// Wait for the down->up direction to genuinely complete before
		// upClient sends its still-pending reverse-direction payload:
		// downClient's CloseWrite below propagates through Handle's
		// io.Copy(up, down) as EOF, then Handle half-closes up's write
		// side, which upClient observes as its own EOF when draining.
		// This is deterministic signalling via the conn itself, not a
		// fixed sleep, so this test would fail (truncated read) against
		// the pre-fix closeBoth-on-first-completion code, not by
		// coincidence of timing.
		drainBuf := make([]byte, 1)
		upClient.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			_, readErr := upClient.Read(drainBuf)
			if readErr != nil {
				break
			}
		}
		upClient.SetReadDeadline(time.Time{})

		payload := []byte("reverse-direction-payload-must-not-be-truncated")
		if _, err := upClient.Write(payload); err != nil {
			t.Fatalf("upClient.Write() error = %v", err)
		}
		upClient.Close()

		got := make([]byte, 0, len(payload))
		buf := make([]byte, len(payload))
		downClient.SetReadDeadline(time.Now().Add(3 * time.Second))
		for len(got) < len(payload) {
			n, err := downClient.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				break
			}
		}
		if string(got) != string(payload) {
			t.Fatalf("downClient received %q, want %q (reverse direction was truncated)", got, payload)
		}

		select {
		case err := <-done:
			if err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("Handle() error = %v, want nil/EOF", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Handle() did not complete")
		}
	})
}
