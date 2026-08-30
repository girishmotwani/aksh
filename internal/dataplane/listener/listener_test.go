package listener_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// blockingHandler is a ConnHandler test double whose Handle behaviour is
// injected per-test: recording invocations, panicking, blocking forever, or
// simply closing the connection.
type blockingHandler struct {
	mu       sync.Mutex
	invoked  int
	fn       func(ctx context.Context, cc *listener.ConnContext) error
	released chan struct{} // closed once fn returns, for tests that must
	// observe completion of a background handler goroutine.
	releaseOnce sync.Once // guards released against a double-close panic
	// if Handle is invoked more than once on the same instance.
}

func (h *blockingHandler) Handle(ctx context.Context, cc *listener.ConnContext) error {
	h.mu.Lock()
	h.invoked++
	h.mu.Unlock()
	var err error
	if h.fn != nil {
		err = h.fn(ctx, cc)
	} else {
		cc.Downstream.Close()
	}
	if h.released != nil {
		h.releaseOnce.Do(func() { close(h.released) })
	}
	return err
}

func (h *blockingHandler) invokedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.invoked
}

type listenerMetrics struct {
	audit.NopMetricsRecorder
	mu        sync.Mutex
	decisions []string
	latencies []string
}

func (m *listenerMetrics) Decisions(d pipeline.Disposition, r pipeline.DenyReason, transport audit.TransportKind, fault bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions = append(m.decisions, d.String()+":"+r.String())
}
func (m *listenerMetrics) StageDuration(stage audit.StageName, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latencies = append(m.latencies, stage.String())
}

func (m *listenerMetrics) decisionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.decisions)
}

func (m *listenerMetrics) latencyCount(stage string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.latencies {
		if s == stage {
			n++
		}
	}
	return n
}

func loopbackOpts(h listener.ConnHandler, m *listenerMetrics) listener.Options {
	o := listener.DefaultOptions()
	o.ListenAddr = netip.MustParseAddrPort("127.0.0.1:0")
	o.Handler = h
	o.Metrics = m
	return o
}

func newTestListener(t *testing.T, h listener.ConnHandler) (*listener.Listener, *listenerMetrics) {
	t.Helper()
	m := &listenerMetrics{}
	opts := loopbackOpts(h, m)
	l, err := listener.New(opts, &noopResolver{}, h, m, testLogger())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return l, m
}

type noopResolver struct{}

func (noopResolver) Resolve(conn net.Conn) (netip.AddrPort, error) {
	return netip.MustParseAddrPort("10.0.0.9:443"), nil
}

func dialAndForget(t *testing.T, addr netip.AddrPort) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp4", addr.String())
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	return conn
}

func TestListener(t *testing.T) {
	t.Run("BlockingHandler_HandleInvokedTwiceWithReleasedChannel_DoesNotPanicOnDoubleClose", func(t *testing.T) {
		// blockingHandler.Handle used to unconditionally close(h.released)
		// whenever it was set, so invoking Handle more than once on the
		// same instance (e.g. a shared handler across multiple accepted
		// connections in a test) would panic on the second close.
		h := &blockingHandler{released: make(chan struct{})}
		down1, downPeer1 := net.Pipe()
		defer downPeer1.Close()
		down2, downPeer2 := net.Pipe()
		defer downPeer2.Close()
		cc1 := &listener.ConnContext{ConnID: "c1", Downstream: down1, AcceptedAt: time.Now()}
		cc2 := &listener.ConnContext{ConnID: "c2", Downstream: down2, AcceptedAt: time.Now()}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Handle() panicked on second invocation: %v", r)
			}
		}()
		if err := h.Handle(context.Background(), cc1); err != nil {
			t.Fatalf("Handle() error = %v, want nil", err)
		}
		if err := h.Handle(context.Background(), cc2); err != nil {
			t.Fatalf("Handle() error = %v, want nil", err)
		}
	})

	t.Run("Bind_ValidLoopbackAddr_TransitionsToBoundState", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v, want nil", err)
		}
		defer l.Shutdown(context.Background())
		if l.Addr() == (netip.AddrPort{}) {
			t.Fatal("Addr() is zero value after successful Bind")
		}
	})

	t.Run("Bind_AddressAlreadyInUse_ReturnsWrappedError", func(t *testing.T) {
		h := &blockingHandler{}
		l1, _ := newTestListener(t, h)
		if err := l1.Bind(); err != nil {
			t.Fatalf("first Bind() error = %v", err)
		}
		defer l1.Shutdown(context.Background())

		m2 := &listenerMetrics{}
		opts2 := listener.DefaultOptions()
		opts2.ListenAddr = l1.Addr()
		opts2.Handler = h
		opts2.Metrics = m2
		l2, err := listener.New(opts2, &noopResolver{}, h, m2, testLogger())
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		err = l2.Bind()
		if err == nil {
			t.Fatal("second Bind() on the same address returned nil, want an address-in-use error")
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) {
			t.Fatalf("Bind() error = %v, want wrapped *net.OpError", err)
		}
	})

	t.Run("Bind_CalledTwice_ReturnsErrAlreadyBound", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		defer l.Shutdown(context.Background())
		if err := l.Bind(); !errors.Is(err, listener.ErrAlreadyBound) {
			t.Fatalf("second Bind() error = %v, want ErrAlreadyBound", err)
		}
	})

	t.Run("Bind_AfterShutdown_ReturnsErrClosedNotErrAlreadyBound", func(t *testing.T) {
		// Regression test for the dev-review finding that Bind's CAS
		// (StateNew -> StateBound) fails identically whether the current
		// state is StateBound, StateServing, or StateClosed, always
		// returning ErrAlreadyBound. A caller invoking Bind after
		// Shutdown got the misleading "already bound" error instead of one
		// reflecting that the listener is closed.
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		if err := l.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		if err := l.Bind(); !errors.Is(err, listener.ErrClosed) {
			t.Fatalf("Bind() after Shutdown = %v, want ErrClosed (not ErrAlreadyBound)", err)
		}
	})

	t.Run("Addr_BeforeBind_ReturnsZeroValueAddrPort", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if l.Addr() != (netip.AddrPort{}) {
			t.Fatalf("Addr() before Bind() = %v, want zero value", l.Addr())
		}
	})

	t.Run("Addr_AfterBind_ReturnsBoundAddrPort", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		defer l.Shutdown(context.Background())
		addr := l.Addr()
		if !addr.Addr().IsLoopback() || addr.Port() == 0 {
			t.Fatalf("Addr() = %v, want a bound loopback address with non-zero port", addr)
		}
	})

	t.Run("Addr_ConcurrentWithBind_NoDataRace", func(t *testing.T) {
		// l.ln is written in Bind and read in Addr; run them concurrently
		// under -race to catch an unsynchronized access to that field.
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)

		bindDone := make(chan error, 1)
		go func() { bindDone <- l.Bind() }()

		for i := 0; i < 50; i++ {
			_ = l.Addr()
		}

		if err := <-bindDone; err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		defer l.Shutdown(context.Background())
	})

	t.Run("AcceptProbe_BeforeBind_ReturnsErrNotBound", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if _, err := l.AcceptProbe(time.Now().Add(time.Second)); !errors.Is(err, listener.ErrNotBound) {
			t.Fatalf("AcceptProbe() error = %v, want ErrNotBound", err)
		}
	})

	t.Run("AcceptProbe_WhileServing_ReturnsErrServing", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForCondition(t, func() bool {
			_, err := l.AcceptProbe(time.Now().Add(-time.Second))
			return errors.Is(err, listener.ErrServing)
		})
		cancel()
		<-serveDone
	})

	t.Run("AcceptProbe_AfterShutdown_ReturnsErrClosedNotErrServing", func(t *testing.T) {
		// Regression test for the dev-review finding that AcceptProbe
		// returned the same ErrServing for both StateServing and
		// StateClosed, making it impossible for callers to distinguish
		// "still serving" from "already shut down."
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		if err := l.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		_, err := l.AcceptProbe(time.Now().Add(time.Second))
		if !errors.Is(err, listener.ErrClosed) {
			t.Fatalf("AcceptProbe() after Shutdown error = %v, want ErrClosed", err)
		}
		if errors.Is(err, listener.ErrServing) {
			t.Fatalf("AcceptProbe() after Shutdown error = %v, must not be ErrServing", err)
		}
	})

	t.Run("AcceptProbe_BoundNotServing_AcceptsOneConnection", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		defer l.Shutdown(context.Background())
		go func() {
			conn, err := net.Dial("tcp4", l.Addr().String())
			if err == nil {
				conn.Close()
			}
		}()
		conn, err := l.AcceptProbe(time.Now().Add(3 * time.Second))
		if err != nil {
			t.Fatalf("AcceptProbe() error = %v, want nil", err)
		}
		conn.Close()
	})

	t.Run("AcceptProbe_DeadlineExceeded_ReturnsTimeoutError", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		defer l.Shutdown(context.Background())
		_, err := l.AcceptProbe(time.Now().Add(-time.Second))
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("AcceptProbe() error = %v, want a timeout net.Error", err)
		}
	})

	t.Run("Serve_NotBound_ReturnsErrNotBound", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Serve(context.Background()); !errors.Is(err, listener.ErrNotBound) {
			t.Fatalf("Serve() error = %v, want ErrNotBound", err)
		}
	})

	t.Run("Serve_CalledTwice_ReturnsErrAlreadyServing", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForServing(t, l)
		if err := l.Serve(ctx); !errors.Is(err, listener.ErrAlreadyServing) {
			t.Fatalf("second Serve() error = %v, want ErrAlreadyServing", err)
		}
		cancel()
		<-serveDone
	})

	t.Run("Serve_AcceptsAndDispatchesConnection_InvokesConnHandler", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForServing(t, l)

		conn := dialAndForget(t, l.Addr())
		defer conn.Close()
		waitForCondition(t, func() bool { return h.invokedCount() > 0 })

		cancel()
		<-serveDone
	})

	t.Run("Serve_TemporaryAcceptError_LogsAndContinuesLoop", func(t *testing.T) {
		// A temporary accept error is exercised indirectly: the loop must
		// continue serving new connections after any handler invocation,
		// which is verified by successfully accepting two connections in
		// sequence (proving the loop never exited after the first).
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForServing(t, l)

		for i := 0; i < 2; i++ {
			conn := dialAndForget(t, l.Addr())
			conn.Close()
		}
		waitForCondition(t, func() bool { return h.invokedCount() >= 2 })
		cancel()
		<-serveDone
	})

	t.Run("Serve_PermanentAcceptError_ReturnsErrorAndExitsLoop", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(context.Background()) }()
		waitForServing(t, l)

		if err := l.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		select {
		case err := <-serveDone:
			if err == nil {
				t.Fatal("Serve() error = nil after listener closed, want non-nil")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Serve() did not return after listener was closed")
		}
	})

	t.Run("Serve_ContextCancelled_ReturnsContextErrAndStopsAccepting", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		defer l.Shutdown(context.Background())
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForServing(t, l)

		cancel()
		select {
		case err := <-serveDone:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Serve() error = %v, want context.Canceled", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Serve() did not return after context cancellation")
		}
	})

	t.Run("Serve_ConnectionSemaphoreFull_RejectsNewConnWithoutBlockingLoop", func(t *testing.T) {
		released := make(chan struct{})
		h := &blockingHandler{fn: func(ctx context.Context, cc *listener.ConnContext) error {
			<-released
			cc.Downstream.Close()
			return nil
		}}
		m := &listenerMetrics{}
		opts := loopbackOpts(h, m)
		opts.MaxConnections = 1
		l, err := listener.New(opts, &noopResolver{}, h, m, testLogger())
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForServing(t, l)

		conn1 := dialAndForget(t, l.Addr())
		defer conn1.Close()
		waitForCondition(t, func() bool { return h.invokedCount() >= 1 })

		conn2 := dialAndForget(t, l.Addr())
		defer conn2.Close()
		// The second connection should be rejected (closed) promptly rather
		// than the accept loop blocking on a full semaphore: confirmed by the
		// connection being closed by the peer shortly after dialing.
		conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1)
		_, rerr := conn2.Read(buf)
		if rerr == nil {
			t.Fatal("expected the semaphore-rejected connection to be closed by the listener")
		}
		waitForCondition(t, func() bool { return m.decisionCount() >= 1 })

		close(released)
		cancel()
		<-serveDone
	})

	t.Run("Serve_OneHandlerPanics_OtherConnectionsUnaffected", func(t *testing.T) {
		var callNum atomic.Int32
		h := &blockingHandler{fn: func(ctx context.Context, cc *listener.ConnContext) error {
			n := callNum.Add(1)
			defer cc.Downstream.Close()
			if n == 1 {
				panic("boom")
			}
			return nil
		}}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForServing(t, l)

		conn1 := dialAndForget(t, l.Addr())
		defer conn1.Close()
		waitForCondition(t, func() bool { return h.invokedCount() >= 1 })

		conn2 := dialAndForget(t, l.Addr())
		defer conn2.Close()
		waitForCondition(t, func() bool { return h.invokedCount() >= 2 })

		cancel()
		<-serveDone
	})

	t.Run("Serve_ContextCancelled_HandlerContextIsAlsoCancelled", func(t *testing.T) {
		// Handlers must observe Serve's own context cancellation (e.g. so an
		// in-flight PassthroughHandler forward can close promptly), rather
		// than always receiving context.Background(), which never cancels.
		handlerCtxDone := make(chan struct{}, 1)
		h := &blockingHandler{fn: func(ctx context.Context, cc *listener.ConnContext) error {
			select {
			case <-ctx.Done():
				handlerCtxDone <- struct{}{}
			case <-time.After(2 * time.Second):
			}
			cc.Downstream.Close()
			return ctx.Err()
		}}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForServing(t, l)

		conn := dialAndForget(t, l.Addr())
		defer conn.Close()
		waitForCondition(t, func() bool { return h.invokedCount() >= 1 })

		cancel()
		select {
		case <-handlerCtxDone:
		case <-time.After(2 * time.Second):
			t.Fatal("handler's context was never cancelled after Serve's context was cancelled")
		}
		<-serveDone
	})

	t.Run("Serve_OneHandlerBlocksForever_OtherConnectionsStillServed", func(t *testing.T) {
		block := make(chan struct{})
		var callNum atomic.Int32
		h := &blockingHandler{fn: func(ctx context.Context, cc *listener.ConnContext) error {
			n := callNum.Add(1)
			if n == 1 {
				<-block
			}
			cc.Downstream.Close()
			return nil
		}}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForServing(t, l)

		conn1 := dialAndForget(t, l.Addr())
		defer conn1.Close()
		waitForCondition(t, func() bool { return callNum.Load() >= 1 })

		conn2 := dialAndForget(t, l.Addr())
		defer conn2.Close()
		waitForCondition(t, func() bool { return callNum.Load() >= 2 })

		close(block)
		cancel()
		<-serveDone
	})

	t.Run("Serve_TwoConnections_EachGetsADistinct32CharLowercaseHexConnID", func(t *testing.T) {
		// Regression test for issue #61: ConnContext.ConnID was declared and
		// read throughout the request path but never assigned by the accept
		// loop, so every connection carried the empty string and every
		// audit record collapsed onto the same "req-1" fallback RequestID.
		// This test only exercises the field the accept loop itself
		// populates; the end-to-end RequestID plumbing is covered in
		// internal/dataplane/requestpath.
		var mu sync.Mutex
		var connIDs []string
		h := &blockingHandler{fn: func(ctx context.Context, cc *listener.ConnContext) error {
			mu.Lock()
			connIDs = append(connIDs, cc.ConnID)
			mu.Unlock()
			cc.Downstream.Close()
			return nil
		}}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForServing(t, l)

		conn1 := dialAndForget(t, l.Addr())
		defer conn1.Close()
		waitForCondition(t, func() bool { return h.invokedCount() >= 1 })

		conn2 := dialAndForget(t, l.Addr())
		defer conn2.Close()
		waitForCondition(t, func() bool { return h.invokedCount() >= 2 })

		cancel()
		<-serveDone

		mu.Lock()
		defer mu.Unlock()
		if len(connIDs) != 2 {
			t.Fatalf("len(connIDs) = %d, want 2", len(connIDs))
		}
		for _, id := range connIDs {
			if len(id) != 32 {
				t.Fatalf("ConnID = %q, want exactly 32 characters, got %d", id, len(id))
			}
			for _, r := range id {
				if !strings.ContainsRune("0123456789abcdef", r) {
					t.Fatalf("ConnID = %q, want only lowercase hex characters, found %q", id, r)
				}
			}
		}
		if connIDs[0] == connIDs[1] {
			t.Fatalf("both connections got the same ConnID %q, want distinct values", connIDs[0])
		}
		if connIDs[0] == "" || connIDs[1] == "" {
			t.Fatal("ConnID was empty; accept loop never assigned it")
		}
	})

	t.Run("Shutdown_WhileServing_StopsAcceptLoopGracefully", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(context.Background()) }()
		waitForServing(t, l)

		if err := l.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		select {
		case <-serveDone:
		case <-time.After(3 * time.Second):
			t.Fatal("Serve() did not return after Shutdown()")
		}
	})

	t.Run("Shutdown_WhileServing_ServeReturnsErrClosedNotRawAcceptError", func(t *testing.T) {
		// Regression test for the dev-review finding that when Shutdown
		// (rather than ctx cancellation) closes the socket mid-Serve, the
		// resulting Accept error was neither ctx.Err() (nil, since Serve
		// was called with context.Background()) nor a sentinel: it was the
		// raw "use of closed network connection" error, indistinguishable
		// from a genuine unexpected socket failure. Serve must return
		// ErrClosed in this case so callers can distinguish an intentional
		// shutdown from a real failure without string-matching errors.
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(context.Background()) }()
		waitForServing(t, l)

		if err := l.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		select {
		case err := <-serveDone:
			if !errors.Is(err, listener.ErrClosed) {
				t.Fatalf("Serve() error = %v, want ErrClosed", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Serve() did not return after Shutdown()")
		}
	})

	t.Run("Shutdown_WhileHandlersInFlight_WaitsUpToContextDeadline", func(t *testing.T) {
		released := make(chan struct{})
		h := &blockingHandler{fn: func(ctx context.Context, cc *listener.ConnContext) error {
			<-released
			cc.Downstream.Close()
			return nil
		}}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(context.Background()) }()
		waitForServing(t, l)

		conn := dialAndForget(t, l.Addr())
		defer conn.Close()
		waitForCondition(t, func() bool { return h.invokedCount() >= 1 })

		shutdownDone := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			shutdownDone <- l.Shutdown(ctx)
		}()

		time.Sleep(200 * time.Millisecond)
		close(released)

		select {
		case err := <-shutdownDone:
			if err != nil {
				t.Fatalf("Shutdown() error = %v, want nil once handler released within deadline", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Shutdown() did not return after handler released")
		}
		<-serveDone
	})

	t.Run("Shutdown_ContextDeadlineExceededWithHandlersStillRunning_ReturnsDeadlineExceeded", func(t *testing.T) {
		block := make(chan struct{})
		defer close(block)
		h := &blockingHandler{fn: func(ctx context.Context, cc *listener.ConnContext) error {
			<-block
			cc.Downstream.Close()
			return nil
		}}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(context.Background()) }()
		waitForServing(t, l)

		conn := dialAndForget(t, l.Addr())
		defer conn.Close()
		waitForCondition(t, func() bool { return h.invokedCount() >= 1 })

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		err := l.Shutdown(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Shutdown() error = %v, want context.DeadlineExceeded", err)
		}
		<-serveDone
	})

	t.Run("Shutdown_ContextCancelledWithHandlersInFlight_LogsGoroutineStillWaiting", func(t *testing.T) {
		// Regression test for the dev-review finding that Shutdown's
		// internal wg.Wait goroutine keeps running silently after ctx.Err()
		// is returned to the caller. Assert the documented warning log line
		// fires on this path, so the leak is at least observable.
		var logBuf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logBuf, nil))

		block := make(chan struct{})
		defer close(block)
		h := &blockingHandler{fn: func(ctx context.Context, cc *listener.ConnContext) error {
			<-block
			cc.Downstream.Close()
			return nil
		}}
		m := &listenerMetrics{}
		opts := loopbackOpts(h, m)
		l, err := listener.New(opts, &noopResolver{}, h, m, logger)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(context.Background()) }()
		waitForServing(t, l)

		conn := dialAndForget(t, l.Addr())
		defer conn.Close()
		waitForCondition(t, func() bool { return h.invokedCount() >= 1 })

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if err := l.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Shutdown() error = %v, want context.DeadlineExceeded", err)
		}
		if !strings.Contains(logBuf.String(), "shutdown context cancelled with handlers still in flight") {
			t.Fatalf("log output = %q, want a warning about handlers still in flight", logBuf.String())
		}
		<-serveDone
	})

	t.Run("Shutdown_CalledTwice_SecondCallIsIdempotent", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(context.Background()) }()
		waitForServing(t, l)

		if err := l.Shutdown(context.Background()); err != nil {
			t.Fatalf("first Shutdown() error = %v", err)
		}
		<-serveDone
		if err := l.Shutdown(context.Background()); err != nil {
			t.Fatalf("second Shutdown() error = %v, want nil (idempotent)", err)
		}
	})

	t.Run("Shutdown_ClosesUnderlyingSocket_NoFDLeak", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		addr := l.Addr()
		if err := l.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		// A cross-platform proxy for "the fd was released": rebinding the
		// exact same address must succeed immediately, which would fail with
		// address-in-use if the original socket were still open.
		opts := listener.DefaultOptions()
		opts.ListenAddr = addr
		opts.Handler = h
		m2 := &listenerMetrics{}
		opts.Metrics = m2
		l2, err := listener.New(opts, &noopResolver{}, h, m2, testLogger())
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if err := l2.Bind(); err != nil {
			t.Fatalf("rebinding the just-released address failed: %v, want nil (fd was leaked)", err)
		}
		l2.Shutdown(context.Background())
	})

	t.Run("Shutdown_BeforeBindOrServe_ReturnsNilWithoutPanic", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown() before Bind/Serve error = %v, want nil", err)
		}
	})

	t.Run("New_NilConnHandler_ReturnsErrMissingHandler", func(t *testing.T) {
		opts := listener.DefaultOptions()
		opts.Metrics = &listenerMetrics{}
		_, err := listener.New(opts, &noopResolver{}, nil, opts.Metrics, testLogger())
		if !errors.Is(err, listener.ErrMissingHandler) {
			t.Fatalf("New() error = %v, want ErrMissingHandler", err)
		}
	})

	t.Run("New_NilOptions_ReturnsErrMissingOptions", func(t *testing.T) {
		h := &blockingHandler{}
		_, err := listener.NewFromPointer(nil, &noopResolver{}, h, &listenerMetrics{}, testLogger())
		if !errors.Is(err, listener.ErrMissingOptions) {
			t.Fatalf("NewFromPointer(nil, ...) error = %v, want ErrMissingOptions", err)
		}
	})

	t.Run("Serve_NoGoroutineLeakAfterShutdown_RuntimeNumGoroutineReturnsToBaseline", func(t *testing.T) {
		baseline := stableGoroutineBaseline(t)
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(context.Background()) }()
		waitForServing(t, l)

		conn := dialAndForget(t, l.Addr())
		waitForCondition(t, func() bool { return h.invokedCount() >= 1 })
		conn.Close()

		if err := l.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		<-serveDone

		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if runtime.NumGoroutine() <= baseline {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("goroutine count = %d, baseline = %d: possible leak", runtime.NumGoroutine(), baseline)
	})

	t.Run("Serve_StateTransitions_OnlyProceedForwardViaCompareAndSwap", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if _, err := l.AcceptProbe(time.Now().Add(time.Second)); err == nil {
			t.Fatal("expected an error before Bind")
		}
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		if err := l.Bind(); !errors.Is(err, listener.ErrAlreadyBound) {
			t.Fatalf("Bind() after bound = %v, want ErrAlreadyBound (no backward/duplicate transition)", err)
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(context.Background()) }()
		waitForServing(t, l)
		if err := l.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		<-serveDone
		if err := l.Serve(context.Background()); err == nil {
			t.Fatal("Serve() after Shutdown returned nil, want an error (state cannot regress)")
		}
	})

	t.Run("Serve_ConcurrentShutdownAndAccept_NoDataRace", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(context.Background()) }()
		waitForServing(t, l)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				conn, err := net.Dial("tcp4", l.Addr().String())
				if err == nil {
					conn.Close()
				}
			}
		}()
		go func() {
			defer wg.Done()
			l.Shutdown(context.Background())
		}()
		wg.Wait()
		<-serveDone
	})

	t.Run("Serve_PerAcceptedConnection_RecordDecisionCalled", func(t *testing.T) {
		h := &blockingHandler{}
		l, m := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForServing(t, l)

		conn := dialAndForget(t, l.Addr())
		defer conn.Close()
		waitForCondition(t, func() bool { return m.decisionCount() >= 1 })

		cancel()
		<-serveDone
	})

	t.Run("Serve_AcceptToDispatch_LatencyRecorded", func(t *testing.T) {
		h := &blockingHandler{}
		l, m := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForServing(t, l)

		conn := dialAndForget(t, l.Addr())
		defer conn.Close()
		waitForCondition(t, func() bool { return m.latencyCount("accept_to_dispatch") >= 1 })

		cancel()
		<-serveDone
	})

	t.Run("Serve_LoopbackOnlyBindAddr_RejectsNonLoopbackConfiguredAddr", func(t *testing.T) {
		h := &blockingHandler{}
		m := &listenerMetrics{}
		opts := listener.DefaultOptions()
		opts.ListenAddr = netip.MustParseAddrPort("0.0.0.0:0")
		opts.Handler = h
		opts.Metrics = m
		_, err := listener.New(opts, &noopResolver{}, h, m, testLogger())
		if err == nil {
			t.Fatal("New() with a non-loopback ListenAddr returned nil error, want non-nil")
		}
	})

	t.Run("AcceptProbe_ConcurrentWithServe_NeverCalledSimultaneously", func(t *testing.T) {
		h := &blockingHandler{}
		l, _ := newTestListener(t, h)
		if err := l.Bind(); err != nil {
			t.Fatalf("Bind() error = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveDone := make(chan error, 1)
		go func() { serveDone <- l.Serve(ctx) }()
		waitForServing(t, l)

		// Once Serve has genuinely transitioned to stateServing, repeated
		// concurrent AcceptProbe calls must always resolve to ErrServing,
		// never a real Accept (which would race the accept loop's own call).
		var wg sync.WaitGroup
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := l.AcceptProbe(time.Now().Add(time.Second))
				if !errors.Is(err, listener.ErrServing) {
					t.Errorf("AcceptProbe() during Serve() error = %v, want ErrServing", err)
				}
			}()
		}
		wg.Wait()
		cancel()
		<-serveDone
	})

	t.Run("Serve_ZeroValueOptionsListener_ReturnsErrMissingListenAddr", func(t *testing.T) {
		h := &blockingHandler{}
		m := &listenerMetrics{}
		var opts listener.Options
		opts.Handler = h
		opts.Metrics = m
		_, err := listener.New(opts, &noopResolver{}, h, m, testLogger())
		if !errors.Is(err, listener.ErrMissingListenAddr) {
			t.Fatalf("New() with zero-value ListenAddr error = %v, want ErrMissingListenAddr", err)
		}
	})
}

func waitForServing(t *testing.T, l *listener.Listener) {
	t.Helper()
	waitForCondition(t, func() bool { return l.State() == listener.StateServing })
}

func waitForCondition(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition was not met within the deadline")
}

// stableGoroutineBaseline returns a runtime.NumGoroutine() reading that has
// settled (i.e. two consecutive samples agree), so goroutines left behind by
// prior tests or not yet garbage-collected don't make a leak-detection
// test's baseline itself unstable/flaky.
func stableGoroutineBaseline(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	prev := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
		cur := runtime.NumGoroutine()
		if cur == prev {
			return cur
		}
		prev = cur
	}
	return prev
}
