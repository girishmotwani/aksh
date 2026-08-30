package listener

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/pipeline"
	"golang.org/x/time/rate"
)

// TestErrServing_ErrAlreadyServing_HaveDistinguishableMessages is a
// regression test for the dev-review finding that ErrServing's and
// ErrAlreadyServing's messages were nearly identical ("serving" vs "already
// serving"), making it hard for callers/logs to tell which failure mode
// occurred. Each message must name the specific method that returns it
// (AcceptProbe vs Serve) so the two are never confused.
func TestErrServing_ErrAlreadyServing_HaveDistinguishableMessages(t *testing.T) {
	if ErrServing.Error() == ErrAlreadyServing.Error() {
		t.Fatalf("ErrServing and ErrAlreadyServing have identical messages: %q", ErrServing.Error())
	}
	if !strings.Contains(ErrServing.Error(), "AcceptProbe") {
		t.Errorf("ErrServing.Error() = %q, want it to name AcceptProbe", ErrServing.Error())
	}
	if !strings.Contains(ErrAlreadyServing.Error(), "Serve") {
		t.Errorf("ErrAlreadyServing.Error() = %q, want it to name Serve", ErrAlreadyServing.Error())
	}
}

// panicOnCloseConn is a net.Conn test double whose Close panics, used to
// verify dispatch's defer ordering: the recover() defer must run *after*
// conn.Close(), so it is registered *after* conn.Close() in source order
// (LIFO executes the most-recently-registered defer first).
type panicOnCloseConn struct{ net.Conn }

func (panicOnCloseConn) Close() error { panic("simulated conn.Close panic") }
func (panicOnCloseConn) Read(b []byte) (int, error) {
	return 0, io.EOF
}

// recordingHandler is a minimal ConnHandler double for internal white-box
// tests that don't need blockingHandler's full feature set.
type recordingHandler struct{}

func (recordingHandler) Handle(ctx context.Context, cc *ConnContext) error { return nil }

// panicOnHandleHandler is a ConnHandler test double whose Handle always
// panics, used to verify dispatch records a metrics decision even when the
// handler itself panics rather than returning an error.
type panicOnHandleHandler struct{}

func (panicOnHandleHandler) Handle(ctx context.Context, cc *ConnContext) error {
	panic("simulated handler panic")
}

// recordingMetrics is a minimal audit.MetricsRecorder test double that
// records every Decisions call.
type recordingMetrics struct {
	audit.NopMetricsRecorder
	mu                 sync.Mutex
	decisions          []string
	decisionFaults     []bool
	decisionTransports []audit.TransportKind
	latencies          []time.Duration
	stageNames         []audit.StageName
	transportRejects   []string
}

func (m *recordingMetrics) Decisions(d pipeline.Disposition, r pipeline.DenyReason, transport audit.TransportKind, fault bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions = append(m.decisions, d.String()+"/"+r.String())
	m.decisionFaults = append(m.decisionFaults, fault)
	m.decisionTransports = append(m.decisionTransports, transport)
}
func (m *recordingMetrics) StageDuration(stage audit.StageName, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latencies = append(m.latencies, duration)
	m.stageNames = append(m.stageNames, stage)
}
func (m *recordingMetrics) TransportReject(class audit.RejectClass, bound audit.BoundName) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transportRejects = append(m.transportRejects, class.String()+":"+bound.String())
}

// faultFor returns the fault flag recorded for the first decision matching
// key ("disposition/reason"), or (false, false) if no such decision exists.
func (m *recordingMetrics) faultFor(key string) (fault bool, found bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, d := range m.decisions {
		if d == key {
			return m.decisionFaults[i], true
		}
	}
	return false, false
}

// transportFor returns the transport recorded for the first decision matching
// key ("disposition/reason"), or (0, false) if no such decision exists.
func (m *recordingMetrics) transportFor(key string) (audit.TransportKind, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, d := range m.decisions {
		if d == key {
			return m.decisionTransports[i], true
		}
	}
	return 0, false
}

// hasReject reports whether a TransportReject("class:bound") was recorded.
func (m *recordingMetrics) hasReject(s string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.transportRejects {
		if r == s {
			return true
		}
	}
	return false
}

// errorOnHandleHandler is a ConnHandler double whose Handle returns a
// non-nil error, exercising dispatch's handler-returned-error path.
type errorOnHandleHandler struct{}

func (errorOnHandleHandler) Handle(ctx context.Context, cc *ConnContext) error {
	return errors.New("simulated handler error")
}

// closableConn is a minimal net.Conn test double whose Close is a no-op.
type closableConn struct{ net.Conn }

func (closableConn) Close() error { return nil }
func (closableConn) Read(b []byte) (int, error) {
	return 0, io.EOF
}

// TestDispatch_AcceptedAtPassedIn_LatencyExcludesSemaphoreWait is a
// white-box regression test for the dev-review finding that dispatch
// captured acceptedAt := time.Now() internally, at the start of dispatch
// itself rather than when Accept() actually returned in the accept loop:
// under semaphore contention, that blended semaphore queueing time into
// the "accept_to_dispatch" latency metric, misleadingly overcounting
// dispatch latency and undercounting the true accept-to-dispatch gap.
// dispatch now takes acceptedAt as a parameter, so this asserts the exact
// caller-supplied timestamp (not one derived from a later time.Now() call
// inside dispatch, which would be larger) is what RecordLatency measures
// against.
func TestDispatch_AcceptedAtPassedIn_LatencyExcludesSemaphoreWait(t *testing.T) {
	metrics := &recordingMetrics{}
	l := &Listener{
		handler: recordingHandler{},
		metrics: metrics,
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		sem:     make(chan struct{}, 1),
	}
	conn := closableConn{}

	// Simulate semaphore queueing time by supplying an acceptedAt far in
	// the past: if dispatch still called time.Now() internally to compute
	// acceptedAt, the recorded latency would be near zero instead of
	// reflecting this artificially large gap.
	acceptedAt := time.Now().Add(-500 * time.Millisecond)
	l.dispatch(context.Background(), conn, acceptedAt)
	l.wg.Wait()

	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	if len(metrics.latencies) == 0 {
		t.Fatalf("RecordLatency was never called")
	}
	if got := metrics.latencies[0]; got < 400*time.Millisecond {
		t.Fatalf("accept_to_dispatch latency = %v, want >= 400ms (dispatch must use the caller-supplied acceptedAt, not its own time.Now())", got)
	}
}

// TestDispatch_HandlerPanics_RecordsDecisionInsteadOfSilentlyDropping is a
// white-box regression test for the dev-review finding that dispatch's
// panic-recovery defer only logged the panic and never recorded any
// metrics decision for the connection, unlike the handler-returned-error
// path (which always calls RecordDecision). A panicking handler left the
// connection's outcome completely unobserved in metrics.
func TestDispatch_HandlerPanics_RecordsDecisionInsteadOfSilentlyDropping(t *testing.T) {
	metrics := &recordingMetrics{}
	l := &Listener{
		handler: panicOnHandleHandler{},
		metrics: metrics,
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		sem:     make(chan struct{}, 1),
	}
	conn := closableConn{}

	l.dispatch(context.Background(), conn, time.Now())
	l.wg.Wait()

	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	found := false
	for _, d := range metrics.decisions {
		if d == "deny/handler_panic" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RecordDecision calls = %v, want one entry \"deny/handler_panic\"", metrics.decisions)
	}
}

// TestDispatch_RejectedByDraining_RecordsDecisionInsteadOfSilentlyDropping
// is a white-box regression test for the dev-review finding that
// trackHandler()'s "false" (draining) path in dispatch released the
// semaphore slot and closed the connection but never called
// RecordDecision, unlike the parallel "resource limit" rejection just
// above it (semaphore full) which does. A connection rejected because
// Shutdown had already begun draining was left completely unobserved in
// metrics.
func TestDispatch_RejectedByDraining_RecordsDecisionInsteadOfSilentlyDropping(t *testing.T) {
	metrics := &recordingMetrics{}
	l := &Listener{
		handler: recordingHandler{},
		metrics: metrics,
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		sem:     make(chan struct{}, 1),
	}
	l.draining = true
	conn := closableConn{}

	l.dispatch(context.Background(), conn, time.Now())

	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	found := false
	for _, d := range metrics.decisions {
		if d == "deny/draining" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RecordDecision calls = %v, want one entry \"deny/draining\"", metrics.decisions)
	}
}

// TestDispatch_HandlerReturnsError_RecordsInternalFault asserts that a
// handler-returned error is recorded as a fault. The fault dimension exists
// to separate runtime/infrastructure failures from clean policy denials;
// an internal handler error is a fault, not a policy decision, so the
// rolled-up deny/internal decision must carry fault=true (mirroring the
// handler-panic path).
func TestDispatch_HandlerReturnsError_RecordsInternalFault(t *testing.T) {
	metrics := &recordingMetrics{}
	l := &Listener{
		handler: errorOnHandleHandler{},
		metrics: metrics,
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		sem:     make(chan struct{}, 1),
	}
	conn := closableConn{}

	l.dispatch(context.Background(), conn, time.Now())
	l.wg.Wait()

	fault, found := metrics.faultFor("deny/internal")
	if !found {
		t.Fatalf("RecordDecision calls = %v, want one entry \"deny/internal\"", metrics.decisions)
	}
	if !fault {
		t.Fatalf("deny/internal fault = false, want true (handler error is a fault)")
	}
	// The listener is the TLS-terminating front door, so its outcome
	// rollups carry TransportTLS (documented invariant in dispatch).
	if tk, _ := metrics.transportFor("deny/internal"); tk != audit.TransportTLS {
		t.Fatalf("deny/internal transport = %v, want %v", tk, audit.TransportTLS)
	}
}

// TestDispatch_HandshakeRateLimited_RecordsBoundReject asserts that a
// handshake-rate rejection emits a bounded TransportReject carrying the
// handshake-rate bound, restoring the specificity the legacy
// "resource_limit:handshake_rate" token provided before the typed migration.
func TestDispatch_HandshakeRateLimited_RecordsBoundReject(t *testing.T) {
	metrics := &recordingMetrics{}
	l := &Listener{
		handler:          recordingHandler{},
		metrics:          metrics,
		log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		sem:              make(chan struct{}, 1),
		handshakeLimiter: rate.NewLimiter(0, 0), // zero rate+burst: Allow() always false
	}
	conn := closableConn{}

	l.dispatch(context.Background(), conn, time.Now())

	want := audit.RejectClassResourceLimit.String() + ":" + audit.BoundHandshakeRate.String()
	if !metrics.hasReject(want) {
		t.Fatalf("TransportReject calls = %v, want one entry %q", metrics.transportRejects, want)
	}
}

// TestDispatch_SemaphoreSaturated_RecordsBoundReject asserts that a
// max-inflight (semaphore-saturation) rejection emits a bounded
// TransportReject carrying the max-inflight bound.
func TestDispatch_SemaphoreSaturated_RecordsBoundReject(t *testing.T) {
	metrics := &recordingMetrics{}
	sem := make(chan struct{}, 1)
	sem <- struct{}{} // saturate: the only slot is taken
	l := &Listener{
		handler: recordingHandler{},
		metrics: metrics,
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		sem:     sem,
	}
	conn := closableConn{}

	l.dispatch(context.Background(), conn, time.Now())

	want := audit.RejectClassResourceLimit.String() + ":" + audit.BoundMaxInflightRequests.String()
	if !metrics.hasReject(want) {
		t.Fatalf("TransportReject calls = %v, want one entry %q", metrics.transportRejects, want)
	}
}

// white-box regression test (package listener, not listener_test) for the
// dev-review finding that dispatch's defer order let a panic from
// conn.Close() itself propagate unrecovered: the recover() defer was
// registered before defer conn.Close(), so in LIFO order conn.Close() ran
// *first* and any panic from it skipped recover entirely.
func TestDispatch_ConnCloseItselfPanics_RecoveredWithoutCrashingProcess(t *testing.T) {
	l := &Listener{
		handler: recordingHandler{},
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics: &recordingMetrics{},
		sem:     make(chan struct{}, 1),
	}
	conn := panicOnCloseConn{}

	l.dispatch(context.Background(), conn, time.Now())
	// dispatch spawns its own goroutine that eventually calls conn.Close(),
	// which panics. If dispatch's defer order is wrong (recover registered
	// before conn.Close, so conn.Close runs first per LIFO), that panic
	// escapes unrecovered in the goroutine and crashes the whole test
	// binary -- there is no way to catch a panic in another goroutine from
	// here. Reaching the end of this test (and the process still running)
	// is therefore the pass condition.
	//
	// Regression test for the dev-review finding that this synchronization
	// previously used a fixed time.Sleep(100ms), which is flaky under
	// scheduler delay or heavy CI load (the goroutine might not have run
	// yet when the sleep elapses). l.wg.Wait() deterministically blocks
	// until dispatch's spawned goroutine has called wg.Done() (its first
	// deferred call), which only happens after conn.Close() and the
	// recover() defer have both run.
	l.wg.Wait()
}

// TestBind_SocketStoredBeforeStateTransition_ConcurrentAcceptProbeNeverSeesNilListener
// is a white-box regression test for the dev-review finding that Bind
// transitioned state to StateBound via CompareAndSwap before storing the
// opened socket in l.ln, leaving a window where a concurrent
// Serve/AcceptProbe could observe StateBound, pass its state check, and
// then dereference a nil l.ln. Bind now stores l.ln under lnMu *before*
// the CAS to StateBound, so any goroutine that observes StateBound is
// guaranteed (via the Go memory model's happens-before rule for a
// successful CompareAndSwap) to see a non-nil l.ln.
func TestBind_SocketStoredBeforeStateTransition_ConcurrentAcceptProbeNeverSeesNilListener(t *testing.T) {
	opts := DefaultOptions()
	opts.ListenAddr = netip.MustParseAddrPort("127.0.0.1:0")
	l, err := newListener(&opts, nil, recordingHandler{}, &recordingMetrics{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newListener() error = %v", err)
	}

	var wg sync.WaitGroup
	nilObserved := atomic.Bool{}
	stateObserved := atomic.Bool{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if s := State(l.state.Load()); s == StateBound || s == StateServing || s == StateClosed {
				stateObserved.Store(true)
				l.lnMu.Lock()
				ln := l.ln
				l.lnMu.Unlock()
				if ln == nil {
					nilObserved.Store(true)
				}
				return
			}
		}
	}()

	if err := l.Bind(); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	defer l.Shutdown(context.Background())
	wg.Wait()

	if !stateObserved.Load() {
		t.Fatalf("observer goroutine never observed a post-StateNew state within 2s: this test would otherwise pass vacuously without exercising the regression it targets")
	}
	if nilObserved.Load() {
		t.Fatalf("observed StateBound (or later) with a nil l.ln: Bind's socket-store-then-CAS ordering was violated")
	}
}

// fakeNonTCPListener is a minimal net.Listener double that is deliberately
// not a *net.TCPListener, used to exercise AcceptProbe's deadline-handling
// path for listeners with no SetDeadline method.
type fakeNonTCPListener struct {
	acceptCh chan net.Conn
	closed   chan struct{}
}

func newFakeNonTCPListener() *fakeNonTCPListener {
	return &fakeNonTCPListener{acceptCh: make(chan net.Conn), closed: make(chan struct{})}
}

func (f *fakeNonTCPListener) Accept() (net.Conn, error) {
	select {
	case c := <-f.acceptCh:
		return c, nil
	case <-f.closed:
		return nil, net.ErrClosed
	}
}
func (f *fakeNonTCPListener) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}
func (f *fakeNonTCPListener) Addr() net.Addr { return &net.TCPAddr{} }

// trackedClosableConn is closableConn with an observable Close call, used
// to verify a net.Conn accepted after AcceptProbe's deadline already fired
// is not leaked.
type trackedClosableConn struct {
	closableConn
	closed *atomic.Bool
}

func (c trackedClosableConn) Close() error {
	c.closed.Store(true)
	return nil
}

// TestAcceptProbe_NonTCPListener_DeadlineFiresBeforeLateAccept_ClosesConnInstead
// is a regression test for the dev-review finding that when the deadline
// fires before the background Accept goroutine returns, and that goroutine
// later succeeds, the accepted net.Conn was silently discarded (leaked)
// rather than closed. AcceptProbe must close any connection that arrives
// after the deadline already timed it out.
func TestAcceptProbe_NonTCPListener_DeadlineFiresBeforeLateAccept_ClosesConnInstead(t *testing.T) {
	l := &Listener{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	fake := newFakeNonTCPListener()
	l.ln = fake
	l.state.Store(int32(StateBound))

	_, err := l.AcceptProbe(time.Now().Add(20 * time.Millisecond))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("AcceptProbe() error = %v, want os.ErrDeadlineExceeded", err)
	}

	closed := &atomic.Bool{}
	conn := trackedClosableConn{closed: closed}
	fake.acceptCh <- conn // deliver the "late" accept after the deadline fired

	deadline := time.Now().Add(2 * time.Second)
	for !closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !closed.Load() {
		t.Fatalf("connection accepted after AcceptProbe's deadline fired was never closed (leaked)")
	}
}

// TestAcceptProbe_NonTCPListener_DeadlineIsEnforced is a regression test for
// the dev-review finding that AcceptProbe only applied the caller's
// deadline via SetDeadline on *net.TCPListener specifically, silently
// ignoring the deadline (and blocking forever) for any other net.Listener
// implementation whose Accept never returns on its own.
func TestAcceptProbe_NonTCPListener_DeadlineIsEnforced(t *testing.T) {
	l := &Listener{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	l.ln = newFakeNonTCPListener()
	l.state.Store(int32(StateBound))

	start := time.Now()
	_, err := l.AcceptProbe(time.Now().Add(50 * time.Millisecond))
	elapsed := time.Since(start)

	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("AcceptProbe() error = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("AcceptProbe() took %v to return after its deadline, want close to 50ms (deadline was not enforced)", elapsed)
	}
}

// TestAcceptProbe_SocketClosedMidAccept_ReturnsErrClosedNotOpaqueNetErrClosed
// is a regression test for the dev-review finding that a concurrent
// Shutdown closing the socket while AcceptProbe's Accept call was already
// in flight surfaced the raw net.ErrClosed (or a wrapped *net.OpError)
// instead of this package's own ErrClosed sentinel, breaking
// errors.Is(err, listener.ErrClosed) for callers racing Shutdown against
// an in-flight probe.
func TestAcceptProbe_SocketClosedMidAccept_ReturnsErrClosedNotOpaqueNetErrClosed(t *testing.T) {
	l := &Listener{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	fake := newFakeNonTCPListener()
	l.ln = fake
	l.state.Store(int32(StateBound))

	errCh := make(chan error, 1)
	go func() {
		_, err := l.AcceptProbe(time.Now().Add(5 * time.Second))
		errCh <- err
	}()

	// Give AcceptProbe a moment to enter its Accept call before closing.
	time.Sleep(20 * time.Millisecond)
	fake.Close()

	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("AcceptProbe() error = %v, want ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("AcceptProbe() did not return within 2s after the listener was closed mid-Accept")
	}
}

// TestServe_StateClosedDuringRace_ReturnsErrClosedNotErrAlreadyServing is a
// white-box regression test for the dev-review finding that Serve's initial
// StateNew check happens outside acceptMu: if a concurrent Shutdown closes
// the listener between that check and the CAS(StateBound->StateServing)
// inside acceptMu, the CAS fails and Serve returns the misleading
// ErrAlreadyServing even though the real cause was closure, not another
// Serve call. This directly simulates the race outcome (state already
// StateClosed by the time Serve's CAS runs) rather than relying on tight
// goroutine timing.
func TestServe_StateClosedDuringRace_ReturnsErrClosedNotErrAlreadyServing(t *testing.T) {
	l := &Listener{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	// Simulate: Bind succeeded (StateBound), then a concurrent Shutdown won
	// the race and moved state to StateClosed before Serve's own CAS ran.
	l.state.Store(int32(StateClosed))

	err := l.Serve(context.Background())
	if err != ErrClosed {
		t.Fatalf("Serve() error = %v, want ErrClosed", err)
	}
}

// TestServe_ShutdownRacesBetweenStateCheckAndCAS_NeverReturnsErrAlreadyServing
// is a regression test for the dev-review finding that Serve's
// CompareAndSwap(StateBound, StateServing) can fail because a concurrent
// Shutdown moved state to StateClosed between Serve's initial switch check
// and this CAS (Shutdown does not take acceptMu, so this window is real,
// not merely hypothetical). Serve previously returned the misleading
// ErrAlreadyServing whenever this CAS failed, regardless of cause. This
// stress-tests the actual race (not a synthetic pre-set state) across many
// iterations so the timing-dependent window is exercised at least once.
func TestServe_ShutdownRacesBetweenStateCheckAndCAS_NeverReturnsErrAlreadyServing(t *testing.T) {
	for i := 0; i < 500; i++ {
		l := &Listener{
			log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			ln:  newFakeNonTCPListener(),
		}
		l.state.Store(int32(StateBound))

		errCh := make(chan error, 1)
		go func() { errCh <- l.Serve(context.Background()) }()
		l.Shutdown(context.Background())

		err := <-errCh
		if err == ErrAlreadyServing {
			t.Fatalf("iteration %d: Serve() error = ErrAlreadyServing, want ErrClosed or nil (Shutdown, not a second Serve, caused the CAS to fail)", i)
		}
	}
}
