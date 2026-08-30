package listener

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/pipeline"
	"golang.org/x/time/rate"
)

// State is the Listener's lifecycle state, transitioned strictly forward via
// atomic.Int32.CompareAndSwap (design section 9.1): stateNew -> stateBound ->
// stateServing -> stateClosed. No transition ever goes backward or skips a
// state.
type State int32

const (
	StateNew State = iota
	// StateBinding is a transient state occupied only for the duration of
	// Bind's net.Listen call: it reserves the exclusive right to open the
	// socket (via a StateNew->StateBinding CAS) so at most one goroutine
	// ever calls net.Listen, while still keeping StateBound reserved for
	// after l.ln is actually stored -- so no other goroutine can ever
	// observe StateBound with a nil l.ln.
	StateBinding
	StateBound
	StateServing
	StateClosed
)

// Listener owns the loopback accept loop described in design section 9. Bind
// and Serve are separate calls so the two-phase startup probe gate (6.7) can
// accept exactly one connection between them via AcceptProbe.
type Listener struct {
	opts Options
	// resolver recovers the kernel-attested pre-NAT destination in the
	// dispatch goroutine (see dispatch). It may be nil for the legacy 5A
	// passthrough path, which forwards raw bytes with no resolution step;
	// the production request-path factory always injects a real
	// BPFDestinationResolver.
	resolver dataplane.DestinationResolver
	handler  ConnHandler
	metrics  audit.MetricsRecorder
	log      *slog.Logger

	ln   net.Listener
	lnMu sync.Mutex // guards ln: written once in Bind, read from Addr/AcceptProbe/Serve/closeSocket.

	state atomic.Int32 // State

	sem chan struct{} // buffered, capacity opts.MaxConnections

	// handshakeLimiter bounds the rate at which accepted downstream
	// connections are admitted to a handler (the TLS-handshake initiation
	// rate). It is checked at the top of dispatch with a non-blocking
	// Allow() so an over-rate connection is closed immediately rather than
	// queued (design section 18.2).
	handshakeLimiter *rate.Limiter

	// mu guards draining/wg together: trackHandler() must never Add to wg
	// after Shutdown has begun waiting, which is why both the draining check
	// and the Add happen under the same lock (design out the historical
	// WaitGroup Add/Wait race).
	mu       sync.Mutex
	draining bool
	wg       sync.WaitGroup

	closeOnce sync.Once

	// acceptMu serializes AcceptProbe's state-check-then-Accept sequence
	// against Serve's transition into StateServing, so a probe can never
	// observe StateBound, get past the switch, and then race Serve's own
	// accept loop for the same underlying net.Listener.Accept call.
	acceptMu sync.Mutex
}

// New constructs a Listener. opts is validated; a nil handler or invalid
// options are rejected before any socket work happens.
func New(opts Options, resolver dataplane.DestinationResolver, h ConnHandler, m audit.MetricsRecorder, log *slog.Logger) (*Listener, error) {
	return newListener(&opts, resolver, h, m, log)
}

// NewFromPointer is New's pointer-argument counterpart, used where the
// options value may genuinely be absent (the nil *Options "null" case,
// spec case #170) rather than merely zero-valued.
func NewFromPointer(opts *Options, resolver dataplane.DestinationResolver, h ConnHandler, m audit.MetricsRecorder, log *slog.Logger) (*Listener, error) {
	if opts == nil {
		return nil, ErrMissingOptions
	}
	return newListener(opts, resolver, h, m, log)
}

func newListener(opts *Options, resolver dataplane.DestinationResolver, h ConnHandler, m audit.MetricsRecorder, log *slog.Logger) (*Listener, error) {
	if h == nil {
		return nil, ErrMissingHandler
	}
	o := *opts
	o.Handler = h
	o.Metrics = m
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	l := &Listener{
		opts: o,
		// resolver recovers the kernel-attested pre-NAT destination in the
		// dispatch path (see dispatch below). It is optional: 5A's
		// PassthroughHandler forwards raw bytes with no destination
		// resolution of its own (design section 9.1/12.1), so a nil
		// resolver preserves that legacy passthrough behaviour. The
		// production request-path factory (S4/S5) always injects a real
		// BPFDestinationResolver.
		resolver:         resolver,
		handler:          h,
		metrics:          m,
		log:              log,
		sem:              make(chan struct{}, o.MaxConnections),
		handshakeLimiter: rate.NewLimiter(rate.Limit(o.HandshakeRatePerSecond), o.HandshakeRateBurst),
	}
	l.state.Store(int32(StateNew))
	return l, nil
}

// State reports the Listener's current lifecycle state.
func (l *Listener) State() State {
	return State(l.state.Load())
}

// Bind opens the listening socket. It must be called exactly once, before
// Serve or AcceptProbe can do anything useful.
func (l *Listener) Bind() error {
	// Reserve the exclusive right to open the socket via a
	// StateNew->StateBinding CAS first, so at most one goroutine ever
	// calls net.Listen (a second concurrent Bind fails this CAS
	// immediately, before doing any socket work). Only after l.ln is
	// actually stored does this transition to StateBound: a concurrent
	// Serve/AcceptProbe/Addr observing StateBound is therefore guaranteed
	// (by the CAS below acting as a release, matched by their own
	// state.Load() as an acquire) to see a non-nil l.ln. This closes the
	// dev-review-identified window where Bind previously published
	// StateBound before storing l.ln.
	if !l.state.CompareAndSwap(int32(StateNew), int32(StateBinding)) {
		// The CAS above fails identically whether the current state is
		// StateBinding, StateBound, StateServing, or StateClosed;
		// distinguish StateClosed here so a caller invoking Bind after
		// Shutdown gets ErrClosed rather than the misleading
		// ErrAlreadyBound.
		if l.State() == StateClosed {
			return ErrClosed
		}
		return ErrAlreadyBound
	}
	ln, err := net.Listen("tcp4", l.opts.ListenAddr.String())
	if err != nil {
		l.rollbackFailedBind()
		return fmt.Errorf("listener: bind %s: %w", l.opts.ListenAddr, err)
	}
	l.lnMu.Lock()
	l.ln = ln
	l.lnMu.Unlock()
	if !l.state.CompareAndSwap(int32(StateBinding), int32(StateBound)) {
		// Only a concurrent Shutdown can move state away from
		// StateBinding at this point (Bind itself holds exclusive
		// occupancy of StateBinding, so no other Bind call can race
		// here). Close the socket this call just opened rather than
		// leaking it, since nothing will ever use it after Shutdown has
		// already moved on to StateClosed.
		l.lnMu.Lock()
		l.ln = nil
		l.lnMu.Unlock()
		ln.Close()
		return ErrClosed
	}
	return nil
}

// rollbackFailedBind restores state to StateNew after net.Listen fails
// inside Bind, so a caller cannot be left with a Listener that claims to be
// binding but holds no socket and can never proceed. It uses a CAS keyed on
// StateBinding specifically (not an unconditional Store): if a concurrent
// Shutdown already moved the state to StateClosed while net.Listen was
// failing, this failure path must not resurrect StateNew over that.
func (l *Listener) rollbackFailedBind() {
	l.state.CompareAndSwap(int32(StateBinding), int32(StateNew))
}

// Addr reports the bound address, or the zero value before Bind.
func (l *Listener) Addr() netip.AddrPort {
	l.lnMu.Lock()
	ln := l.ln
	l.lnMu.Unlock()
	if ln == nil {
		return netip.AddrPort{}
	}
	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		return netip.AddrPort{}
	}
	return addr
}

// AcceptProbe accepts exactly one connection for the redirect self-probe
// (6.7.1). It returns ErrNotBound before Bind, ErrServing once Serve has
// started, and ErrClosed after Shutdown, so the probe can never race the
// accept loop's own Accept call and callers can distinguish "still serving"
// from "already shut down."
func (l *Listener) AcceptProbe(deadline time.Time) (net.Conn, error) {
	l.acceptMu.Lock()
	defer l.acceptMu.Unlock()
	switch State(l.state.Load()) {
	case StateNew, StateBinding:
		return nil, ErrNotBound
	case StateServing:
		return nil, ErrServing
	case StateClosed:
		return nil, ErrClosed
	}
	l.lnMu.Lock()
	ln := l.ln
	l.lnMu.Unlock()
	// l.ln is guaranteed non-nil here: Bind stores it before transitioning
	// state to StateBound (a release), and the state.Load() above (an
	// acquire) observing anything past StateNew establishes
	// happens-before for that store per the Go memory model, so this
	// switch could not have fallen through to here while l.ln was still
	// nil.
	if tc, ok := ln.(*net.TCPListener); ok {
		tc.SetDeadline(deadline)
		defer tc.SetDeadline(time.Time{})
		conn, err := ln.Accept()
		return l.translateAcceptProbeErr(conn, err)
	}
	// ln is not a *net.TCPListener (only possible via test doubles: Bind
	// always constructs a genuine *net.TCPListener via net.Listen("tcp4",
	// ...) in production). Such listeners have no SetDeadline method, so
	// enforce the deadline externally via a timer racing Accept, rather
	// than silently ignoring the caller's deadline and blocking forever.
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept()
		resultCh <- acceptResult{conn, err}
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case r := <-resultCh:
		return l.translateAcceptProbeErr(r.conn, r.err)
	case <-timer.C:
		// The Accept goroutine above has no way to be cancelled (this
		// non-*net.TCPListener path exists precisely because ln has no
		// SetDeadline). It keeps running after this function returns, so
		// drain resultCh here in the background rather than discarding
		// it: if that goroutine eventually accepts a connection after
		// the deadline has already passed, this closes it immediately
		// instead of leaking the net.Conn (in addition to the
		// already-accepted goroutine leak, which resultCh being
		// buffered-by-1 ensures this send never blocks on).
		go func() {
			if r := <-resultCh; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, os.ErrDeadlineExceeded
	}
}

// translateAcceptProbeErr converts the opaque net.ErrClosed that Accept
// returns when a concurrent Shutdown closes the socket mid-call into this
// package's own ErrClosed sentinel, so AcceptProbe callers can rely on
// errors.Is(err, ErrClosed) regardless of whether Shutdown raced them
// before or during the Accept call itself.
func (l *Listener) translateAcceptProbeErr(conn net.Conn, err error) (net.Conn, error) {
	if err != nil && errors.Is(err, net.ErrClosed) {
		return nil, ErrClosed
	}
	return conn, err
}

// Serve runs the accept loop until ctx is cancelled, a permanent Accept error
// occurs, or Shutdown closes the listening socket. It must be called after
// Bind.
func (l *Listener) Serve(ctx context.Context) error {
	// Move the initial state check inside acceptMu so it's atomic with the
	// CAS below: without this, a concurrent Shutdown could close the
	// listener between this check and the CAS, causing the CAS to fail and
	// this method to return the misleading ErrAlreadyServing when the real
	// cause was closure, not a second concurrent Serve call.
	l.acceptMu.Lock()
	switch State(l.state.Load()) {
	case StateNew, StateBinding:
		l.acceptMu.Unlock()
		return ErrNotBound
	case StateClosed:
		l.acceptMu.Unlock()
		return ErrClosed
	}
	// Acquire acceptMu before transitioning to StateServing so an
	// in-flight AcceptProbe (which holds acceptMu across its own
	// state-check-then-Accept sequence) cannot observe StateBound, proceed
	// past its switch, and then race this method's own accept loop for the
	// same underlying net.Listener.Accept call.
	swapped := l.state.CompareAndSwap(int32(StateBound), int32(StateServing))
	l.acceptMu.Unlock()
	if !swapped {
		// The CAS above fails identically whether a concurrent Shutdown
		// already moved state to StateClosed (racing this call between
		// its own state check and this CAS) or another concurrent Serve
		// call is already running; distinguish StateClosed so a caller
		// racing Shutdown against Serve gets ErrClosed (the true cause)
		// rather than the misleading ErrAlreadyServing.
		if l.State() == StateClosed {
			return ErrClosed
		}
		return ErrAlreadyServing
	}

	// Close the socket promptly on context cancellation, mirroring Shutdown,
	// so Serve returns ctx.Err() rather than waiting on a blocked Accept.
	stopCh := make(chan struct{})
	defer close(stopCh)
	go func() {
		select {
		case <-ctx.Done():
			l.closeSocket()
		case <-stopCh:
		}
	}()

	backoff := 5 * time.Millisecond
	const maxBackoff = time.Second

	l.lnMu.Lock()
	ln := l.ln
	l.lnMu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// A closed-listener Accept error can arise from either ctx
			// cancellation (the goroutine above calling closeSocket) or a
			// concurrent Shutdown() call closing the socket directly.
			// Check net.ErrClosed first and re-check ctx.Err() inside
			// that branch (rather than checking ctx.Err() as a separate
			// preceding branch), so a genuine race between this Accept
			// call unblocking and ctx.Err() becoming observably non-nil
			// on this goroutine can never cause the wrong cause to be
			// reported: whichever is true by the time we get here wins,
			// and ctx cancellation is preferred when both are true since
			// it is the more specific cause.
			if errors.Is(err, net.ErrClosed) {
				l.state.CompareAndSwap(int32(StateServing), int32(StateClosed))
				if ctxErr := ctx.Err(); ctxErr != nil {
					return ctxErr
				}
				return ErrClosed
			}
			if ctx.Err() != nil {
				l.state.CompareAndSwap(int32(StateServing), int32(StateClosed))
				return ctx.Err()
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				l.log.Warn("listener: temporary accept error", "error", err)
				time.Sleep(backoff)
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			l.state.CompareAndSwap(int32(StateServing), int32(StateClosed))
			return err
		}
		backoff = 5 * time.Millisecond
		l.dispatch(ctx, conn, time.Now())
	}
}

func (l *Listener) dispatch(ctx context.Context, conn net.Conn, acceptedAt time.Time) {
	// Transport labelling invariant: this listener is the TLS-terminating
	// front door (the production handler chain is
	// tlsTerminatingConnHandler -> requestpath), so every connection reaching
	// dispatch is TLS on ingress. The accept-time rejections below operate on
	// a raw net.Conn before any ConnContext/Protocol exists, and the
	// post-Handle outcome decisions run after the TLS handler has set
	// cc.Protocol = ProtocolTLS on success; audit.TransportTLS is therefore
	// the correct, non-derivable label at all of these sites. transportKindOf
	// is applied only where a genuinely non-TLS framing is classified
	// (discriminator/passthrough), never here.
	//
	// Handshake rate limit (design section 18.2): Allow() is non-blocking,
	// so an over-rate connection is rejected and closed immediately rather
	// than queued (Wait() would hold the accept goroutine and a socket
	// open under a churn flood).
	if l.handshakeLimiter != nil && !l.handshakeLimiter.Allow() {
		conn.Close()
		if l.metrics != nil {
			l.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonResourceLimit, audit.TransportTLS, false)
			// Carry the specific bound (handshake rate) that legacy metrics
			// exposed via the "resource_limit:handshake_rate" token, so it
			// stays distinguishable from semaphore saturation.
			l.metrics.TransportReject(audit.RejectClassResourceLimit, audit.BoundHandshakeRate)
		}
		return
	}

	select {
	case l.sem <- struct{}{}:
	default:
		conn.Close()
		if l.metrics != nil {
			l.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonResourceLimit, audit.TransportTLS, false)
			l.metrics.TransportReject(audit.RejectClassResourceLimit, audit.BoundMaxInflightRequests)
		}
		return
	}

	if !l.trackHandler() {
		<-l.sem
		conn.Close()
		if l.metrics != nil {
			l.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonDraining, audit.TransportTLS, false)
		}
		return
	}

	go func() {
		defer l.wg.Done()
		defer func() { <-l.sem }()
		// Consolidated into a single defer (rather than separate recover
		// and conn.Close defers) so panic recovery, connection close, and
		// metrics recording always happen in a well-defined order: if
		// Handle or conn.Close panics, recover() still runs, the metrics
		// decision for the panic is still recorded, and conn.Close is
		// still attempted exactly once. The previous separate-defers
		// version registered recover() before conn.Close(), so in LIFO
		// order conn.Close() ran *first* and any panic from it skipped
		// recover entirely; it also recorded no metrics decision at all
		// when Handle panicked.
		defer func() {
			if r := recover(); r != nil {
				l.log.Error("listener: handler panicked", "panic", r)
				if l.metrics != nil {
					l.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonHandlerPanic, audit.TransportTLS, true)
				}
			}
			// conn.Close() itself may panic (e.g. a misbehaving net.Conn
			// implementation); recover it separately so it can never
			// escape this already-deferred function unrecovered.
			defer func() {
				if r := recover(); r != nil {
					l.log.Error("listener: conn.Close panicked", "panic", r)
				}
			}()
			conn.Close()
		}()

		cc := &ConnContext{ConnID: l.newConnID(), Downstream: conn, AcceptedAt: acceptedAt}
		if l.metrics != nil {
			l.metrics.StageDuration(audit.StageAcceptDispatch, time.Since(acceptedAt))
		}

		// Recover the kernel-attested pre-NAT destination before handing
		// the connection to the handler. This is fail-closed: a resolve
		// miss (the T1 umbrella, ErrNoOriginalDestination) rejects the
		// connection rather than dispatching it with a zero OriginalDst.
		// The resolver is optional here so the legacy 5A passthrough path
		// (which threads a nil resolver through New) keeps its behaviour;
		// the production request-path factory (S4/S5) always injects a
		// real BPFDestinationResolver.
		if l.resolver != nil {
			resolveStart := time.Now()
			dst, err := l.resolver.Resolve(conn)
			// Bracket the resolve attempt regardless of outcome so stage
			// timing is observed on both success and failure.
			if l.metrics != nil {
				l.metrics.StageDuration(audit.StageResolve, time.Since(resolveStart))
			}
			if err != nil {
				l.log.Warn("listener: no_original_dst; rejecting connection", "error", err)
				if l.metrics != nil {
					// fault=false: a missing original destination is a
					// clean fail-closed denial, not a runtime fault. The
					// resolver already recorded any T2 loop-guard detail,
					// so the listener maps every resolve error to exactly
					// one T1 without re-classifying or double-counting.
					l.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonNoOriginalDst, audit.TransportTLS, false)
					l.metrics.TransportReject(audit.RejectClassNoOriginalDst, audit.BoundNone)
				}
				return
			}
			cc.OriginalDst = dst
		}

		err := l.handler.Handle(ctx, cc)
		if l.metrics != nil && cc.MarkDecided() {
			// Fallback only. Any layer that reached a terminal disposition
			// (tlsterm handshake refusal, requestpath policy verdict or
			// rejection, relay/dialer transport fault) has already recorded
			// it and claimed the latch, so this runs only for connections
			// nothing else classified.
			//
			// Before the latch this branch ran unconditionally, which is
			// what produced issues #89 and #83: a policy-DENIED request
			// writes its deny to the wire and returns nil from Handle, so
			// the else-branch below recorded that denied connection as an
			// ALLOW; and a refused connection recorded its specific reason
			// here as a second, coarser sample on top.
			if err != nil {
				// A handler-returned error is the connection's terminal
				// outcome; the specific per-stage reason (if any) was already
				// recorded by the handler itself, so this rollup uses the
				// bounded ReasonInternal rather than a raw error string.
				// fault=true: an internal handler error is a runtime fault,
				// not a clean policy denial (same fault=true convention as the
				// handler-panic path, though the reason codes differ:
				// ReasonInternal here vs ReasonHandlerPanic there).
				l.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonInternal, audit.TransportTLS, true)
			} else {
				l.metrics.Decisions(pipeline.DispositionAllow, pipeline.ReasonNone, audit.TransportTLS, false)
			}
		}
	}()
}

// newConnID generates the 128-bit random hex ConnID documented on
// ConnContext.ConnID (correlates log lines across a single connection's
// audit records; not a RequestID).
//
// Error-handling policy: crypto/rand.Read on a 16-byte buffer essentially
// never fails on any platform this runs on (it only fails if the OS CSPRNG
// itself is unavailable), but "essentially never" is not "never", so this
// must not be allowed to panic or silently hang the accept loop. It also
// must not be treated as fail-closed (rejecting or dropping the
// connection): ConnID only supports log/audit correlation, not any
// admission or security decision, so degrading it is safe while denying an
// otherwise-legitimate connection over it would not be. Accordingly, on
// error this logs once and returns "" for that connection; requestID()
// already has a "req-<ordinal>" fallback for exactly this case (an empty
// ConnID), so correlation for that one connection degrades to ordinal-only
// instead of being lost, and every other connection is unaffected.
func (l *Listener) newConnID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		l.log.Error("listener: crypto/rand failed generating ConnID; falling back to empty ConnID for this connection", "error", err)
		return ""
	}
	return hex.EncodeToString(b[:])
}

// trackHandler registers one in-flight handler goroutine with wg, refusing to
// do so once Shutdown has begun draining. Both the draining check and the
// wg.Add happen under the same mutex Shutdown holds while calling wg.Wait,
// which is what makes the Add/Wait race structurally impossible rather than
// merely unlikely.
func (l *Listener) trackHandler() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.draining {
		return false
	}
	l.wg.Add(1)
	return true
}

// Shutdown stops the accept loop, closes the listening socket, and waits for
// in-flight handlers to finish, up to ctx's deadline. It is idempotent and
// safe to call before Bind or Serve.
//
// If ctx is cancelled while handlers are still in flight, Shutdown returns
// ctx.Err() immediately, but the internal goroutine waiting on l.wg.Wait
// keeps running until every handler actually returns -- it is not itself
// cancellable, since abandoning wg.Wait early would risk a future Bind/Serve
// on a reused Listener racing against handlers this Shutdown call never
// waited for. Callers that pass a ctx with a deadline are relying on
// ConnHandler implementations honoring ctx cancellation (see ConnHandler's
// contract) so that ctx.Done() firing here also unblocks the handlers
// themselves in a bounded amount of time, not just this call's own wait.
//
// Each Shutdown call that times out this way spawns its own wg.Wait
// goroutine, which is not itself cancelled by a later Shutdown call:
// repeatedly calling Shutdown with a short-timeout ctx while handlers are
// still in flight will accumulate one such goroutine per call (bounded by
// however many times the caller retries), not just one total. Since
// draining is set unconditionally at the top of every Shutdown call and
// wg.Wait only returns once all in-flight handlers finish, every one of
// these goroutines eventually exits on its own once the handlers that were
// in flight when it started have all returned; they do not persist
// forever, but they are not synchronized with each other either.
func (l *Listener) Shutdown(ctx context.Context) error {
	l.mu.Lock()
	l.draining = true
	l.mu.Unlock()

	l.closeSocket()
	l.state.CompareAndSwap(int32(StateServing), int32(StateClosed))
	l.state.CompareAndSwap(int32(StateBound), int32(StateClosed))
	l.state.CompareAndSwap(int32(StateBinding), int32(StateClosed))
	l.state.CompareAndSwap(int32(StateNew), int32(StateClosed))

	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		l.log.Warn("listener: shutdown context cancelled with handlers still in flight; internal wg.Wait goroutine continues running until they return")
		return ctx.Err()
	}
}

func (l *Listener) closeSocket() {
	l.closeOnce.Do(func() {
		l.lnMu.Lock()
		ln := l.ln
		l.lnMu.Unlock()
		if ln != nil {
			ln.Close()
		}
	})
}
