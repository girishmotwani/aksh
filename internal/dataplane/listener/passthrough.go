package listener

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

// PassthroughHandler is the 5A-only ConnHandler: it dials the kernel-attested
// upstream and relays bytes bidirectionally, with no request-level parsing.
// 5B replaces it with the request path without changing the listener
// (design section 9.1, 12.1).
type PassthroughHandler struct {
	Dialer  dataplane.UpstreamDialer
	Metrics audit.MetricsRecorder
	Log     *slog.Logger
}

var _ ConnHandler = (*PassthroughHandler)(nil)

// Handle relays bytes between cc.Downstream and the dialed upstream
// connection until either side reaches EOF, the context is cancelled, or a
// copy error occurs. Both connections are closed exactly once regardless of
// how Handle returns.
func (h *PassthroughHandler) Handle(ctx context.Context, cc *ConnContext) error {
	if cc == nil {
		return errNilConnContext
	}
	if cc.Downstream == nil {
		return errNilDownstream
	}
	down := cc.Downstream

	if h.Dialer == nil {
		down.Close()
		h.logError("passthrough: Dialer is nil, cannot forward connection", nil)
		return errNilDialer
	}

	if _, ok := cc.Protocol.Transport(); !ok {
		// Not a forwardable framing (ProtocolUnknown / ProtocolH2CPreface):
		// close without ever attempting to dial upstream.
		down.Close()
		if h.Metrics != nil {
			// These framings never presented a TLS handshake, so the
			// transport label is plaintext, never tls.
			h.Metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonUnsupportedProtocol, audit.TransportPlaintext, false)
		}
		return ErrUnsupportedProtocol
	}

	up, err := h.Dialer.DialUpstream(ctx, cc.OriginalDst, cc.CandidateSNI, "")
	if err != nil {
		down.Close()
		if h.Metrics != nil {
			h.Metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonDialFailed, transportKindOf(cc.Protocol), true)
		}
		h.logError("passthrough: upstream dial failed", err)
		return err
	}

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			down.Close()
			up.Close()
		})
	}
	defer closeBoth()

	// Close both connections promptly if the caller's context is cancelled
	// mid-forward, rather than waiting for natural EOF on a copy that may
	// never see one (design section 9.3, per-stage deadlines).
	//
	// ctxDone is a plain channel rather than context.WithCancel because
	// Handle does not want to derive a child context here (that would
	// change ctx's identity for the rest of Handle, e.g. any future
	// context-value lookups); it only needs a one-shot signal telling this
	// goroutine "Handle is returning, stop watching ctx.Done()". Closing
	// it is safe even if the goroutine already exited via ctx.Done() and
	// called closeBoth(): closeBoth's sync.Once makes that call a no-op,
	// and closing an already-unread channel with no remaining receivers is
	// itself safe (it does not block or panic).
	ctxDone := make(chan struct{})
	defer close(ctxDone)
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-ctxDone:
		}
	}()

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(up, down)
		// Half-close up's write side (if supported) instead of closing it
		// outright: down has reached EOF, so no more data will ever flow
		// down->up, but up->down (the reverse direction, still copying
		// below) may still have data in flight that a full close would
		// truncate.
		if cwErr := closeWrite(up); cwErr != nil && !isClosedConnErr(cwErr) {
			h.logError("passthrough: CloseWrite failed on upstream connection", cwErr)
		}
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(down, up)
		if cwErr := closeWrite(down); cwErr != nil && !isClosedConnErr(cwErr) {
			h.logError("passthrough: CloseWrite failed on downstream connection", cwErr)
		}
		errCh <- err
	}()

	// Collect both directions' results. Either may complete first; do not
	// discard the second one just because it arrived after the deferred
	// closeBoth ran — a genuine, non-closed-conn error from either
	// direction must be reported, not silently swallowed. The explicit
	// closeBoth() call previously here was redundant: the deferred
	// closeBoth() (guarded by sync.Once, so calling it twice is a no-op)
	// already guarantees both connections are closed by the time Handle
	// returns.
	first := <-errCh
	second := <-errCh

	firstIsReal := first != nil && !isClosedConnErr(first)
	secondIsReal := second != nil && !isClosedConnErr(second)
	switch {
	case firstIsReal && secondIsReal:
		// Both directions failed for genuine reasons: join both errors
		// (rather than returning only whichever arrived first on errCh)
		// so a caller inspecting the error via errors.Is/errors.As can
		// still observe either underlying cause, instead of one being
		// silently discarded.
		return errors.Join(first, second)
	case firstIsReal:
		return first
	case secondIsReal:
		return second
	default:
		return nil
	}
}

// halfCloser is implemented by connections that support a TCP-style
// half-close (e.g. *net.TCPConn), letting one direction of a duplex
// connection reach EOF without severing the other direction.
type halfCloser interface {
	CloseWrite() error
}

// closeWrite half-closes conn's write side if it supports halfCloser,
// signalling "no more data from me" without preventing the still-copying
// reverse direction from completing. Connections that don't support
// half-close (e.g. net.Pipe in tests) are left open here; closeBoth's full
// close after both directions finish still applies in that case. Returns
// the underlying CloseWrite error (nil if conn doesn't support half-close)
// so callers can decide whether a non-closed-conn failure is worth logging;
// previously this error was silently discarded, which could mask a failed
// FIN leaving the peer's read blocked indefinitely.
func closeWrite(conn net.Conn) error {
	if hc, ok := conn.(halfCloser); ok {
		return hc.CloseWrite()
	}
	return nil
}

func isClosedConnErr(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	// os.ErrDeadlineExceeded surfaces from SetDeadline-backed connections
	// when closeBoth's context-cancellation path races a still-running
	// io.Copy; it is an expected side effect of orderly shutdown, not a
	// real transport error.
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	// syscall.ECONNRESET wrapped in *net.OpError is a benign "connection
	// reset by peer" that occurs on Linux when a half-closed peer resets
	// instead of completing a clean FIN; treat it the same as any other
	// closed-connection signal rather than propagating it as an error.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errors.Is(opErr.Err, syscall.ECONNRESET)
	}
	return false
}

// errNilConnContext is returned by Handle when cc itself is nil, so a
// caller bug (invoking Handle without a ConnContext) is surfaced as an
// error instead of silently treated as success.
var errNilConnContext = errors.New("passthrough: ConnContext must not be nil")

// errNilDialer is returned by Handle when h.Dialer is nil, so a zero-value
// or partially initialized PassthroughHandler fails with a descriptive
// error instead of panicking on the first DialUpstream call.
var errNilDialer = errors.New("passthrough: Dialer must not be nil")

// errNilDownstream is returned by Handle when cc is non-nil but
// cc.Downstream is nil. A nil Downstream on a non-nil ConnContext is almost
// certainly a caller bug; silently returning nil (success) would hide it.
var errNilDownstream = errors.New("passthrough: ConnContext.Downstream must not be nil")

// logError logs msg (with err, if non-nil) via h.Log if set, or discards it
// otherwise. h.Log was previously an unused field with no call sites in this
// file; wiring it up here surfaces dial failures and misconfiguration
// instead of silently swallowing them.
func (h *PassthroughHandler) logError(msg string, err error) {
	if h.Log == nil {
		return
	}
	if err != nil {
		h.Log.Error(msg, "error", err)
		return
	}
	h.Log.Error(msg)
}
