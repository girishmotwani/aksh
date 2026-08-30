package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/dataplane/requestpath"
	"github.com/girishmotwani/aksh/internal/dataplane/tlsterm"
	"github.com/girishmotwani/aksh/internal/policy"
)

var (
	// errNilNext is returned by Handle when no downstream handler is wired, so
	// a misconfigured chain fails closed instead of silently dropping traffic.
	errNilNext = errors.New("runtime: tls handler has nil Next")
	// errNilTerminator is returned by Handle when no terminator is wired, so a
	// connection is never delegated without TLS termination.
	errNilTerminator = errors.New("runtime: tls handler has nil Terminator")
	// errBareRequestPathBypass is returned by NewTLSTerminatingConnHandler when
	// the request path would receive raw connections, bypassing TLS termination.
	errBareRequestPathBypass = errors.New("runtime: refusing to wire bare requestpath.Handler as Next, which would bypass TLS termination")
	// errNilContext is returned by Handle when the context is nil, so the handler
	// fails closed instead of panicking in ctx.Err().
	errNilContext = errors.New("runtime: tls handler received nil context")
	// errNilConnContext is returned by Handle when the ConnContext is nil, so the
	// handler fails closed instead of panicking while building the TLS server.
	errNilConnContext = errors.New("runtime: tls handler received nil ConnContext")
	// errNilDownstream is returned by Handle when the ConnContext carries no
	// downstream connection, so the handler fails closed instead of panicking in
	// tls.Server.
	errNilDownstream = errors.New("runtime: tls handler received nil downstream connection")
)

// tlsTerminator is the narrow downstream-TLS contract the connection handler
// consumes. It exists so the handler depends on behaviour rather than on a
// concrete terminator, which makes the post-handshake assertion branch
// injectable without manufacturing an impossible ConnContext.
type tlsTerminator interface {
	GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error)
	PostHandshakeAssert(state tls.ConnectionState, candidateSNI string) error
	RecordHandshakeFailure(candidateSNI string)
	RecordPlaintextReject()
}

// tlsTerminatingConnHandler performs the downstream TLS handshake through a
// tlsterm.Terminator, populates the connection's TLS fields, and delegates to
// the request path. It exists only to insert TLS termination before
// requestpath.Handler and holds no state of its own.
type tlsTerminatingConnHandler struct {
	Terminator tlsTerminator
	Next       listener.ConnHandler
	// Log, when non-nil, receives a WARN line naming the destination of a
	// refused plaintext connection (issue #83). Optional: a nil Log disables
	// only the log line, never the metrics.
	Log *slog.Logger
}

// NewTLSTerminatingConnHandler constructs the TLS-terminating handler. It fails
// closed when Next is a bare *requestpath.Handler, because wiring that handler
// directly to the listener would bypass TLS termination, and when the
// terminator is nil. Nil Next and nil context/ConnContext are validated at call
// time in Handle, not here.
func NewTLSTerminatingConnHandler(next listener.ConnHandler, term *tlsterm.Terminator) (*tlsTerminatingConnHandler, error) {
	if _, ok := next.(*requestpath.Handler); ok {
		return nil, errBareRequestPathBypass
	}
	if term == nil {
		return nil, errNilTerminator
	}
	return &tlsTerminatingConnHandler{Terminator: term, Next: next}, nil
}

// terminatorIsNil reports whether t is unusable: either an untyped nil
// interface, or an interface holding a nil value of any implementing type whose
// underlying kind can be nil. The typed-nil case is reachable because the
// handler is also constructed as a struct literal in assembly.go, which no
// constructor check can intercept. The check is reflective rather than a type
// assertion on *tlsterm.Terminator so it covers every implementation of the
// seam, not only the one production wires today: any named pointer, map, slice,
// func, channel or unsafe.Pointer type can carry the three seam methods, and a
// nil value of any of them panics or misbehaves on first use. reflect.Interface
// is absent because reflect.ValueOf reports the dynamic kind, never Interface.
func terminatorIsNil(t tlsTerminator) bool {
	if t == nil {
		return true
	}
	switch v := reflect.ValueOf(t); v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return v.IsNil()
	default:
		return false
	}
}

// configForClient returns the per-connection ClientHello callback for cc. It
// delegates certificate selection to the terminator and, only once that
// succeeds, records the canonical SNI on cc. Canonicalisation uses the same
// tlsterm rule set the terminator applies internally, so the recorded value is
// byte-identical to the identity the leaf was minted for. cc is written on the
// goroutine that calls HandshakeContext, which is the same goroutine that later
// reads the field, so no lock is needed.
func (h tlsTerminatingConnHandler) configForClient(cc *listener.ConnContext, recorded *bool) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		cfg, err := h.Terminator.GetConfigForClient(hello)
		if err != nil {
			// Reject path: nothing is recorded *here*, so a refused ClientHello
			// leaves CandidateSNI empty and the handshake fails closed. The
			// terminator, however, has already recorded the specific reason
			// (missing_client_hello, no_sni, malformed_target, handshake_failed).
			// Flag that so Handle does not add a second, coarser
			// handshake_failed sample on top when HandshakeContext subsequently
			// fails - one connection, one decision (issues #83 and #89).
			//
			// A plain bool needs no synchronisation: this callback runs on the
			// goroutine that called HandshakeContext, which is the same
			// goroutine that reads the flag afterwards.
			*recorded = true
			return nil, err
		}
		identity, err := tlsterm.CanonicaliseServerName(hello.ServerName)
		if err != nil {
			// Defensive: currently unreachable because the terminator
			// canonicalised the same input successfully on the line above.
			// Wrapped so this call site stays distinguishable from the
			// terminator's own canonicalisation failure if the two rule sets
			// ever diverge.
			return nil, fmt.Errorf("runtime: capture canonicalisation: %w", err)
		}
		cc.CandidateSNI = identity
		return cfg, nil
	}
}

// Handle terminates downstream TLS and delegates to Next. It validates the
// wiring and context before touching the connection, drives the handshake
// through the terminator's per-ClientHello config path, enforces the
// post-handshake identity assertion, populates the ConnContext TLS fields, and
// only then delegates. Any handshake or assertion failure returns without
// delegating so the request path never sees an unterminated connection.
func (h tlsTerminatingConnHandler) Handle(ctx context.Context, cc *listener.ConnContext) error {
	if h.Next == nil {
		return errNilNext
	}
	if terminatorIsNil(h.Terminator) {
		return errNilTerminator
	}
	if ctx == nil {
		return errNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if cc == nil {
		return errNilConnContext
	}
	if cc.Downstream == nil {
		return errNilDownstream
	}

	var configRecorded bool
	tlsConn := tls.Server(cc.Downstream, &tls.Config{
		GetConfigForClient: h.configForClient(cc, &configRecorded),
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		// crypto/tls does not report a post-config handshake failure back to the
		// terminator, so account for it explicitly before propagating.
		//
		// Classify plaintext separately (issue #83). A captured connection that
		// carried no ClientHello is not a failed TLS handshake, it is a
		// connection that was never TLS. crypto/tls surfaces exactly that as a
		// tls.RecordHeaderError: the first bytes could not be read as a TLS
		// record header. Reporting it as handshake_failed/fault=true/tls made
		// the most common real-world misconfiguration - an agent that must
		// speak plaintext to something in-cluster - undiagnosable from aksh's
		// own signals.
		//
		// The latch guard is what keeps this to one decision per connection:
		// Handle returns the error, so without it the listener's rollup would
		// add a second, coarser internal/fault=true sample on top (issue #89,
		// and problem 4 of #83).
		var recordHeaderErr tls.RecordHeaderError
		plaintext := errors.As(err, &recordHeaderErr)
		if cc.MarkDecided() {
			switch {
			case plaintext:
				h.Terminator.RecordPlaintextReject()
			case configRecorded:
				// The terminator already recorded the specific ClientHello
				// rejection reason; the latch is claimed purely to suppress
				// the listener rollup.
			default:
				h.Terminator.RecordHandshakeFailure(cc.CandidateSNI)
			}
		}
		if plaintext && h.Log != nil {
			// The destination is known here and is the single most useful
			// field for answering "what got refused, and where was it going?".
			h.Log.Warn("refused plaintext connection: aksh requires TLS on captured egress",
				"original_dst", cc.OriginalDst.String(),
				"peer", cc.PeerAddr.String(),
				"conn_id", cc.ConnID,
			)
		}
		return err
	}

	state := tlsConn.ConnectionState()
	if err := h.Terminator.PostHandshakeAssert(state, cc.CandidateSNI); err != nil {
		// PostHandshakeAssert records its own deny before returning, so claim
		// the latch to stop the listener rollup adding a second, coarser
		// internal/fault=true sample on top (the #89 invariant).
		cc.MarkDecided()
		return err
	}

	// Populate the TLS-derived fields before delegating so the request path sees
	// the terminated stream and its negotiated protocol.
	cc.Downstream = tlsConn
	cc.Protocol = listener.ProtocolTLS
	cc.Transport = policy.TransportTLS
	cc.NegotiatedALPN = state.NegotiatedProtocol

	return h.Next.Handle(ctx, cc)
}

// Compile-time assertion that the handler satisfies the listener seam.
var _ listener.ConnHandler = tlsTerminatingConnHandler{}
