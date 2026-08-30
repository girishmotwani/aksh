package tlsterm

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

// Terminator supplies the per-ClientHello *tls.Config used by the downstream
// TLS handshake and enforces post-handshake identity invariants. See
// docs/design/S1a-dataplane-capture.md §11.1.
type Terminator struct {
	source  dataplane.LeafSource
	opts    LeafOptions
	metrics audit.MetricsRecorder
}

// NewTerminator constructs a Terminator. source and opts.Validate() are both
// required; metrics may be nil (a no-op recorder is used in that case).
func NewTerminator(source dataplane.LeafSource, opts LeafOptions, metrics audit.MetricsRecorder) (*Terminator, error) {
	if source == nil {
		return nil, ErrMissingLeafSource
	}
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
	}
	if metrics == nil {
		metrics = audit.NopMetricsRecorder{}
	}
	return &Terminator{source: source, opts: opts, metrics: metrics}, nil
}

// GetConfigForClient has the exact signature crypto/tls.Config requires
// (spec #305). It canonicalises the ClientHello's SNI, mints/fetches the
// matching leaf certificate via the injected dataplane.LeafSource, and
// returns a *tls.Config scoped to that one handshake.
func (t *Terminator) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	start := time.Now()
	defer func() {
		t.metrics.StageDuration(audit.StageTLSConfigBuild, time.Since(start))
	}()

	if hello == nil {
		t.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonMissingClientHello, audit.TransportTLS, false)
		return nil, ErrMissingClientHello
	}

	if hello.ServerName == "" {
		t.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonNoSNI, audit.TransportTLS, false)
		return nil, ErrNoSNI
	}

	identity, err := CanonicaliseServerName(hello.ServerName)
	if err != nil {
		// hello.ServerName is agent-controlled and is deliberately never
		// passed as a label; the closed ReasonMalformedTarget carries the
		// bounded meaning.
		t.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonMalformedTarget, audit.TransportTLS, false)
		return nil, fmt.Errorf("%w: %w", ErrInvalidSNI, err)
	}

	cert, err := t.source.CertificateFor(hello.Context(), identity)
	if err != nil {
		// A leaf-mint failure is a proxy-dependency fault, not a clean
		// rejection, so fault=true.
		t.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonHandshakeFailed, audit.TransportTLS, true)
		return nil, fmt.Errorf("tlsterm: mint leaf for %q: %w", identity, err)
	}

	cfg := &tls.Config{
		MinVersion:             t.opts.MinVersion,
		NextProtos:             append([]string(nil), t.opts.NextProtos...),
		Certificates:           []tls.Certificate{*cert},
		SessionTicketsDisabled: true,
		ClientAuth:             tls.NoClientCert,
	}
	return cfg, nil
}

// PostHandshakeAssert enforces the invariants that only hold once the
// handshake has completed (spec rows #312-#314): the negotiated ServerName
// must match the SNI recorded before the handshake began, and the
// connection must not be an anomalous session resumption (no valid ticket
// could have been issued in 5A, since SessionTicketsDisabled is set).
func (t *Terminator) PostHandshakeAssert(state tls.ConnectionState, candidateSNI string) error {
	if state.DidResume {
		t.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonHandshakeFailed, audit.TransportTLS, false)
		return fmt.Errorf("%w: unexpected session resumption", ErrHandshakeAssertFailed)
	}
	// candidateSNI is expected to already be canonical (ConnContext.CandidateSNI
	// is populated from GetConfigForClient's own canonicalisation), but it is
	// canonicalised again defensively here so a caller passing a non-canonical
	// value (e.g. mixed case) does not trigger a false-mismatch reject.
	negotiated, negErr := CanonicaliseServerName(state.ServerName)
	candidate, candErr := CanonicaliseServerName(candidateSNI)
	if negErr != nil || candErr != nil || negotiated != candidate {
		t.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonHandshakeFailed, audit.TransportTLS, false)
		return fmt.Errorf("%w: negotiated ServerName %q does not match candidate SNI %q",
			ErrHandshakeAssertFailed, state.ServerName, candidateSNI)
	}
	return nil
}

// RecordHandshakeFailure records a RejectHandshake (T4) decision for a
// connection whose downstream handshake failed after GetConfigForClient
// already returned a valid *tls.Config (spec #316). crypto/tls does not
// itself notify GetConfigForClient of a later handshake failure, so the
// caller (the listener, watching the handshake's outcome) invokes this
// explicitly rather than the failure going unaccounted.
func (t *Terminator) RecordHandshakeFailure(candidateSNI string) {
	t.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonHandshakeFailed, audit.TransportTLS, true)
}

// RecordPlaintextReject records the T9 rejection of a connection that carried
// no ClientHello at all, i.e. a captured plaintext stream (issue #83).
//
// This is deliberately not RecordHandshakeFailure. A plaintext connection is
// refused by design, so:
//
//   - transport is Plaintext, not TLS. The connection carried no TLS record,
//     and "is anything of mine being refused for being plaintext?" is the
//     natural operator query.
//   - fault is false. fault=true means aksh malfunctioned; refusing plaintext
//     is a transport-policy outcome, and labelling it a fault both inflates
//     fault-rate SLOs and points the operator at aksh rather than at their own
//     workload.
//   - the reason is unsupported_protocol, matching what the discriminator and
//     passthrough paths already use for plaintext.
//
// It also raises the T9 class, which the taxonomy has always defined
// (RejectPlaintextRegistryUnavail, RejectClassPlaintextRegistryUnavail) but no
// production site raised.
func (t *Terminator) RecordPlaintextReject() {
	t.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonUnsupportedProtocol, audit.TransportPlaintext, false)
	t.metrics.TransportReject(audit.RejectClassPlaintextRegistryUnavail, audit.BoundNone)
}
