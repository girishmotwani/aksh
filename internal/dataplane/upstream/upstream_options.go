package upstream

import (
	"crypto/x509"
	"time"
)

// UpstreamOptions configures DirectDialer's dial/handshake/concurrency
// behaviour. See docs/design/S1a-dataplane-capture.md §8.3.
type UpstreamOptions struct {
	DialTimeout time.Duration
	// HandshakeTimeout is deliberately NOT validated by Validate(): the
	// spec (docs/design/S1a-dataplane-capture.md §8.3) defines no
	// ErrMissingHandshakeTimeout/ErrInvalidHandshakeTimeout case, so a
	// zero value is accepted and means "no deadline", consistent with
	// context's own zero-value semantics.
	HandshakeTimeout   time.Duration
	MaxConcurrentDials int
	ProxyUID           uint32 // matches capture.Options.ProxyUID's type; must be > 0
	ListenerPort       uint16
	RootCAs            *x509.CertPool // nil means system roots
	NextProtos         []string
}

// Validate checks UpstreamOptions for the ordered set of rules in
// docs/design/S1a-dataplane-capture.md §8.3 (first failing check wins).
// It never checks a MetricsRecorder -- UpstreamOptions carries no metrics
// field, and that nil-check is NewDirectDialer's responsibility (see
// ErrMissingMetrics in errors.go): the design doc's
// NewDirectDialer(opts, reg, m) signature makes the MetricsRecorder a
// separate constructor parameter, not an Options field. See direct_test.go's
// Validate_NilMetricsRecorderReference_ReturnsErrMissingMetrics subtest.
func (o UpstreamOptions) Validate() error {
	if o.DialTimeout == 0 {
		return ErrMissingDialTimeout
	}
	if o.DialTimeout < 0 {
		return ErrInvalidDialTimeout
	}
	if o.ProxyUID == 0 {
		return ErrInvalidProxyUID
	}
	if o.MaxConcurrentDials <= 0 {
		return ErrInvalidMaxConcurrentDials
	}
	return nil
}
