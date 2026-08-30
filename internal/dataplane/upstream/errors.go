package upstream

import "errors"

// Sentinel errors returned by UpstreamOptions validation, DirectDialer
// construction, and DialUpstream.
var (
	// NewDirectDialer construction (direct.go). Each sentinel below is
	// returned by exactly one function -- see its own comment for which.

	// ErrMissingRegistry is returned by NewDirectDialer when reg is nil.
	ErrMissingRegistry = errors.New("upstream: SelfDialRegistry is required")
	// ErrMissingMetrics is returned by NewDirectDialer when m is nil.
	// UpstreamOptions carries no Metrics field and Validate() never
	// returns this error; the nil-metrics check is constructor-only,
	// exactly mirroring the design doc's NewDirectDialer(opts, reg, m)
	// signature (m is a separate parameter, not an Options field).
	ErrMissingMetrics = errors.New("upstream: MetricsRecorder is required")
	// ErrInvalidOptions is returned by NewDirectDialer when opts.Validate()
	// fails; it wraps the underlying Validate() error.
	ErrInvalidOptions = errors.New("upstream: UpstreamOptions is invalid")

	// UpstreamOptions validation (upstream_options.go).

	// ErrMissingDialTimeout is returned by Validate() when DialTimeout is
	// the Go zero value.
	ErrMissingDialTimeout = errors.New("upstream: DialTimeout is required")
	// ErrInvalidDialTimeout is returned by Validate() when DialTimeout is
	// negative.
	ErrInvalidDialTimeout = errors.New("upstream: DialTimeout must not be negative")
	// ErrInvalidProxyUID is returned by Validate() when ProxyUID is 0.
	ErrInvalidProxyUID = errors.New("upstream: ProxyUID must not be zero")
	// ErrInvalidMaxConcurrentDials is returned by Validate() when
	// MaxConcurrentDials is 0 or negative (a non-positive limit would
	// either reject all upstream dials or panic on make(chan, n)).
	ErrInvalidMaxConcurrentDials = errors.New("upstream: MaxConcurrentDials must be greater than zero")

	// DialUpstream validation and rejection (direct.go).

	// ErrInvalidAddr is returned by DialUpstream when addr is not
	// addr.IsValid() or addr.Port() == 0.
	ErrInvalidAddr = errors.New("upstream: destination address is invalid")
	// ErrEmptyServerName is returned by DialUpstream when serverName is
	// the empty string.
	ErrEmptyServerName = errors.New("upstream: server name is empty")
	// ErrUnsupportedAddrFamily is returned by DialUpstream when addr is a
	// valid, non-zero address that is not IPv4 (IPv6 is out of scope for
	// Phase 5A).
	ErrUnsupportedAddrFamily = errors.New("upstream: only IPv4 destination addresses are supported in Phase 5A")
	// ErrLoopGuard is returned by DialUpstream when addr matches the
	// proxy's own listener endpoint (T2 rejection).
	ErrLoopGuard = errors.New("upstream: destination address matches the proxy's own listener endpoint")
	// ErrUpstreamConcurrency is returned by DialUpstream when the
	// configured MaxConcurrentDials limit is already saturated (T7
	// rejection).
	ErrUpstreamConcurrency = errors.New("upstream: maximum concurrent upstream dials reached")
)
