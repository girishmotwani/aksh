package listener

import "errors"

// Sentinel errors returned by listener construction, validation, classification,
// and lifecycle transitions.
var (
	ErrInvalidAddr  = errors.New("listener: address is invalid")
	ErrAlreadyBound = errors.New("listener: already bound")
	ErrNotBound     = errors.New("listener: not bound")
	// ErrServing is returned by AcceptProbe when the listener is already in
	// the serving state (Serve has been called and has not returned). It is
	// distinct from ErrAlreadyServing, which Serve itself returns when
	// called a second time while already serving.
	ErrServing = errors.New("listener: AcceptProbe called while Serve is active")
	// ErrAlreadyServing is returned by Serve when it is called a second time
	// while already serving. It is distinct from ErrServing, which
	// AcceptProbe returns when called while Serve is active.
	ErrAlreadyServing        = errors.New("listener: Serve called while already serving")
	ErrMissingHandler        = errors.New("listener: handler is required")
	ErrMissingOptions        = errors.New("listener: options are required")
	ErrMissingMetrics        = errors.New("listener: metrics recorder is required")
	ErrInvalidMaxConnections = errors.New("listener: MaxConnections must be positive")
	ErrInvalidPeekTimeout    = errors.New("listener: PeekTimeout must be positive")
	ErrInvalidHandshakeRate  = errors.New("listener: HandshakeRatePerSecond must be positive")
	ErrInvalidHandshakeBurst = errors.New("listener: HandshakeRateBurst must be positive")
	ErrRequiresUnsafeStartup = errors.New("listener: option requires AllowUnsafeStartup")
	ErrNonLoopbackAddr       = errors.New("listener: ListenAddr must be loopback")
	ErrMissingListenAddr     = errors.New("listener: ListenAddr is required")
	ErrMissingName           = errors.New("listener: Name is required")
	ErrMissingConn           = errors.New("listener: connection is required")
	ErrPeekTimeout           = errors.New("listener: peek timed out")
	ErrUnsupportedProtocol   = errors.New("listener: protocol is not forwardable")
	ErrSetDeadlineFailed     = errors.New("listener: failed to set read deadline for peek")
	ErrInvalidInterval       = errors.New("listener: refresh interval must be positive")
	ErrNoProgress            = errors.New("listener: underlying conn made no progress discarding peeked bytes")
	ErrClosed                = errors.New("listener: already closed")
	ErrMissingLoad           = errors.New("listener: PodLocalSet load function is required")
)
