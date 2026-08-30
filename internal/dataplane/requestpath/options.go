package requestpath

import (
	"fmt"
	"time"
)

const (
	defaultMaxHeaderBytes          = 64 * 1024
	defaultMaxInflightRequests     = 2048
	defaultCopyBufferBytes         = 32 * 1024
	defaultHeaderReadTimeout       = 10 * time.Second
	defaultIdleTimeout             = 90 * time.Second
	defaultProgressDeadline        = 60 * time.Second
	defaultUpstreamDialTimeout     = 15 * time.Second
	defaultUpstreamResponseTimeout = 30 * time.Second
	defaultMaxRejectionAudits      = 64
	defaultRejectionAuditTimeout   = 250 * time.Millisecond
	defaultMaxResponseBodyBytes    = 128 * 1024 * 1024
)

// Options configures the 5B request path.
type Options struct {
	MaxHeaderBytes          int
	MaxInflightRequests     int
	CopyBufferBytes         int
	HeaderReadTimeout       time.Duration
	IdleTimeout             time.Duration
	ProgressDeadline        time.Duration
	UpstreamDialTimeout     time.Duration
	UpstreamResponseTimeout time.Duration
	MaxRejectionAudits      int
	RejectionAuditTimeout   time.Duration
	MaxResponseBodyBytes    int64
}

// DefaultOptions returns the design defaults for the request path.
func DefaultOptions() Options {
	return Options{
		MaxHeaderBytes:          defaultMaxHeaderBytes,
		MaxInflightRequests:     defaultMaxInflightRequests,
		CopyBufferBytes:         defaultCopyBufferBytes,
		HeaderReadTimeout:       defaultHeaderReadTimeout,
		IdleTimeout:             defaultIdleTimeout,
		ProgressDeadline:        defaultProgressDeadline,
		UpstreamDialTimeout:     defaultUpstreamDialTimeout,
		UpstreamResponseTimeout: defaultUpstreamResponseTimeout,
		MaxRejectionAudits:      defaultMaxRejectionAudits,
		RejectionAuditTimeout:   defaultRejectionAuditTimeout,
		MaxResponseBodyBytes:    defaultMaxResponseBodyBytes,
	}
}

// Validate rejects any zero or negative bound.
func (o Options) Validate() error {
	switch {
	case o.MaxHeaderBytes <= 0:
		return fmt.Errorf("MaxHeaderBytes must be greater than zero")
	case o.MaxInflightRequests <= 0:
		return fmt.Errorf("MaxInflightRequests must be greater than zero")
	case o.CopyBufferBytes <= 0:
		return fmt.Errorf("CopyBufferBytes must be greater than zero")
	case o.HeaderReadTimeout <= 0:
		return fmt.Errorf("HeaderReadTimeout must be greater than zero")
	case o.IdleTimeout <= 0:
		return fmt.Errorf("IdleTimeout must be greater than zero")
	case o.ProgressDeadline <= 0:
		return fmt.Errorf("ProgressDeadline must be greater than zero")
	case o.UpstreamDialTimeout <= 0:
		return fmt.Errorf("UpstreamDialTimeout must be greater than zero")
	case o.UpstreamResponseTimeout <= 0:
		return fmt.Errorf("UpstreamResponseTimeout must be greater than zero")
	case o.MaxRejectionAudits <= 0:
		return fmt.Errorf("MaxRejectionAudits must be greater than zero")
	case o.RejectionAuditTimeout <= 0:
		return fmt.Errorf("RejectionAuditTimeout must be greater than zero")
	case o.MaxResponseBodyBytes <= 0:
		return fmt.Errorf("MaxResponseBodyBytes must be greater than zero")
	default:
		return nil
	}
}
