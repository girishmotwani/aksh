package listener

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
)

// ConnHandler is the 5A/5B seam for accepted connections.
type ConnHandler interface {
	Handle(ctx context.Context, cc *ConnContext) error
}

const (
	defaultMaxConnections         = 512
	defaultPeekTimeout            = 10 * time.Second
	defaultHandshakeRatePerSecond = 50
	defaultHandshakeRateBurst     = 100
)

// Options configures the loopback listener and protocol discriminator.
type Options struct {
	Name                   string
	ListenAddr             netip.AddrPort
	Handler                ConnHandler
	Metrics                audit.MetricsRecorder
	MaxConnections         int
	PeekTimeout            time.Duration
	HandshakeRatePerSecond int
	HandshakeRateBurst     int
	BlockNonTCP            bool
	AllowUnsafeStartup     bool
}

// DefaultOptions returns the design defaults for 5A listener startup
// (ListenAddr, MaxConnections, PeekTimeout). It intentionally does not set
// Handler or Metrics, both of which are mandatory (see Validate): callers
// must always populate those two fields themselves before Validate will
// pass, since there is no meaningful process-wide default for either.
func DefaultOptions() Options {
	return Options{
		Name:                   "listener",
		ListenAddr:             netip.MustParseAddrPort("127.0.0.1:15001"),
		MaxConnections:         defaultMaxConnections,
		PeekTimeout:            defaultPeekTimeout,
		HandshakeRatePerSecond: defaultHandshakeRatePerSecond,
		HandshakeRateBurst:     defaultHandshakeRateBurst,
	}
}

// Validate returns the first configuration error in a fixed order.
//
// ListenAddr is intentionally restricted to IPv4 loopback (127.0.0.0/8), not
// just any loopback address: Bind hardcodes net.Listen("tcp4", ...), so an
// IPv6 loopback address (::1) would pass a family-agnostic loopback check
// here only to fail confusingly inside Bind with an address-family mismatch.
// If IPv6 support is ever needed, Bind's network argument must be widened
// (and made address-family-aware) at the same time as this check.
func (o *Options) Validate() error {
	if o == nil {
		return ErrMissingOptions
	}
	if o.ListenAddr == (netip.AddrPort{}) {
		return ErrMissingListenAddr
	}
	addr := o.ListenAddr.Addr().Unmap()
	if !addr.Is4() || !addr.IsLoopback() {
		return fmt.Errorf("ListenAddr=%v: %w", o.ListenAddr, ErrNonLoopbackAddr)
	}
	if o.Name == "" {
		return ErrMissingName
	}
	if o.Handler == nil {
		return ErrMissingHandler
	}
	if o.Metrics == nil {
		return ErrMissingMetrics
	}
	if o.MaxConnections <= 0 {
		return ErrInvalidMaxConnections
	}
	if o.PeekTimeout <= 0 {
		return ErrInvalidPeekTimeout
	}
	if o.HandshakeRatePerSecond <= 0 {
		return ErrInvalidHandshakeRate
	}
	if o.HandshakeRateBurst <= 0 {
		return ErrInvalidHandshakeBurst
	}
	// BlockNonTCP requires AllowUnsafeStartup because it changes accept-loop
	// behavior (rejecting any non-TCP-classified connection outright) in a
	// way that is not exercised by this package's default test/production
	// path; operators must explicitly acknowledge the unvalidated startup
	// mode before enabling it, even though "block non-TCP" itself sounds
	// like a safe, restrictive policy.
	if o.BlockNonTCP && !o.AllowUnsafeStartup {
		return fmt.Errorf("BlockNonTCP=true requires unsafe startup: %w", ErrRequiresUnsafeStartup)
	}
	return nil
}
