package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

// DirectDialer establishes one TLS connection per DialUpstream call to the
// kernel-attested destination and verifies the peer against the validated
// identity. It performs no pooling: that is Phase 5C (ADR-S1a-10). credID is
// accepted and forwarded through DialUpstream unmodified in 5A; Phase 5C
// will add validation/recording once it becomes part of the pool key. See
// docs/design/S1a-dataplane-capture.md §8.3.
type DirectDialer struct {
	dialer      *net.Dialer
	rootCAs     *x509.CertPool // nil means system roots
	nextProtos  []string
	connectTO   time.Duration
	handshakeTO time.Duration
	listenerP   uint16
	sem         chan struct{} // bounds concurrent upstream dials
	registry    *listener.SelfDialRegistry
	metrics     audit.MetricsRecorder
}

// compile-time frozen-interface assertion (spec #334).
var _ dataplane.UpstreamDialer = (*DirectDialer)(nil)

// NewDirectDialer constructs a DirectDialer. reg and m are both required;
// opts must satisfy opts.Validate(). reg/m nil-checks are performed before
// opts.Validate() so a nil reg or m is reported precisely even when opts is
// itself invalid.
func NewDirectDialer(opts UpstreamOptions, reg *listener.SelfDialRegistry, m audit.MetricsRecorder) (*DirectDialer, error) {
	if reg == nil {
		return nil, ErrMissingRegistry
	}
	if m == nil {
		return nil, ErrMissingMetrics
	}
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
	}
	return &DirectDialer{
		dialer:      &net.Dialer{},
		rootCAs:     opts.RootCAs,
		nextProtos:  append([]string(nil), opts.NextProtos...),
		connectTO:   opts.DialTimeout,
		handshakeTO: opts.HandshakeTimeout,
		listenerP:   opts.ListenerPort,
		sem:         make(chan struct{}, opts.MaxConcurrentDials),
		registry:    reg,
		metrics:     m,
	}, nil
}

// DialUpstream validates the destination and identity, rejects self-dials
// and over-limit concurrency, dials and TLS-handshakes with the upstream,
// and returns a wrapper net.Conn (see docs/design/S1a-dataplane-capture.md
// §8.3).
//
// Decision-metric invariant: DialUpstream records exactly one
// aksh_decisions_total deny sample on every error return, naming the specific
// reason, and records none at all on success. Callers rely on this. The relay
// (requestpath.ensureUpstream) claims the connection's decision latch without
// recording anything of its own precisely because this method has already
// recorded the more informative reason; if any error path here stopped
// recording, that connection would produce no decision sample at all. Any new
// error return must therefore record before returning. See issue #89.
func (d *DirectDialer) DialUpstream(ctx context.Context, addr netip.AddrPort, serverName string, credID string) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !addr.IsValid() || addr.Port() == 0 {
		d.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonInternal, audit.TransportTLS, true)
		return nil, ErrInvalidAddr
	}
	if !addr.Addr().Is4() {
		d.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonInternal, audit.TransportTLS, true)
		return nil, ErrUnsupportedAddrFamily
	}
	if serverName == "" {
		d.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonInternal, audit.TransportTLS, true)
		return nil, ErrEmptyServerName
	}
	// credID is an opaque, forward-compatible identifier for Phase 5C's
	// pool key; 5A neither interprets nor stores it beyond accepting
	// either "" (no-auth sentinel) or a non-empty string unmodified. No
	// validation beyond that is defined by the binding spec.

	// Loop guard (design doc §8.3 step 3): reject strictly before any
	// socket is created or handshake attempted. The listener-port match
	// models "resolved destination's owning uid equals ProxyUID" -- the
	// only address a self-dial could use to reach our own accept loop is
	// this loopback+ListenerPort endpoint (DirectDialer has no
	// pre-connect uid-introspection API). The registry match is the
	// defense-in-depth secondary check for the racy redirected-loop case;
	// the true primary, race-free uid check lives upstream in the
	// resolver/capture layer.
	if d.isSelfDial(addr) {
		// fault=false: a loop-guard rejection is a clean policy decision,
		// not an I/O or system fault (the fault dimension flags only
		// dependency/proxy/internal faults, e.g. dial/write failures).
		d.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonLoopGuard, audit.TransportTLS, false)
		return nil, ErrLoopGuard
	}

	start := time.Now()

	// Concurrency bound (T7): reject immediately rather than queueing, so
	// a saturated dialer fails fast instead of adding latency.
	select {
	case d.sem <- struct{}{}:
	default:
		d.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonResourceLimit, audit.TransportTLS, false)
		return nil, ErrUpstreamConcurrency
	}
	release := func() { <-d.sem }

	connectCtx := ctx
	var cancel context.CancelFunc
	if d.connectTO > 0 {
		connectCtx, cancel = context.WithTimeout(ctx, d.connectTO)
	}
	tcp, err := d.dialer.DialContext(connectCtx, "tcp4", addr.String())
	if cancel != nil {
		cancel()
	}
	if err != nil {
		release()
		d.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonDialFailed, audit.TransportTLS, true)
		d.metrics.StageDuration(audit.StageUpstreamDial, time.Since(start))
		return nil, fmt.Errorf("upstream: dial %s: %w", addr, err)
	}

	tcpAddr, ok := tcp.LocalAddr().(*net.TCPAddr)
	if !ok {
		_ = tcp.Close()
		release()
		d.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonInternal, audit.TransportTLS, true)
		d.metrics.StageDuration(audit.StageUpstreamDial, time.Since(start))
		return nil, fmt.Errorf("upstream: unexpected local address type %T from %s", tcp.LocalAddr(), addr)
	}
	local, ok := netip.AddrFromSlice(tcpAddr.IP)
	var localAddrPort netip.AddrPort
	if ok {
		localAddrPort = netip.AddrPortFrom(local.Unmap(), uint16(tcpAddr.Port))
		if err := d.registry.Add(localAddrPort); err != nil {
			_ = tcp.Close()
			release()
			d.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonRegistryAddFailed, audit.TransportTLS, true)
			d.metrics.StageDuration(audit.StageUpstreamDial, time.Since(start))
			return nil, fmt.Errorf("upstream: registering self-dial guard: %w", err)
		}
	} else {
		// AddrFromSlice should never fail for a *net.TCPAddr.IP, but if
		// it ever did, silently skipping registration would leave a live
		// connection outside the self-dial guard's defense-in-depth
		// coverage; fail closed instead.
		_ = tcp.Close()
		release()
		d.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonRegistryAddFailed, audit.TransportTLS, true)
		d.metrics.StageDuration(audit.StageUpstreamDial, time.Since(start))
		return nil, fmt.Errorf("upstream: could not parse local address %v for self-dial guard registration", tcpAddr)
	}

	tlsConfig := &tls.Config{
		ServerName: serverName,
		RootCAs:    d.rootCAs,
		MinVersion: tls.VersionTLS12,
		NextProtos: d.nextProtos,
	}
	tc := tls.Client(tcp, tlsConfig)

	handshakeCtx := ctx
	var hsCancel context.CancelFunc
	if d.handshakeTO > 0 {
		handshakeCtx, hsCancel = context.WithTimeout(ctx, d.handshakeTO)
	}
	err = tc.HandshakeContext(handshakeCtx)
	if hsCancel != nil {
		hsCancel()
	}
	if err != nil {
		_ = tc.Close()
		if localAddrPort.IsValid() {
			d.registry.Remove(localAddrPort)
		}
		release()
		d.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonHandshakeFailed, audit.TransportTLS, true)
		d.metrics.StageDuration(audit.StageUpstreamDial, time.Since(start))
		return nil, fmt.Errorf("upstream: TLS handshake with %s: %w", serverName, err)
	}

	// No DispositionAllow is recorded here. A successful upstream dial is a
	// connection-lifecycle event, not a terminal disposition: the request it
	// serves may still be denied, and the connection's single decision sample
	// is owned by the layer that reaches the terminal outcome (see
	// listener.ConnContext.MarkDecided). Recording an allow here made every
	// allowed request count twice — once here and once in the listener rollup
	// — which is half of issue #89.
	d.metrics.StageDuration(audit.StageUpstreamDial, time.Since(start))

	return &upstreamConn{
		Conn:     tc,
		release:  release,
		registry: d.registry,
		addr:     localAddrPort,
	}, nil
}

// upstreamConn wraps the TLS connection returned by DialUpstream, releasing
// the concurrency semaphore and deregistering the self-dial guard entry
// exactly once on Close, regardless of how many times Close is called
// (spec #352).
type upstreamConn struct {
	net.Conn
	release  func()
	registry *listener.SelfDialRegistry
	addr     netip.AddrPort
	closed   int32
}

func (c *upstreamConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		// Close the underlying socket before releasing the semaphore
		// slot/registry entry, so a new dial cannot be admitted while
		// this connection's fd is still open (spec #352's idempotency
		// requirement is unaffected: this ordering change is
		// unobservable from the caller's Close() return value).
		err := c.Conn.Close()
		if c.addr.IsValid() {
			c.registry.Remove(c.addr)
		}
		c.release()
		return err
	}
	return nil
}

// isSelfDial reports whether addr targets the proxy's own listener endpoint
// (loopback address matching the configured ListenerPort) or is already
// known to the SelfDialRegistry from a prior accept.
func (d *DirectDialer) isSelfDial(addr netip.AddrPort) bool {
	if addr.Addr().IsLoopback() && addr.Port() == d.listenerP {
		return true
	}
	return d.registry.Contains(addr)
}
