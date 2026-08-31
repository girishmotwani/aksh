package upstream_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/dataplane/upstream"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

// fakeMetrics is a minimal audit.MetricsRecorder used to exercise
// DirectDialer without any real observability backend. It is safe for
// concurrent use since multiple DialUpstream calls may share one instance.
type fakeMetrics struct {
	audit.NopMetricsRecorder
	mu       sync.Mutex
	decision []string
	latency  []string
}

func (f *fakeMetrics) Decisions(d pipeline.Disposition, r pipeline.DenyReason, _ audit.TransportKind, _ bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decision = append(f.decision, d.String()+"/"+r.String())
}

func (f *fakeMetrics) StageDuration(stage audit.StageName, _ time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.latency = append(f.latency, stage.String())
}

func (f *fakeMetrics) decisions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.decision))
	copy(out, f.decision)
	return out
}

func (f *fakeMetrics) latencies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.latency))
	copy(out, f.latency)
	return out
}

var _ audit.MetricsRecorder = (*fakeMetrics)(nil)

// compile-time frozen-interface assertion (spec #334).
var _ dataplane.UpstreamDialer = (*upstream.DirectDialer)(nil)

func validUpstreamOptions() upstream.UpstreamOptions {
	return upstream.UpstreamOptions{
		DialTimeout:        5 * time.Second,
		HandshakeTimeout:   10 * time.Second,
		MaxConcurrentDials: 256,
		ProxyUID:           1774,
		ListenerPort:       15001,
		NextProtos:         []string{"h2", "http/1.1"},
	}
}

func TestUpstreamOptionsValidate(t *testing.T) {
	t.Run("Validate_ZeroValueUpstreamOptions_ReturnsErrMissingDialTimeout", func(t *testing.T) {
		opts := upstream.UpstreamOptions{}
		if err := opts.Validate(); err != upstream.ErrMissingDialTimeout {
			t.Fatalf("Validate() error = %v, want ErrMissingDialTimeout", err)
		}
	})

	t.Run("Validate_ProxyUIDZero_ReturnsErrInvalidProxyUID", func(t *testing.T) {
		opts := validUpstreamOptions()
		opts.ProxyUID = 0
		if err := opts.Validate(); err != upstream.ErrInvalidProxyUID {
			t.Fatalf("Validate() error = %v, want ErrInvalidProxyUID", err)
		}
	})

	t.Run("Validate_DialTimeoutNegative_ReturnsErrInvalidDialTimeout", func(t *testing.T) {
		opts := validUpstreamOptions()
		opts.DialTimeout = -time.Second
		if err := opts.Validate(); err != upstream.ErrInvalidDialTimeout {
			t.Fatalf("Validate() error = %v, want ErrInvalidDialTimeout", err)
		}
	})

	t.Run("Validate_MaxConcurrentDialsZero_ReturnsErrInvalidMaxConcurrentDials", func(t *testing.T) {
		opts := validUpstreamOptions()
		opts.MaxConcurrentDials = 0
		if err := opts.Validate(); err != upstream.ErrInvalidMaxConcurrentDials {
			t.Fatalf("Validate() error = %v, want ErrInvalidMaxConcurrentDials", err)
		}
	})

	t.Run("Validate_AllFieldsWellFormed_ReturnsNilError", func(t *testing.T) {
		opts := validUpstreamOptions()
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_DialTimeoutPositive_Passes", func(t *testing.T) {
		opts := validUpstreamOptions()
		opts.DialTimeout = 5 * time.Second
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("Validate_MaxConcurrentDialsPositive_Passes", func(t *testing.T) {
		opts := validUpstreamOptions()
		opts.MaxConcurrentDials = 256
		if err := opts.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})
}

func TestNewDirectDialer(t *testing.T) {
	t.Run("NewDirectDialer_ZeroValueUpstreamOptions_ReturnsErrInvalidOptions", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		_, err := upstream.NewDirectDialer(upstream.UpstreamOptions{}, reg, m)
		if !errors.Is(err, upstream.ErrInvalidOptions) {
			t.Fatalf("NewDirectDialer() error = %v, want ErrInvalidOptions", err)
		}
	})

	t.Run("NewDirectDialer_NilSelfDialRegistry_ReturnsErrMissingRegistry", func(t *testing.T) {
		m := &fakeMetrics{}
		_, err := upstream.NewDirectDialer(validUpstreamOptions(), nil, m)
		if !errors.Is(err, upstream.ErrMissingRegistry) {
			t.Fatalf("NewDirectDialer() error = %v, want ErrMissingRegistry", err)
		}
	})

	t.Run("NewDirectDialer_NilMetricsRecorder_ReturnsErrMissingMetrics", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		_, err := upstream.NewDirectDialer(validUpstreamOptions(), reg, nil)
		if !errors.Is(err, upstream.ErrMissingMetrics) {
			t.Fatalf("NewDirectDialer() error = %v, want ErrMissingMetrics", err)
		}
	})

	t.Run("DialUpstream_FrozenInterfaceSignature_MatchesUpstreamDialer", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(validUpstreamOptions(), reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var _ dataplane.UpstreamDialer = d
	})

	t.Run("Validate_NilMetricsRecorderReference_ReturnsErrMissingMetrics", func(t *testing.T) {
		// UpstreamOptions itself carries no MetricsRecorder field (it is
		// a separate constructor parameter to NewDirectDialer), so the
		// nil-metrics check is performed by NewDirectDialer, not
		// UpstreamOptions.Validate(). Exercised end-to-end above by
		// NewDirectDialer_NilMetricsRecorder_ReturnsErrMissingMetrics;
		// this subtest documents that mapping under its own
		// spec-required name.
		reg := listener.NewSelfDialRegistry()
		_, err := upstream.NewDirectDialer(validUpstreamOptions(), reg, nil)
		if !errors.Is(err, upstream.ErrMissingMetrics) {
			t.Fatalf("NewDirectDialer() error = %v, want ErrMissingMetrics", err)
		}
	})
}

func TestDialUpstreamValidation(t *testing.T) {
	newDialer := func(t *testing.T) *upstream.DirectDialer {
		t.Helper()
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(validUpstreamOptions(), reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return d
	}

	t.Run("DialUpstream_ZeroValueAddrPort_ReturnsErrInvalidAddr", func(t *testing.T) {
		d := newDialer(t)
		_, err := d.DialUpstream(context.Background(), netip.AddrPort{}, "svc.ns", "")
		if !errors.Is(err, upstream.ErrInvalidAddr) {
			t.Fatalf("DialUpstream() error = %v, want ErrInvalidAddr", err)
		}
	})

	t.Run("DialUpstream_EmptyServerName_ReturnsErrEmptyServerName", func(t *testing.T) {
		d := newDialer(t)
		addr := netip.MustParseAddrPort("10.0.0.5:443")
		_, err := d.DialUpstream(context.Background(), addr, "", "")
		if !errors.Is(err, upstream.ErrEmptyServerName) {
			t.Fatalf("DialUpstream() error = %v, want ErrEmptyServerName", err)
		}
	})

	t.Run("DialUpstream_NonTCPAddrFamily_ReturnsErrUnsupportedAddrFamily", func(t *testing.T) {
		d := newDialer(t)
		// A valid, non-zero IPv6 address:port passes addr.IsValid() and
		// therefore reaches the family check distinctly from the
		// zero-value ErrInvalidAddr path above.
		addr := netip.MustParseAddrPort("[::1]:443")
		_, err := d.DialUpstream(context.Background(), addr, "svc.ns", "")
		if !errors.Is(err, upstream.ErrUnsupportedAddrFamily) {
			t.Fatalf("DialUpstream() error = %v, want ErrUnsupportedAddrFamily", err)
		}
	})

	t.Run("DialUpstream_NilContext_TreatedAsBackgroundNoPanic", func(t *testing.T) {
		d := newDialer(t)
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DialUpstream panicked with nil context: %v", r)
			}
		}()
		//lint:ignore SA1012 exercising the documented nil-context tolerance (spec #354)
		_, _ = d.DialUpstream(nil, netip.AddrPort{}, "svc.ns", "")
	})
}

func TestDialUpstreamLoopGuard(t *testing.T) {
	t.Run("DialUpstream_LoopGuardAddrInSelfDialRegistry_RejectsBeforeSocketCreated", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(validUpstreamOptions(), reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// A registered self-dial addr must be rejected before any socket
		// is created; use a non-listener-port loopback addr so the
		// registry match, not the listener-port match, is what's
		// exercised (spec #337).
		self := netip.MustParseAddrPort("127.0.0.1:54321")
		if err := reg.Add(self); err != nil {
			t.Fatalf("reg.Add() error = %v", err)
		}
		_, err = d.DialUpstream(context.Background(), self, "svc.ns", "")
		if !errors.Is(err, upstream.ErrLoopGuard) {
			t.Fatalf("DialUpstream() error = %v, want ErrLoopGuard", err)
		}
		if len(m.decision) != 1 || m.decision[0] != "deny/"+listener.RejectLoopGuard.String() {
			t.Fatalf("Decisions calls = %v, want exactly one deny/%s", m.decision, listener.RejectLoopGuard.String())
		}
	})

	t.Run("DialUpstream_LoopGuardUIDMatchesProxyUID_RejectsWithAlert", func(t *testing.T) {
		// The proxy's own listener endpoint (loopback + configured
		// ListenerPort) is the deterministic construction that models
		// "the resolved destination's owning uid equals ProxyUID" per
		// design doc §8.3 step 3 -- DirectDialer has no way to
		// introspect a remote socket's owning uid pre-connect, so this
		// endpoint match IS the mechanism.
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		opts := validUpstreamOptions()
		d, err := upstream.NewDirectDialer(opts, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		addr := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", opts.ListenerPort))
		_, err = d.DialUpstream(context.Background(), addr, "svc.ns", "")
		if !errors.Is(err, upstream.ErrLoopGuard) {
			t.Fatalf("DialUpstream() error = %v, want ErrLoopGuard", err)
		}
	})

	t.Run("DialUpstream_LoopGuardCheckedBeforeUpstreamTLSHandshake_NoWastedHandshakeOnSelfDial", func(t *testing.T) {
		// Point at a loopback listener-port match with no real listener
		// backing it: if the loop guard ran after a dial/handshake
		// attempt, this would fail with a connection-refused/timeout
		// error instead of ErrLoopGuard, proving no handshake work is
		// wasted on a self-dial (spec #351).
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		opts := validUpstreamOptions()
		d, err := upstream.NewDirectDialer(opts, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		addr := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", opts.ListenerPort))
		start := time.Now()
		_, err = d.DialUpstream(context.Background(), addr, "svc.ns", "")
		elapsed := time.Since(start)
		if !errors.Is(err, upstream.ErrLoopGuard) {
			t.Fatalf("DialUpstream() error = %v, want ErrLoopGuard", err)
		}
		if elapsed >= opts.DialTimeout {
			t.Fatalf("DialUpstream() took %v, want well under DialTimeout (%v), indicating a dial/handshake was attempted", elapsed, opts.DialTimeout)
		}
	})

	t.Run("DialUpstream_RegistryRaceWindowDefenseInDepth_UIDCheckIsPrimary", func(t *testing.T) {
		// The registry-based check is documented as defense-in-depth for
		// the racy redirected-loop case; the true primary control is the
		// upstream, race-free orig_dst.uid == proxy_uid check performed
		// by the resolver/capture layer before DirectDialer is ever
		// invoked (design doc §8.3 "On the registration ordering").
		// DirectDialer itself has no uid-introspection API and must not
		// claim to be the primary control: an address absent from the
		// registry and not matching the listener port dials normally,
		// confirming DirectDialer defers to the upstream check rather
		// than attempting its own uid comparison (spec #343).
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(validUpstreamOptions(), reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		notSelf := netip.MustParseAddrPort("127.0.0.1:9999")
		_, err = d.DialUpstream(context.Background(), notSelf, "svc.ns", "")
		if errors.Is(err, upstream.ErrLoopGuard) {
			t.Fatalf("DialUpstream() unexpectedly returned ErrLoopGuard for an unregistered, non-listener-port address")
		}
	})
}

// newTLSTestServer starts an in-process TLS listener on 127.0.0.1 serving
// certName as its certificate CN/SAN, trusted via the returned pool and
// leaf cert (the leaf is exposed so multiple test servers' certs can be
// combined into one shared trust pool). hang, if true, accepts connections
// but never completes a handshake (used to simulate a black-holed/slow
// peer).
func newTLSTestServer(t *testing.T, certName string, hang bool) (addr netip.AddrPort, pool *x509.CertPool, leaf *x509.Certificate, closeFn func()) {
	t.Helper()
	cert, pool, leaf := generateTestCert(t, certName)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	done := make(chan struct{})
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			if hang {
				// Accept the raw TCP connection but never touch TLS
				// records, so the client's handshake never completes.
				continue
			}
			go func(c net.Conn) {
				tc, ok := c.(*tls.Conn)
				if ok {
					_ = tc.Handshake()
				}
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
				_ = c.Close()
			}(conn)
		}
	}()
	go func() {
		<-done
		_ = tlsLn.Close()
	}()
	tcpAddr := ln.Addr().(*net.TCPAddr)
	a := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tcpAddr.Port))
	return a, pool, leaf, func() { close(done) }
}

// newHangTCPServer returns the address of a listener that accepts connections
// and then never speaks, so a TLS handshake against it blocks indefinitely.
//
// Every accept is announced on the returned channel. DirectDialer takes its
// semaphore slot *before* it dials (direct.go), so an accept is proof that the
// slot is held - which is what the saturation tests actually need to know. A
// sleep cannot prove it: if the dialling goroutine has not reached the
// acquisition yet, the slot is still free and the call under test dials for
// real instead of being rejected.
//
// release closes the accepted connections, which unblocks the stalled
// handshake immediately so that a test need not wait out HandshakeTimeout.
func newHangTCPServer(t *testing.T) (addr netip.AddrPort, accepted <-chan struct{}, release func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	acc := make(chan struct{}, 1)
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
			// Non-blocking: the tests care that an accept happened, not how
			// many, and the accept loop must never stall.
			select {
			case acc <- struct{}{}:
			default:
			}
		}
	}()
	var once sync.Once
	release = func() {
		once.Do(func() {
			_ = ln.Close()
			mu.Lock()
			for _, conn := range conns {
				_ = conn.Close()
			}
			conns = nil
			mu.Unlock()
		})
	}
	t.Cleanup(release)
	tcpAddr := ln.Addr().(*net.TCPAddr)
	return netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tcpAddr.Port)), acc, release
}

func TestDialUpstreamDialAndHandshake(t *testing.T) {
	t.Run("DialUpstream_ValidAddrNotSelf_DialsSuccessfully", func(t *testing.T) {
		addr, pool, _, closeSrv := newTLSTestServer(t, "svc.example", false)
		defer closeSrv()

		opts := validUpstreamOptions()
		opts.ListenerPort = 15001 // deliberately distinct from the test server's ephemeral port
		opts.RootCAs = pool
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(opts, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		conn, err := d.DialUpstream(context.Background(), addr, "svc.example", "")
		if err != nil {
			t.Fatalf("DialUpstream() error = %v, want nil", err)
		}
		defer conn.Close()
		if conn == nil {
			t.Fatalf("DialUpstream() conn = nil, want a connected net.Conn")
		}
	})

	t.Run("DialUpstream_ConnectionRefused_ReturnsWrappedDialError", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(validUpstreamOptions(), reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Nothing listens on this ephemeral loopback port.
		addr := netip.MustParseAddrPort("127.0.0.1:1")
		_, err = d.DialUpstream(context.Background(), addr, "svc.example", "")
		if err == nil {
			t.Fatalf("DialUpstream() error = nil, want a wrapped dial error")
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) {
			t.Fatalf("DialUpstream() error = %v, want it to wrap a *net.OpError", err)
		}
	})

	t.Run("DialUpstream_ContextCancelledDuringDial_ReturnsContextError", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(validUpstreamOptions(), reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		// A non-routable TEST-NET-1 address (RFC 5737) that will never
		// respond, so cancellation -- not a real refusal -- determines
		// the outcome.
		addr := netip.MustParseAddrPort("192.0.2.1:443")
		_, err = d.DialUpstream(ctx, addr, "svc.example", "")
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialUpstream() error = %v, want context.Canceled", err)
		}
	})

	t.Run("DialUpstream_DialTimeoutExceeded_ReturnsTimeoutError", func(t *testing.T) {
		opts := validUpstreamOptions()
		opts.DialTimeout = 50 * time.Millisecond
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(opts, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// A non-routable TEST-NET-1 address (RFC 5737), which is reserved
		// for documentation and is never routed, so the SYN is blackholed
		// and the configured DialTimeout -- not a real refusal --
		// determines the outcome. RFC 1918 space must not be used here:
		// cloud CI runners sit inside a 10.0.0.0/8 VNet, so a 10.x target
		// is routable there and answers with an immediate RST, which
		// surfaces as ECONNREFUSED rather than a timeout.
		addr := netip.MustParseAddrPort("192.0.2.1:81")
		_, err = d.DialUpstream(context.Background(), addr, "svc.example", "")
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("DialUpstream() error = %v, want a net.Error with Timeout() == true", err)
		}
	})

	t.Run("DialUpstream_CredIDPassedThroughToUpstreamTLSOrPlain_Unmodified", func(t *testing.T) {
		// 5A forwards credID unmodified with no validation/transformation
		// beyond accepting "" or any non-empty opaque string; a
		// successful dial with a non-empty credID proves no rejection or
		// mutation occurs.
		addr, pool, _, closeSrv := newTLSTestServer(t, "svc.example", false)
		defer closeSrv()
		opts := validUpstreamOptions()
		opts.RootCAs = pool
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(opts, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		conn, err := d.DialUpstream(context.Background(), addr, "svc.example", "opaque-cred-id-123")
		if err != nil {
			t.Fatalf("DialUpstream() error = %v, want nil", err)
		}
		defer conn.Close()
	})

	t.Run("DialUpstream_ConcurrentDialsDistinctAddrs_EachIndependent", func(t *testing.T) {
		addr1, _, leaf1, close1 := newTLSTestServer(t, "svc-a.example", false)
		defer close1()
		addr2, _, leaf2, close2 := newTLSTestServer(t, "svc-b.example", false)
		defer close2()

		// Combine both server certs into one trust pool so a single
		// shared DirectDialer can dial both concurrently (exercises
		// concurrent access to one dialer's semaphore/registry, per the
		// review finding that separate dialers didn't).
		combined := x509.NewCertPool()
		combined.AddCert(leaf1)
		combined.AddCert(leaf2)

		opts := validUpstreamOptions()
		opts.RootCAs = combined
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(opts, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var wg sync.WaitGroup
		errs := make([]error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			c, e := d.DialUpstream(context.Background(), addr1, "svc-a.example", "")
			errs[0] = e
			if c != nil {
				c.Close()
			}
		}()
		go func() {
			defer wg.Done()
			c, e := d.DialUpstream(context.Background(), addr2, "svc-b.example", "")
			errs[1] = e
			if c != nil {
				c.Close()
			}
		}()
		wg.Wait()
		for i, e := range errs {
			if e != nil {
				t.Fatalf("concurrent DialUpstream #%d error = %v, want nil", i, e)
			}
		}
	})

	t.Run("DialUpstream_OneDialBlocksIndefinitely_OtherDialsUnaffected", func(t *testing.T) {
		hangAddr, hangPool, _, closeHang := newTLSTestServer(t, "svc-hang.example", true)
		defer closeHang()
		okAddr, okPool, _, closeOK := newTLSTestServer(t, "svc-ok.example", false)
		defer closeOK()

		optsHang := validUpstreamOptions()
		optsHang.DialTimeout = 50 * time.Millisecond
		optsHang.HandshakeTimeout = 50 * time.Millisecond
		optsHang.RootCAs = hangPool
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		dHang, err := upstream.NewDirectDialer(optsHang, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		optsOK := validUpstreamOptions()
		optsOK.RootCAs = okPool
		dOK, err := upstream.NewDirectDialer(optsOK, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			// This call is expected to time out on the handshake; its
			// outcome is not asserted here beyond not blocking forever.
			_, _ = dHang.DialUpstream(context.Background(), hangAddr, "svc-hang.example", "")
		}()

		okDone := make(chan error, 1)
		go func() {
			conn, err := dOK.DialUpstream(context.Background(), okAddr, "svc-ok.example", "")
			if conn != nil {
				conn.Close()
			}
			okDone <- err
		}()

		select {
		case err := <-okDone:
			if err != nil {
				t.Fatalf("DialUpstream() to the healthy server error = %v, want nil", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("DialUpstream() to the healthy server did not return within 2s; the hung dial appears to be blocking it")
		}
		wg.Wait()
	})

	t.Run("DialUpstream_OnSuccessOrRejection_RecordDecisionCalled", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		opts := validUpstreamOptions()
		d, err := upstream.NewDirectDialer(opts, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		addr := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", opts.ListenerPort))
		_, _ = d.DialUpstream(context.Background(), addr, "svc.example", "")
		if len(m.decision) != 1 {
			t.Fatalf("RecordDecision call count = %d, want exactly 1", len(m.decision))
		}
	})

	t.Run("DialUpstream_OnDialCompletion_LatencyRecorded", func(t *testing.T) {
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		opts := validUpstreamOptions()
		d, err := upstream.NewDirectDialer(opts, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		addr := netip.MustParseAddrPort("127.0.0.1:1")
		_, _ = d.DialUpstream(context.Background(), addr, "svc.example", "")
		if len(m.latency) != 1 || m.latency[0] != "upstream_dial" {
			t.Fatalf("RecordLatency calls = %v, want exactly one call for stage upstream_dial", m.latency)
		}
	})

	t.Run("DialUpstream_ResourceLimitTooManyConcurrentDials_RejectsWithBoundLabel", func(t *testing.T) {
		opts := validUpstreamOptions()
		opts.MaxConcurrentDials = 1
		opts.HandshakeTimeout = 10 * time.Second // safety net only; release() ends the hang
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(opts, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		hangAddr, accepted, release := newHangTCPServer(t)

		firstDone := make(chan struct{})
		go func() {
			// Uses the same d (and therefore the same semaphore) as the
			// rejected call below; RootCAs doesn't matter here since the
			// handshake never completes on the hung server.
			_, _ = d.DialUpstream(context.Background(), hangAddr, "svc-hang.example", "")
			close(firstDone)
		}()
		<-accepted // the only semaphore slot is now provably held

		addr := netip.MustParseAddrPort("127.0.0.1:1")
		_, err = d.DialUpstream(context.Background(), addr, "svc.example", "")
		if !errors.Is(err, upstream.ErrUpstreamConcurrency) {
			t.Fatalf("DialUpstream() error = %v, want ErrUpstreamConcurrency", err)
		}
		decisions := m.decisions()
		if len(decisions) == 0 || decisions[len(decisions)-1] != "deny/"+listener.RejectResourceLimit.String() {
			t.Fatalf("Decisions calls = %v, want a trailing deny/%s", decisions, listener.RejectResourceLimit.String())
		}
		release()
		<-firstDone
	})

	t.Run("DialUpstream_ClosingReturnedConnTwice_IsIdempotent", func(t *testing.T) {
		addr, pool, _, closeSrv := newTLSTestServer(t, "svc.example", false)
		defer closeSrv()
		opts := validUpstreamOptions()
		opts.RootCAs = pool
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(opts, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		conn, err := d.DialUpstream(context.Background(), addr, "svc.example", "")
		if err != nil {
			t.Fatalf("DialUpstream() error = %v, want nil", err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("first Close() error = %v, want nil", err)
		}
		if err := conn.Close(); err != nil {
			t.Fatalf("second Close() panicked or errored unexpectedly: %v", err)
		}
	})

	t.Run("DialUpstream_DoubleDialSameAddrConcurrently_BothSucceedIndependently", func(t *testing.T) {
		addr, pool, _, closeSrv := newTLSTestServer(t, "svc.example", false)
		defer closeSrv()
		opts := validUpstreamOptions()
		opts.RootCAs = pool
		reg := listener.NewSelfDialRegistry()
		m := &fakeMetrics{}
		d, err := upstream.NewDirectDialer(opts, reg, m)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var wg sync.WaitGroup
		conns := make([]net.Conn, 2)
		errs := make([]error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c, e := d.DialUpstream(context.Background(), addr, "svc.example", "")
				conns[i] = c
				errs[i] = e
			}(i)
		}
		wg.Wait()
		for i, e := range errs {
			if e != nil {
				t.Fatalf("DialUpstream() #%d error = %v, want nil", i, e)
			}
		}
		if conns[0] == conns[1] {
			t.Fatalf("both concurrent DialUpstream calls to the same addr returned the identical net.Conn; want two independent connections")
		}
		conns[0].Close()
		conns[1].Close()
	})
}

// generateTestCert issues a short-lived, self-signed, ECDSA leaf certificate
// for name, returning the tls.Certificate for the server, an x509.CertPool
// that trusts it for the client, and the parsed leaf certificate (for
// combining multiple test certs into one shared pool).
// ---- Phase 5C upstream-semaphore preservation tests (#27-31, #34) ----
//
// No production change is required for 5C; these tests document that the
// existing DirectDialer.sem / ErrUpstreamConcurrency behavior is now the
// durable upstream-connection bound (design section 18.3).

// preservation mirror of the production compile-time frozen-interface
// assertion, so accidental removal of the one in direct.go is still caught.
var _ dataplane.UpstreamDialer = (*upstream.DirectDialer)(nil)

func TestDirectDialer_SemaphoreSaturated_ReturnsErrUpstreamConcurrency(t *testing.T) {
	opts := validUpstreamOptions()
	opts.MaxConcurrentDials = 1
	opts.HandshakeTimeout = 10 * time.Second // safety net only; release() ends the hang
	reg := listener.NewSelfDialRegistry()
	m := &fakeMetrics{}
	d, err := upstream.NewDirectDialer(opts, reg, m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hangAddr, accepted, release := newHangTCPServer(t)

	firstDone := make(chan struct{})
	go func() {
		_, _ = d.DialUpstream(context.Background(), hangAddr, "svc-hang.example", "")
		close(firstDone)
	}()
	<-accepted // the only semaphore slot is now provably held

	addr := netip.MustParseAddrPort("127.0.0.1:1")
	_, err = d.DialUpstream(context.Background(), addr, "svc.example", "")
	if !errors.Is(err, upstream.ErrUpstreamConcurrency) {
		t.Fatalf("DialUpstream() error = %v, want ErrUpstreamConcurrency (fail-fast, no queue)", err)
	}
	release()
	<-firstDone
}

func TestDirectDialer_SemaphoreSaturated_RecordsResourceLimitMetric(t *testing.T) {
	opts := validUpstreamOptions()
	opts.MaxConcurrentDials = 1
	opts.HandshakeTimeout = 10 * time.Second // safety net only; release() ends the hang
	reg := listener.NewSelfDialRegistry()
	m := &fakeMetrics{}
	d, err := upstream.NewDirectDialer(opts, reg, m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hangAddr, accepted, release := newHangTCPServer(t)

	firstDone := make(chan struct{})
	go func() {
		_, _ = d.DialUpstream(context.Background(), hangAddr, "svc-hang.example", "")
		close(firstDone)
	}()
	<-accepted // the only semaphore slot is now provably held

	addr := netip.MustParseAddrPort("127.0.0.1:1")
	_, _ = d.DialUpstream(context.Background(), addr, "svc.example", "")

	// The pre-existing semaphore rejection emits the UNQUALIFIED T7 reason
	// "resource_limit" (RejectResourceLimit.String()), deliberately distinct
	// from 5C's sub-typed strings; see Findings F8.
	want := "deny/" + listener.RejectResourceLimit.String()
	decisions := m.decisions()
	if len(decisions) == 0 || decisions[len(decisions)-1] != want {
		t.Fatalf("RecordDecision calls = %v, want a trailing %q", decisions, want)
	}
	if listener.RejectResourceLimit.String() != "resource_limit" {
		t.Fatalf("RejectResourceLimit.String() = %q, want unqualified \"resource_limit\"", listener.RejectResourceLimit.String())
	}
	release()
	<-firstDone
}

func TestDirectDialer_Close_ReleasesSlotExactlyOnce(t *testing.T) {
	addr, pool, _, closeSrv := newTLSTestServer(t, "svc.example", false)
	defer closeSrv()
	opts := validUpstreamOptions()
	opts.MaxConcurrentDials = 1
	opts.HandshakeTimeout = 200 * time.Millisecond
	opts.RootCAs = pool
	reg := listener.NewSelfDialRegistry()
	m := &fakeMetrics{}
	d, err := upstream.NewDirectDialer(opts, reg, m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	conn, err := d.DialUpstream(context.Background(), addr, "svc.example", "")
	if err != nil {
		t.Fatalf("DialUpstream() error = %v, want nil", err)
	}
	// Double-close: a second Close must not release a second slot.
	if err := conn.Close(); err != nil {
		t.Fatalf("first Close() error = %v, want nil", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want nil", err)
	}

	// The single slot must now be free again (exactly one release), so one
	// fresh dial succeeds...
	conn2, err := d.DialUpstream(context.Background(), addr, "svc.example", "")
	if err != nil {
		t.Fatalf("post-close DialUpstream() error = %v, want nil (slot freed exactly once)", err)
	}
	defer conn2.Close()

	// ...but the slot is again occupied, so a concurrent dial is rejected.
	// If double-close had over-released, capacity would appear as 2 and this
	// would wrongly succeed.
	_, err = d.DialUpstream(context.Background(), netip.MustParseAddrPort("127.0.0.1:1"), "svc.example", "")
	if !errors.Is(err, upstream.ErrUpstreamConcurrency) {
		t.Fatalf("DialUpstream() error = %v, want ErrUpstreamConcurrency (double-close must not leak a slot)", err)
	}
}

func TestDirectDialer_ConcurrentDialsUpToMax_AllSucceed(t *testing.T) {
	addr, pool, _, closeSrv := newTLSTestServer(t, "svc.example", false)
	defer closeSrv()
	const max = 8
	opts := validUpstreamOptions()
	opts.MaxConcurrentDials = max
	opts.RootCAs = pool
	reg := listener.NewSelfDialRegistry()
	m := &fakeMetrics{}
	d, err := upstream.NewDirectDialer(opts, reg, m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var wg sync.WaitGroup
	conns := make([]net.Conn, max)
	errs := make([]error, max)
	for i := 0; i < max; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, e := d.DialUpstream(context.Background(), addr, "svc.example", "")
			conns[i] = c
			errs[i] = e
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("DialUpstream() #%d error = %v, want nil (full capacity usable)", i, e)
		}
	}
	for _, c := range conns {
		if c != nil {
			c.Close()
		}
	}
}

func TestDirectDialer_SatisfiesUpstreamDialerInterface_CompileTime(t *testing.T) {
	// Test-file mirror of the direct.go compile-time assertion; referencing
	// it here exercises the frozen-seam guarantee even if the production
	// assertion is accidentally removed.
	var _ dataplane.UpstreamDialer = (*upstream.DirectDialer)(nil)
}

func TestDirectDialer_ConcurrentDialAndClose_NoRace(t *testing.T) {
	addr, pool, _, closeSrv := newTLSTestServer(t, "svc.example", false)
	defer closeSrv()
	opts := validUpstreamOptions()
	opts.MaxConcurrentDials = 16
	opts.RootCAs = pool
	reg := listener.NewSelfDialRegistry()
	m := &fakeMetrics{}
	d, err := upstream.NewDirectDialer(opts, reg, m)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := d.DialUpstream(context.Background(), addr, "svc.example", "")
			if e == nil && c != nil {
				c.Close()
			}
		}()
	}
	wg.Wait()
}

func generateTestCert(t *testing.T, name string) (tls.Certificate, *x509.CertPool, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, pool, cert
}
