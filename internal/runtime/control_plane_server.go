// Package runtime — control_plane_server.go implements the S6 §5 control-plane
// HTTP server exposing /metrics, /healthz and /readyz on the pod IP, port 15020.
//
// Per ADR-S6-04 the server binds the pod IP, never loopback: the agent shares
// the pod network namespace and S1's rules deliberately exclude loopback, so a
// 127.0.0.1 bind is MORE reachable by the agent, not less. Loopback bind
// addresses are therefore refused at both construction and startup. The
// endpoints are read-only and expose no secret material (INV-5): only closed
// enum reasons and Prometheus exposition ever reach a response body.
package runtime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Port15020 is the fixed control-plane port for /metrics, /healthz and /readyz
// (S6 §5, F14). It is separate from the data plane.
const Port15020 = 15020

// PodIPEnv is the downward-API environment variable carrying the pod IP. It is
// the wire-time source for an empty ControlPlane.Address (#80).
const PodIPEnv = "POD_IP"

// reasonAuditUnavailable is the degraded readiness reason surfaced when the
// emergency channel has cleared readiness because audit is terminally
// unavailable (§3.1). It is a fixed closed value — never agent-controlled.
const reasonAuditUnavailable = "audit_unavailable"

var (
	// ErrNilProbeSource is returned when a nil ProbeSource is supplied; the
	// server cannot answer /healthz or /readyz without one.
	ErrNilProbeSource = errors.New("runtime: nil probe source")
	// ErrEmptyBindAddress is returned for an empty bind address rather than
	// silently defaulting to loopback.
	ErrEmptyBindAddress = errors.New("runtime: empty control-plane bind address")
	// ErrLoopbackBindAddress is returned when the configured bind address is a
	// loopback address; ADR-S6-04 forbids loopback for the control plane.
	ErrLoopbackBindAddress = errors.New("runtime: control-plane bind address must not be loopback (ADR-S6-04)")
	// ErrAlreadyStarted is returned when Start is called on a server that is
	// already serving; a second Start would orphan the first listener/server so
	// Shutdown could no longer stop it.
	ErrAlreadyStarted = errors.New("runtime: control-plane server already started")
)

// degradedReasons is the closed set of not-ready reasons the control plane will
// echo in a /readyz body. Any reason outside this set is collapsed to the
// generic "not ready" so a response body can never carry unexpected (and thus
// potentially sensitive) text — defense-in-depth for INV-5.
var degradedReasons = map[string]struct{}{
	"starting":             {},
	"shutting down":        {},
	reasonAuditUnavailable: {},
}

// ProbeSource is the seam the ControlPlaneServer reads for readiness and
// liveness plus the current degraded reason. It reflects BOTH the
// orchestrator's ready/live state AND the emergency-channel readiness (audit
// terminally unavailable ⇒ not ready). *Orchestrator satisfies it directly;
// ProbeAggregator layers the emergency-channel signal on top.
type ProbeSource interface {
	// Ready reports readiness and the degraded reason (e.g. "starting",
	// "shutting down", "audit_unavailable").
	Ready() ProbeStatus
	// Live reports liveness.
	Live() ProbeStatus
}

// ControlPlaneServer serves the read-only /metrics, /healthz and /readyz
// endpoints on the pod IP:15020.
type ControlPlaneServer struct {
	bindAddr string
	port     int
	gatherer prometheus.Gatherer
	probes   ProbeSource

	mu                sync.Mutex
	srv               *http.Server
	started           bool
	shutdownRequested bool
	shuttingDown      bool
	shutdownDone      bool
	shutdownErr       error
	shutdownCh        chan struct{}
	serveErr          error
}

// NewControlPlaneServerFromConfig performs wire-time address reconciliation
// (design "Address reconciliation (Findings F3)", ADR-S6-04) and constructs the
// control-plane server. It is the SOLE owner of the loopback-forbidden
// invariant: Config.Validate deliberately does not re-check it. An empty
// ControlPlane.Address resolves to the POD_IP downward-API env (#80); a zero
// ControlPlane.Port defaults to Port15020, a non-zero port overrides it
// (#79/#82); a loopback host is rejected fail-closed via NewControlPlaneServer
// (#81). An empty address with no POD_IP is rejected (ErrEmptyBindAddress).
func NewControlPlaneServerFromConfig(cp config.ControlPlaneConfig, reg prometheus.Gatherer, probes ProbeSource) (*ControlPlaneServer, error) {
	host := strings.TrimSpace(cp.Address)
	if host == "" {
		host = strings.TrimSpace(os.Getenv(PodIPEnv))
		if host == "" {
			return nil, ErrEmptyBindAddress
		}
	}
	port := cp.Port
	if port == 0 {
		port = Port15020
	}
	return NewControlPlaneServer(host, port, reg, probes)
}

// NewControlPlaneServer constructs a control-plane server bound to bindAddr:port
// (canonically the pod IP and Port15020), exposing metrics gathered from reg. A
// nil ProbeSource, an empty bind address, or a loopback bind address
// (`127.0.0.1`/`::1`/`localhost`) each return an error (ADR-S6-04, §5).
func NewControlPlaneServer(bindAddr string, port int, reg prometheus.Gatherer, probes ProbeSource) (*ControlPlaneServer, error) {
	if probes == nil {
		return nil, ErrNilProbeSource
	}
	if err := validateBindAddr(bindAddr); err != nil {
		return nil, err
	}
	return &ControlPlaneServer{
		bindAddr:   bindAddr,
		port:       port,
		gatherer:   reg,
		probes:     probes,
		shutdownCh: make(chan struct{}),
	}, nil
}

// Addr is the TCP address the server binds, host:port.
func (s *ControlPlaneServer) Addr() string {
	return net.JoinHostPort(s.bindAddr, strconv.Itoa(s.port))
}

// Start binds the control-plane socket and begins serving. It re-validates the
// bind address first and refuses to serve on a loopback address (ADR-S6-04),
// complementing the constructor-level rejection. Binding happens synchronously
// so a bind failure is returned to the caller; serving then runs in the
// background until Shutdown.
func (s *ControlPlaneServer) Start(ctx context.Context) error {
	if err := validateBindAddr(s.bindAddr); err != nil {
		return err
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return ErrAlreadyStarted
	}
	if s.shutdownRequested {
		// Shutdown was already requested; honor terminal intent and do not
		// bind or serve.
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	ln, err := net.Listen("tcp", s.Addr())
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.started {
		// Lost a race with a concurrent Start; release this listener so we do
		// not orphan a socket.
		s.mu.Unlock()
		_ = ln.Close()
		return ErrAlreadyStarted
	}
	if s.shutdownRequested {
		// Shutdown was requested during the bind window (TOCTOU): honor it by
		// closing the freshly-bound listener and never serving, so the
		// shutdown request is not lost.
		s.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	s.srv = &http.Server{Handler: s.Handler()}
	s.started = true
	srv := s.srv
	s.mu.Unlock()

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Serve failed for a reason other than a graceful shutdown; record
			// it so it is not silently discarded.
			s.mu.Lock()
			s.serveErr = err
			s.mu.Unlock()
		}
	}()
	return nil
}

// ServeErr returns the error, if any, from the background Serve loop. It is nil
// while serving normally and after a graceful Shutdown (http.ErrServerClosed is
// not reported as an error).
func (s *ControlPlaneServer) ServeErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serveErr
}

// Shutdown gracefully stops serving. Shutdown intent is terminal: it latches a
// shutdownRequested flag under the lock so a concurrent or subsequent Start
// (even one mid-bind) will not begin serving, closing the TOCTOU window where a
// Shutdown could be lost. The lock is released during the blocking
// http.Server.Shutdown; a concurrent second caller waits on shutdownCh and then
// observes the final shutdownErr, never a stale value and never blocked by a
// lock held across I/O. A concurrent second caller also honors its own context
// cancellation while waiting. It is idempotent.
func (s *ControlPlaneServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.shutdownDone {
		err := s.shutdownErr
		s.mu.Unlock()
		return err
	}
	if s.shuttingDown {
		// Another goroutine owns the shutdown; wait for it to finish (or for
		// this caller's own context to cancel), then return the result.
		s.mu.Unlock()
		select {
		case <-s.shutdownCh:
		case <-ctx.Done():
			return ctx.Err()
		}
		s.mu.Lock()
		err := s.shutdownErr
		s.mu.Unlock()
		return err
	}
	// This goroutine owns the shutdown. Latch intent synchronously so an
	// in-flight/future Start cannot serve, then perform the blocking stop
	// WITHOUT holding the lock.
	s.shutdownRequested = true
	s.shuttingDown = true
	srv := s.srv
	s.mu.Unlock()

	var err error
	if srv != nil {
		err = srv.Shutdown(ctx)
	}

	s.mu.Lock()
	s.shutdownErr = err
	s.shutdownDone = true
	close(s.shutdownCh)
	s.mu.Unlock()
	return err
}

// Handler builds the read-only control-plane mux: /metrics exposition plus the
// /healthz and /readyz probes. It is exported so handlers can be exercised via
// httptest without binding a socket (ADR-S6-04 forbids a loopback bind).
func (s *ControlPlaneServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", s.metricsHandler())
	mux.Handle("/healthz", s.healthzHandler())
	mux.Handle("/readyz", s.readyzHandler())
	return mux
}

// metricsHandler serves GET-only Prometheus exposition from the gatherer. Any
// non-GET method is rejected 405 — the surface is strictly read-only.
func (s *ControlPlaneServer) metricsHandler() http.Handler {
	exposition := promhttp.HandlerFor(s.gatherer, promhttp.HandlerOpts{})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		exposition.ServeHTTP(w, r)
	})
}

// healthzHandler serves GET-only liveness: 200 while the process is live, 503
// once liveness is cleared by a fatal startup/serve failure. It exposes no
// secret material (INV-5).
func (s *ControlPlaneServer) healthzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.probes.Live().Live {
			writeProbe(w, http.StatusOK, "ok")
			return
		}
		writeProbe(w, http.StatusServiceUnavailable, "not live")
	})
}

// writeProbe writes a fixed-body probe response. The body is always a closed
// constant string — never agent-controlled — so no secret can leak (INV-5).
func writeProbe(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body + "\n"))
}

// readyzHandler serves GET-only readiness: 200 when the ProbeSource reports
// ready, 503 otherwise. The body reflects the current degraded reason
// ("starting", "shutting down", "audit_unavailable") — a closed enum sourced
// from the orchestrator/emergency channel, never agent input (INV-5).
func (s *ControlPlaneServer) readyzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		st := s.probes.Ready()
		if st.Ready {
			writeProbe(w, http.StatusOK, "ready")
			return
		}
		writeProbe(w, http.StatusServiceUnavailable, degradedReason(st.Reason))
	})
}

// degradedReason returns a non-empty degraded reason drawn from the closed
// degradedReasons set. An empty or unrecognized reason collapses to the generic
// "not ready" so the body never echoes unexpected text (INV-5 defense-in-depth).
func degradedReason(reason string) string {
	if _, ok := degradedReasons[reason]; ok {
		return reason
	}
	return "not ready"
}

// ProbeAggregator adapts an *Orchestrator (or any ProbeSource) into a
// ProbeSource that also folds in the emergency-channel readiness signal. It
// satisfies audit.ReadinessSink so the EmergencyChannel can clear readiness on
// a terminal audit failure and restore it on recovery (§3.1) — the flip is not
// latched. When audit is unavailable, Ready reports not-ready with the
// "audit_unavailable" degraded reason regardless of the base readiness.
type ProbeAggregator struct {
	base       ProbeSource
	auditReady atomic.Bool
}

// NewProbeAggregator wraps base, starting in the audit-available state.
func NewProbeAggregator(base ProbeSource) *ProbeAggregator {
	a := &ProbeAggregator{base: base}
	a.auditReady.Store(true)
	return a
}

// SetReady records the emergency-driven readiness: false on terminal audit
// failure, true on recovery. It satisfies audit.ReadinessSink.
func (a *ProbeAggregator) SetReady(ready bool) { a.auditReady.Store(ready) }

// Ready combines the base readiness with the emergency-channel signal: audit
// unavailability forces not-ready with an "audit_unavailable" reason. A nil
// base is treated as not-ready/not-live so a misconfigured aggregator fails
// closed rather than panicking.
func (a *ProbeAggregator) Ready() ProbeStatus {
	if a.base == nil {
		return ProbeStatus{Ready: false, Live: false, Reason: "not ready"}
	}
	st := a.base.Ready()
	if !a.auditReady.Load() {
		return ProbeStatus{Ready: false, Live: st.Live, Reason: reasonAuditUnavailable}
	}
	return st
}

// Live passes through the base liveness; audit availability does not affect it.
// A nil base fails closed (not live).
func (a *ProbeAggregator) Live() ProbeStatus {
	if a.base == nil {
		return ProbeStatus{Ready: false, Live: false}
	}
	return a.base.Live()
}

var _ ProbeSource = (*ProbeAggregator)(nil)
var _ audit.ReadinessSink = (*ProbeAggregator)(nil)

// validateBindAddr rejects an empty or loopback bind address. It is the single
// gate shared by the constructor and Start so the loopback refusal (ADR-S6-04)
// cannot be bypassed by either path.
func validateBindAddr(bindAddr string) error {
	if bindAddr == "" {
		return ErrEmptyBindAddress
	}
	if isLoopbackHost(bindAddr) {
		return ErrLoopbackBindAddress
	}
	return nil
}

// isLoopbackHost reports whether host is a loopback address or the "localhost"
// name. Both are forbidden for the control plane (ADR-S6-04).
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
