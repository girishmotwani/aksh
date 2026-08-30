package runtime

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
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/dataplane/requestpath"
	"github.com/girishmotwani/aksh/internal/dataplane/tlsterm"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

const testSNI = "test.example.com"

// fakeLeafSource returns a fixed leaf certificate and records the server names
// GetConfigForClient asks it to mint, so tests can assert SNI leaf selection.
type fakeLeafSource struct {
	mu        sync.Mutex
	requested []string
	cert      *tls.Certificate
	err       error
}

func (f *fakeLeafSource) CertificateFor(_ context.Context, serverName string) (*tls.Certificate, error) {
	f.mu.Lock()
	f.requested = append(f.requested, serverName)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.cert, nil
}

func (f *fakeLeafSource) requestedNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requested...)
}

// tlsDecision captures one bounded metrics decision for terminator accounting.
type tlsDecision struct {
	disposition, reason, identity string
	transport                     string
	fault                         bool
}

type fakeTLSMetrics struct {
	audit.NopMetricsRecorder
	mu         sync.Mutex
	decisions  []tlsDecision
	rejectClas []string
}

func (f *fakeTLSMetrics) Decisions(d pipeline.Disposition, r pipeline.DenyReason, tr audit.TransportKind, fault bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decisions = append(f.decisions, tlsDecision{
		disposition: d.String(),
		reason:      r.String(),
		transport:   tr.String(),
		fault:       fault,
	})
}

func (f *fakeTLSMetrics) TransportReject(class audit.RejectClass, _ audit.BoundName) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejectClas = append(f.rejectClas, class.String())
}

func (f *fakeTLSMetrics) rejectClasses() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.rejectClas...)
}

func (f *fakeTLSMetrics) allDecisions() []tlsDecision {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tlsDecision(nil), f.decisions...)
}

func (f *fakeTLSMetrics) handshakeFailures() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, d := range f.decisions {
		if d.disposition == "deny" && d.reason == "handshake_failed" {
			n++
		}
	}
	return n
}

// recordingNext observes the ConnContext it receives so the handler's TLS-field
// population and delegation order can be asserted.
type recordingNext struct {
	mu             sync.Mutex
	calls          int
	err            error
	sawALPN        string
	sawSNI         string
	sawProtocolTLS bool
	sawTerminated  bool
	original       net.Conn
}

func (n *recordingNext) Handle(_ context.Context, cc *listener.ConnContext) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls++
	n.sawALPN = cc.NegotiatedALPN
	n.sawSNI = cc.CandidateSNI
	n.sawProtocolTLS = cc.Protocol == listener.ProtocolTLS
	n.sawTerminated = cc.Downstream != n.original
	return n.err
}

func (n *recordingNext) callCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.calls
}

func newLeafCertificate(t *testing.T, serverName string) *tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: serverName},
		DNSNames:              []string{serverName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func newTestTerminator(t *testing.T, source dataplane.LeafSource, metrics audit.MetricsRecorder) *tlsterm.Terminator {
	t.Helper()
	opts := tlsterm.LeafOptions{
		CacheEntries: 16,
		CacheTTL:     time.Minute,
		LeafLifetime: time.Hour,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		MintRate:     1,
		MintBurst:    1,
	}
	term, err := tlsterm.NewTerminator(source, opts, metrics)
	if err != nil {
		t.Fatalf("new terminator: %v", err)
	}
	return term
}

// tcpPipe returns two ends of a live loopback TCP connection so a real TLS
// handshake can be driven deterministically without the race detector.
func tcpPipe(t *testing.T) (server net.Conn, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		accepted <- acceptResult{c, err}
	}()

	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	res := <-accepted
	if res.err != nil {
		t.Fatalf("accept: %v", res.err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = res.conn.Close()
	})
	return res.conn, client
}

func clientTLSConfig() *tls.Config {
	return clientTLSConfigFor(testSNI)
}

// clientTLSConfigFor builds a client config that offers serverName as the
// ClientHello SNI, so tests can drive non-canonical names through a real
// handshake.
func clientTLSConfigFor(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	}
}

func TestHandle_NilNext_ReturnsError(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	h := &tlsTerminatingConnHandler{Terminator: term, Next: nil}

	server, _ := tcpPipe(t)
	cc := &listener.ConnContext{Downstream: server}
	err := h.Handle(context.Background(), cc)
	if !errors.Is(err, errNilNext) {
		t.Fatalf("Handle err = %v, want errNilNext", err)
	}
	if len(source.requestedNames()) != 0 {
		t.Fatalf("nil Next must not attempt a TLS handshake")
	}
}

func TestHandle_NilTerminator_ReturnsError(t *testing.T) {
	next := &recordingNext{}
	h := &tlsTerminatingConnHandler{Terminator: nil, Next: next}

	server, _ := tcpPipe(t)
	cc := &listener.ConnContext{Downstream: server}
	err := h.Handle(context.Background(), cc)
	if !errors.Is(err, errNilTerminator) {
		t.Fatalf("Handle err = %v, want errNilTerminator", err)
	}
	if next.callCount() != 0 {
		t.Fatalf("nil Terminator must not delegate to the request path")
	}
}

func TestHandle_HandshakeSucceeds_DelegatesAfterTLSFieldsPopulated(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientDone := make(chan error, 1)
	go func() {
		tc := tls.Client(client, clientTLSConfig())
		clientDone <- tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	if next.callCount() != 1 {
		t.Fatalf("Next.Handle calls = %d, want 1", next.callCount())
	}
	if next.sawALPN != "http/1.1" {
		t.Fatalf("Next saw ALPN %q, want http/1.1 (TLS fields not populated before delegation)", next.sawALPN)
	}
	if !next.sawProtocolTLS {
		t.Fatalf("Next saw Protocol != TLS")
	}
	if next.sawSNI != testSNI {
		t.Fatalf("Next saw SNI %q, want %q", next.sawSNI, testSNI)
	}
	if !next.sawTerminated {
		t.Fatalf("Next did not receive the terminated TLS connection as Downstream")
	}
}

// TestHandle_PlaintextConnection_PropagatesErrorAndSkipsNext drives a
// connection carrying no ClientHello at all -- the captured-plaintext case of
// issue #83 -- and asserts it is refused, Next is skipped, and the refusal is
// classified as plaintext rather than as a TLS handshake fault.
//
// This test previously asserted handshake_failed for these same bytes, which
// is precisely the defect #83 reported: an operator filtering on
// transport="plaintext" saw nothing, and fault="true" pointed them at aksh
// instead of at their own workload.
func TestHandle_PlaintextConnection_PropagatesErrorAndSkipsNext(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	metrics := &fakeTLSMetrics{}
	term := newTestTerminator(t, source, metrics)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	go func() {
		_, _ = client.Write([]byte("not-a-tls-client-hello"))
		_ = client.Close()
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(context.Background(), cc); err == nil {
		t.Fatalf("plaintext connection must propagate an error")
	}
	if next.callCount() != 0 {
		t.Fatalf("Next.Handle calls = %d, want 0 after a refused plaintext connection", next.callCount())
	}

	got := metrics.allDecisions()
	if len(got) != 1 {
		t.Fatalf("decisions = %v, want exactly 1 for one connection", got)
	}
	d := got[0]
	if d.disposition != "deny" || d.reason != "unsupported_protocol" {
		t.Fatalf("decision = %+v, want deny/unsupported_protocol", d)
	}
	if d.transport != "plaintext" {
		t.Fatalf("decision transport = %q, want %q: the connection carried no TLS record, "+
			"and transport=\"plaintext\" is the natural operator query for "+
			"\"is anything of mine being refused for being plaintext?\" (#83)", d.transport, "plaintext")
	}
	if d.fault {
		t.Fatalf("decision fault = true, want false: refusing plaintext is a transport-policy "+
			"outcome, not an aksh malfunction; fault=true inflates fault-rate SLOs and "+
			"misdirects the operator (#83). decision = %+v", d)
	}
	if classes := metrics.rejectClasses(); len(classes) != 1 || classes[0] != "plaintext_registry_unavailable" {
		t.Fatalf("transport reject classes = %v, want exactly [plaintext_registry_unavailable]; "+
			"the T9 taxonomy constants existed but no production site raised them (#83)", classes)
	}
	// A malformed ClientHello never reaches the capture point, so nothing may
	// have been recorded on the ConnContext.
	if cc.CandidateSNI != "" {
		t.Fatalf("cc.CandidateSNI = %q, want empty after a malformed ClientHello", cc.CandidateSNI)
	}
}

func TestHandle_PopulatesCandidateSNIFromClientHello_AssertPasses(t *testing.T) {
	// Regression: production creates the ConnContext at accept time with an
	// EMPTY CandidateSNI (the SNI is only known once the ClientHello arrives).
	// The handler must populate cc.CandidateSNI from the ClientHello during the
	// handshake, otherwise PostHandshakeAssert compares the negotiated
	// ServerName against "" and rejects every TLS connection.
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		tc := tls.Client(client, clientTLSConfig())
		_ = tc.HandshakeContext(ctx)
	}()

	// CandidateSNI deliberately left empty to mirror the production accept path.
	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); err != nil {
		t.Fatalf("Handle returned error with empty initial CandidateSNI: %v", err)
	}
	if next.callCount() != 1 {
		t.Fatalf("Next.Handle calls = %d, want 1", next.callCount())
	}
	if cc.CandidateSNI != testSNI {
		t.Fatalf("CandidateSNI = %q, want %q (not populated from ClientHello)", cc.CandidateSNI, testSNI)
	}
}

func TestHandle_ClientHelloSNIOverridesPresetCandidate(t *testing.T) {
	// The ClientHello is the authoritative source of the candidate SNI: any
	// value pre-set on the ConnContext must be overwritten with the negotiated
	// name so the assertion cannot be defeated (or falsely tripped) by stale
	// external state. PostHandshakeAssert's own mismatch rejection is covered
	// directly in tlsterm's terminator tests.
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		tc := tls.Client(client, clientTLSConfig())
		_ = tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server, CandidateSNI: "mismatch.example.com"}
	if err := h.Handle(ctx, cc); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if next.callCount() != 1 {
		t.Fatalf("Next.Handle calls = %d, want 1", next.callCount())
	}
	if cc.CandidateSNI != testSNI {
		t.Fatalf("CandidateSNI = %q, want %q (ClientHello did not override preset)", cc.CandidateSNI, testSNI)
	}
}

func TestHandle_TerminatorGetConfigForClient_UsesLeafSource(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		tc := tls.Client(client, clientTLSConfig())
		_ = tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}

	names := source.requestedNames()
	if len(names) == 0 || names[0] != testSNI {
		t.Fatalf("leaf source requested = %v, want first entry %q (SNI leaf selection)", names, testSNI)
	}
	if next.callCount() != 1 {
		t.Fatalf("request path was not reached after leaf selection")
	}
}

func TestHandle_RequestPathError_PropagatesAfterSuccessfulHandshake(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, client := tcpPipe(t)
	sentinel := errors.New("request path rejected")
	next := &recordingNext{original: server, err: sentinel}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		tc := tls.Client(client, clientTLSConfig())
		_ = tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server}
	err = h.Handle(ctx, cc)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Handle err = %v, want the request-path error", err)
	}
	if next.callCount() != 1 {
		t.Fatalf("Next.Handle calls = %d, want 1", next.callCount())
	}
}

func TestHandle_ContextCanceledBeforeHandshake_ReturnsContextError(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, _ := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cc := &listener.ConnContext{Downstream: server}
	err = h.Handle(ctx, cc)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Handle err = %v, want context.Canceled", err)
	}
	if next.callCount() != 0 {
		t.Fatalf("canceled context must not delegate")
	}
	if len(source.requestedNames()) != 0 {
		t.Fatalf("canceled context must not begin a TLS handshake")
	}
}

// TestHandle_PlaintextRejectMetric_RecordedOnce pins acceptance criterion 1 of
// issue #83: one plaintext connection produces exactly one decision. Before
// the decision latch it produced two -- the terminator's own sample plus the
// listener's unconditional post-Handle rollup, which added internal/fault=true
// on top (problem 4 of #83, and the shared root cause with #89).
func TestHandle_PlaintextRejectMetric_RecordedOnce(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	metrics := &fakeTLSMetrics{}
	term := newTestTerminator(t, source, metrics)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	go func() {
		_, _ = client.Write([]byte("not-a-tls-client-hello"))
		_ = client.Close()
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(context.Background(), cc); err == nil {
		t.Fatalf("plaintext connection must return an error")
	}
	if got := metrics.allDecisions(); len(got) != 1 {
		t.Fatalf("decisions recorded = %v, want exactly 1", got)
	}
	if got := metrics.handshakeFailures(); got != 0 {
		t.Fatalf("handshake_failed recorded %d times, want 0: a connection that carried no "+
			"ClientHello is not a failed TLS handshake (#83)", got)
	}
	if len(source.requestedNames()) != 0 {
		t.Fatalf("a malformed ClientHello must not reach the leaf source (no double counting)")
	}
	if next.callCount() != 0 {
		t.Fatalf("Next must be skipped on a refused plaintext connection")
	}
}

// TestHandle_RealClientHelloThenHandshakeFailure_RecordsHandshakeFailed covers
// the genuine TLS-handshake-failure path, which no test exercised before:
// the two tests that claimed to were writing "not-a-tls-client-hello", i.e.
// plaintext bytes, and so were really asserting the misclassification that
// issue #83 reported.
//
// Here the client sends a well-formed ClientHello carrying SNI, so
// GetConfigForClient succeeds and CandidateSNI is captured, and only then does
// the handshake fail (the client rejects the aksh-minted leaf, since it trusts
// no CA). That must still be accounted as handshake_failed on transport=tls --
// it really was a TLS handshake -- and exactly once.
func TestHandle_RealClientHelloThenHandshakeFailure_RecordsHandshakeFailed(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	metrics := &fakeTLSMetrics{}
	term := newTestTerminator(t, source, metrics)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	go func() {
		// Empty RootCAs: the client sends a real ClientHello, receives the
		// minted leaf, fails to verify it, sends an alert and closes.
		tc := tls.Client(client, &tls.Config{
			ServerName: testSNI,
			RootCAs:    x509.NewCertPool(),
			MinVersion: tls.VersionTLS12,
		})
		_ = tc.Handshake()
		_ = tc.Close()
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(context.Background(), cc); err == nil {
		t.Fatalf("a failed handshake must propagate an error")
	}
	if next.callCount() != 0 {
		t.Fatalf("Next must be skipped on handshake failure")
	}

	got := metrics.allDecisions()
	if len(got) != 1 {
		t.Fatalf("decisions = %v, want exactly 1 for one connection", got)
	}
	if got[0].reason != "handshake_failed" || got[0].transport != "tls" {
		t.Fatalf("decision = %+v, want deny/handshake_failed on transport=tls: a real "+
			"ClientHello was sent, so this is a TLS handshake failure, not plaintext", got[0])
	}
	if classes := metrics.rejectClasses(); len(classes) != 0 {
		t.Fatalf("transport reject classes = %v, want none: T9 is the plaintext class and "+
			"must not be raised for a genuine handshake failure", classes)
	}
	if cc.CandidateSNI != testSNI {
		t.Fatalf("CandidateSNI = %q, want %q: the ClientHello reached the capture point", cc.CandidateSNI, testSNI)
	}
}

func TestHandle_BareRequestPathBypass_NotAccepted(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)

	bare := (*requestpath.Handler)(nil)
	h, err := NewTLSTerminatingConnHandler(bare, term)
	if err == nil {
		t.Fatalf("construction must fail closed when Next is the bare requestpath.Handler")
	}
	if h != nil {
		t.Fatalf("failed construction must not return a handler")
	}
	if !errors.Is(err, errBareRequestPathBypass) {
		t.Fatalf("construction err = %v, want errBareRequestPathBypass", err)
	}
}

// TestHandle_NilContext_ReturnsError asserts Handle fails closed on a nil
// context instead of panicking in ctx.Err(), and never begins a handshake or
// delegates.
func TestHandle_NilContext_ReturnsError(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, _ := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	cc := &listener.ConnContext{Downstream: server}
	err = h.Handle(nil, cc)
	if !errors.Is(err, errNilContext) {
		t.Fatalf("Handle err = %v, want errNilContext", err)
	}
	if next.callCount() != 0 {
		t.Fatalf("nil context must not delegate")
	}
	if len(source.requestedNames()) != 0 {
		t.Fatalf("nil context must not begin a TLS handshake")
	}
}

// TestHandle_NilConnContext_ReturnsError asserts Handle fails closed on a nil
// ConnContext instead of panicking when constructing the TLS server.
func TestHandle_NilConnContext_ReturnsError(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, _ := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	err = h.Handle(context.Background(), nil)
	if !errors.Is(err, errNilConnContext) {
		t.Fatalf("Handle err = %v, want errNilConnContext", err)
	}
	if next.callCount() != 0 {
		t.Fatalf("nil conn context must not delegate")
	}
	if len(source.requestedNames()) != 0 {
		t.Fatalf("nil conn context must not begin a TLS handshake")
	}
}

// TestHandle_NilDownstream_ReturnsError asserts Handle fails closed when the
// ConnContext carries no downstream connection instead of panicking in
// tls.Server.
func TestHandle_NilDownstream_ReturnsError(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, _ := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	cc := &listener.ConnContext{Downstream: nil}
	err = h.Handle(context.Background(), cc)
	if !errors.Is(err, errNilDownstream) {
		t.Fatalf("Handle err = %v, want errNilDownstream", err)
	}
	if next.callCount() != 0 {
		t.Fatalf("nil downstream must not delegate")
	}
	if len(source.requestedNames()) != 0 {
		t.Fatalf("nil downstream must not begin a TLS handshake")
	}
}

// TestNewTLSTerminatingConnHandler_ConcreteTerminator_SatisfiesTerminatorSeam
// asserts the concrete terminator satisfies the narrow consumer-side seam the
// handler depends on, so injection cannot drift from production wiring.
func TestNewTLSTerminatingConnHandler_ConcreteTerminator_SatisfiesTerminatorSeam(t *testing.T) {
	var _ tlsTerminator = (*tlsterm.Terminator)(nil)

	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	next := &recordingNext{}

	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}
	if h == nil {
		t.Fatalf("constructor returned a nil handler")
	}
	if h.Terminator == nil {
		t.Fatalf("handler Terminator field is nil after construction")
	}
}

// TestNewTLSTerminatingConnHandler_NilTerminator_FailsClosed asserts the
// constructor refuses a nil terminator instead of handing back a handler that
// would only fail once a connection arrives.
func TestNewTLSTerminatingConnHandler_NilTerminator_FailsClosed(t *testing.T) {
	next := &recordingNext{}

	h, err := NewTLSTerminatingConnHandler(next, nil)
	if !errors.Is(err, errNilTerminator) {
		t.Fatalf("construction err = %v, want errNilTerminator", err)
	}
	if h != nil {
		t.Fatalf("failed construction must not return a handler")
	}
}

// stubTerminator embeds the real terminator so a genuine handshake still
// completes, and overrides only the post-handshake assertion and the failure
// accounting so those branches are reachable through the production type graph
// instead of through an impossible ConnContext.
type stubTerminator struct {
	*tlsterm.Terminator
	mu               sync.Mutex
	assertErr        error
	delegateAssert   bool
	assertCalls      int
	sawCandidate     string
	failureSNIs      []string
	plaintextRejects int
}

func (s *stubTerminator) PostHandshakeAssert(state tls.ConnectionState, candidateSNI string) error {
	s.mu.Lock()
	s.assertCalls++
	s.sawCandidate = candidateSNI
	delegate := s.delegateAssert
	err := s.assertErr
	s.mu.Unlock()
	if delegate {
		return s.Terminator.PostHandshakeAssert(state, candidateSNI)
	}
	return err
}

func (s *stubTerminator) RecordHandshakeFailure(candidateSNI string) {
	s.mu.Lock()
	s.failureSNIs = append(s.failureSNIs, candidateSNI)
	s.mu.Unlock()
	s.Terminator.RecordHandshakeFailure(candidateSNI)
}

func (s *stubTerminator) RecordPlaintextReject() {
	s.mu.Lock()
	s.plaintextRejects++
	s.mu.Unlock()
	s.Terminator.RecordPlaintextReject()
}

func (s *stubTerminator) plaintextRejectCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.plaintextRejects
}

func (s *stubTerminator) candidateSNISeen() (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sawCandidate, s.assertCalls
}

func (s *stubTerminator) handshakeFailureSNIs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.failureSNIs...)
}

// TestHandle_PostHandshakeAssertFails_ReturnsErrorAndSkipsNext asserts a failed
// post-handshake identity assertion propagates and never delegates, with the
// failure induced through the injected terminator seam.
func TestHandle_PostHandshakeAssertFails_ReturnsErrorAndSkipsNext(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	sentinel := errors.New("post-handshake assert rejected")
	stub := &stubTerminator{Terminator: term, assertErr: sentinel}
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h := tlsTerminatingConnHandler{Terminator: stub, Next: next}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		tc := tls.Client(client, clientTLSConfig())
		_ = tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); !errors.Is(err, sentinel) {
		t.Fatalf("Handle err = %v, want the post-handshake assert error", err)
	}
	if next.callCount() != 0 {
		t.Fatalf("Next.Handle calls = %d, want 0 after assert failure", next.callCount())
	}

	// The real terminator records a deny on both of PostHandshakeAssert's
	// failure branches before returning, so the handler must claim the latch on
	// the way out. Without it the listener rollup adds a second, coarser
	// internal/fault=true sample for the same connection (#89).
	if !cc.Decided() {
		t.Fatalf("cc.Decided() = false, want true: a failed post-handshake assert must claim " +
			"the decision latch so the listener rollup does not double-count it")
	}
}

// TestHandle_TypedNilTerminator_FailsClosedWithoutPanic asserts a nil
// *tlsterm.Terminator boxed into the seam is still rejected. Production wires
// the handler with a struct literal (assembly.go), which no constructor check
// can intercept.
func TestHandle_TypedNilTerminator_FailsClosedWithoutPanic(t *testing.T) {
	// No client is driven: the guard fires before tls.Server is constructed, so
	// a client goroutine would only idle until the test's connections are closed.
	server, _ := tcpPipe(t)
	next := &recordingNext{original: server}
	h := tlsTerminatingConnHandler{Terminator: (*tlsterm.Terminator)(nil), Next: next}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); !errors.Is(err, errNilTerminator) {
		t.Fatalf("Handle err = %v, want errNilTerminator", err)
	}
	if next.callCount() != 0 {
		t.Fatalf("typed-nil Terminator must not delegate to the request path")
	}
}

// seamTerminator satisfies the tlsTerminator seam without being a
// *tlsterm.Terminator, by delegating every method to an embedded pointer field.
// A typed-nil of this type therefore exercises the handler's nil guard against
// the seam itself rather than against the one concrete implementation.
type seamTerminator struct {
	inner *tlsterm.Terminator
}

func (s *seamTerminator) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	return s.inner.GetConfigForClient(hello)
}

func (s *seamTerminator) PostHandshakeAssert(state tls.ConnectionState, candidateSNI string) error {
	return s.inner.PostHandshakeAssert(state, candidateSNI)
}

func (s *seamTerminator) RecordHandshakeFailure(candidateSNI string) {
	s.inner.RecordHandshakeFailure(candidateSNI)
}

func (s *seamTerminator) RecordPlaintextReject() {
	s.inner.RecordPlaintextReject()
}

// TestHandle_TypedNilSeamImplementation_FailsClosedWithoutPanic asserts the nil
// guard covers the whole tlsTerminator seam, not only *tlsterm.Terminator: any
// implementation boxed into the seam as a nil pointer is rejected with
// errNilTerminator instead of panicking on first use.
func TestHandle_TypedNilSeamImplementation_FailsClosedWithoutPanic(t *testing.T) {
	// As above: no client is needed because the guard fires before tls.Server.
	server, _ := tcpPipe(t)
	next := &recordingNext{original: server}
	h := tlsTerminatingConnHandler{Terminator: (*seamTerminator)(nil), Next: next}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); !errors.Is(err, errNilTerminator) {
		t.Fatalf("Handle err = %v, want errNilTerminator", err)
	}
	if next.callCount() != 0 {
		t.Fatalf("typed-nil seam implementation must not delegate to the request path")
	}
}

// mapTerminator satisfies the tlsTerminator seam on a map kind rather than a
// pointer kind, which is legal Go: any named type with the three methods
// implements the seam. Its methods write to the receiver, so a nil value of it
// panics ("assignment to entry in nil map") on first use.
type mapTerminator map[string]*tls.Config

func (m mapTerminator) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	m[hello.ServerName] = &tls.Config{}
	return m[hello.ServerName], nil
}

func (m mapTerminator) PostHandshakeAssert(_ tls.ConnectionState, candidateSNI string) error {
	m[candidateSNI] = nil
	return nil
}

func (m mapTerminator) RecordHandshakeFailure(candidateSNI string) {
	m[candidateSNI] = nil
}

func (m mapTerminator) RecordPlaintextReject() {
	m[""] = nil
}

// TestHandle_NilNonPointerSeamImplementation_FailsClosedWithoutPanic asserts the
// nil guard is as wide as the seam it protects: a nil implementation whose
// underlying kind is not a pointer is rejected with errNilTerminator instead of
// panicking on first use. Without the guard the malformed ClientHello reaches
// RecordHandshakeFailure, which panics on the nil map receiver.
func TestHandle_NilNonPointerSeamImplementation_FailsClosedWithoutPanic(t *testing.T) {
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h := tlsTerminatingConnHandler{Terminator: mapTerminator(nil), Next: next}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Written synchronously (22 bytes fit the socket buffer) so the handshake
	// fails immediately; no client goroutine has to outlive the assertion.
	if _, err := client.Write([]byte("not-a-tls-client-hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); !errors.Is(err, errNilTerminator) {
		t.Fatalf("Handle err = %v, want errNilTerminator", err)
	}
	if next.callCount() != 0 {
		t.Fatalf("nil non-pointer seam implementation must not delegate to the request path")
	}
}

// TestHandle_PostHandshakeAssert_ReceivesRecordedCandidateSNI asserts the
// terminator's post-handshake assertion is handed the value captured during the
// ClientHello, proving the capture happened before HandshakeContext returned.
func TestHandle_PostHandshakeAssert_ReceivesRecordedCandidateSNI(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	stub := &stubTerminator{Terminator: term, delegateAssert: true}
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h := tlsTerminatingConnHandler{Terminator: stub, Next: next}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientDone := make(chan error, 1)
	go func() {
		tc := tls.Client(client, clientTLSConfig())
		clientDone <- tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	seen, calls := stub.candidateSNISeen()
	if calls != 1 {
		t.Fatalf("PostHandshakeAssert calls = %d, want 1", calls)
	}
	if seen != testSNI {
		t.Fatalf("PostHandshakeAssert saw candidate SNI %q, want %q captured during the ClientHello", seen, testSNI)
	}
}

// TestHandle_MixedCaseSNI_RecordsCanonicalisedLowercaseForm asserts the value
// recorded is the terminator's canonical form, not a raw copy of the
// ClientHello server name.
func TestHandle_MixedCaseSNI_RecordsCanonicalisedLowercaseForm(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientDone := make(chan error, 1)
	go func() {
		tc := tls.Client(client, clientTLSConfigFor("TEST.Example.COM"))
		clientDone <- tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	if cc.CandidateSNI != testSNI {
		t.Fatalf("cc.CandidateSNI = %q, want the canonicalised %q", cc.CandidateSNI, testSNI)
	}
	names := source.requestedNames()
	if len(names) == 0 || names[0] != testSNI {
		t.Fatalf("leaf source requested = %v, want first entry %q (terminator's own canonicalisation)", names, testSNI)
	}
}

// TestHandle_ALabelSNI_RecordsALabelVerbatim asserts an IDN presented in
// A-label form is recorded unchanged, which is the canonical A-label the leaf
// is minted for. tlsterm.CanonicaliseServerName performs no unicode-to-A-label
// conversion: a U-label is rejected instead (see
// TestHandle_UnicodeSNI_RejectsHandshakeAndLeavesCandidateSNIEmpty).
func TestHandle_ALabelSNI_RecordsALabelVerbatim(t *testing.T) {
	const aLabelSNI = "xn--bcher-kva.example"
	source := &fakeLeafSource{cert: newLeafCertificate(t, aLabelSNI)}
	term := newTestTerminator(t, source, nil)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientDone := make(chan error, 1)
	go func() {
		tc := tls.Client(client, clientTLSConfigFor(aLabelSNI))
		clientDone <- tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	if cc.CandidateSNI != aLabelSNI {
		t.Fatalf("cc.CandidateSNI = %q, want the A-label %q", cc.CandidateSNI, aLabelSNI)
	}
	names := source.requestedNames()
	if len(names) == 0 || names[0] != aLabelSNI {
		t.Fatalf("leaf source requested = %v, want first entry %q", names, aLabelSNI)
	}
}

// TestHandle_NoSNI_RejectsHandshakeAndLeavesCandidateSNIEmpty asserts a
// ClientHello without SNI is refused and records nothing.
func TestHandle_NoSNI_RejectsHandshakeAndLeavesCandidateSNIEmpty(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	metrics := &fakeTLSMetrics{}
	term := newTestTerminator(t, source, metrics)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		tc := tls.Client(client, clientTLSConfigFor(""))
		_ = tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); err == nil {
		t.Fatalf("a ClientHello without SNI must fail the handshake")
	}
	if cc.CandidateSNI != "" {
		t.Fatalf("cc.CandidateSNI = %q, want empty on the reject path", cc.CandidateSNI)
	}
	if next.callCount() != 0 {
		t.Fatalf("Next.Handle calls = %d, want 0 after an SNI reject", next.callCount())
	}
	if len(source.requestedNames()) != 0 {
		t.Fatalf("a rejected SNI must not reach the leaf source")
	}

	// GetConfigForClient already recorded the specific reason before refusing
	// the ClientHello. The handshake then fails as a consequence of that same
	// refusal, so attributing a second handshake_failed sample to it both
	// double-counts the connection and buries the precise reason under a
	// generic one. Exactly one sample, and it must be the specific reason.
	got := metrics.allDecisions()
	if len(got) != 1 {
		t.Fatalf("decisions = %+v, want exactly 1: the ClientHello rejection reason is "+
			"recorded once, not again as a handshake failure", got)
	}
	if got[0].reason != "no_sni" {
		t.Fatalf("decision reason = %q, want \"no_sni\": the specific rejection reason must "+
			"survive, not be overwritten by handshake_failed", got[0].reason)
	}
}

// TestHandle_SingleLabelSNI_RejectsHandshakeAndLeavesCandidateSNIEmpty asserts a
// dot-less server name is refused and records nothing.
func TestHandle_SingleLabelSNI_RejectsHandshakeAndLeavesCandidateSNIEmpty(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		tc := tls.Client(client, clientTLSConfigFor("localhost"))
		_ = tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); err == nil {
		t.Fatalf("a dot-less SNI must fail the handshake")
	}
	if cc.CandidateSNI != "" {
		t.Fatalf("cc.CandidateSNI = %q, want empty on the reject path", cc.CandidateSNI)
	}
	if next.callCount() != 0 {
		t.Fatalf("Next.Handle calls = %d, want 0 after an SNI reject", next.callCount())
	}
}

// TestHandle_UnicodeSNI_RejectsHandshakeAndLeavesCandidateSNIEmpty asserts a
// U-label server name is refused rather than converted to an A-label:
// tlsterm.CanonicaliseServerName enforces LDH labels and performs no IDNA
// mapping, so an intercepted unicode name fails closed.
func TestHandle_UnicodeSNI_RejectsHandshakeAndLeavesCandidateSNIEmpty(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		tc := tls.Client(client, clientTLSConfigFor("b\u00fccher.example"))
		_ = tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); err == nil {
		t.Fatalf("a unicode SNI must fail the handshake")
	}
	if cc.CandidateSNI != "" {
		t.Fatalf("cc.CandidateSNI = %q, want empty on the reject path", cc.CandidateSNI)
	}
	if next.callCount() != 0 {
		t.Fatalf("Next.Handle calls = %d, want 0 after an SNI reject", next.callCount())
	}
}

// TestHandle_LeafSourceFailure_RejectsHandshakeAndLeavesCandidateSNIEmpty
// asserts nothing is recorded when certificate selection fails, which pins the
// ordering "delegate first, record only on success".
func TestHandle_LeafSourceFailure_RejectsHandshakeAndLeavesCandidateSNIEmpty(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI), err: errors.New("leaf mint refused")}
	term := newTestTerminator(t, source, nil)
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h, err := NewTLSTerminatingConnHandler(next, term)
	if err != nil {
		t.Fatalf("construct handler: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		tc := tls.Client(client, clientTLSConfig())
		_ = tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); err == nil {
		t.Fatalf("a failed leaf mint must fail the handshake")
	}
	if cc.CandidateSNI != "" {
		t.Fatalf("cc.CandidateSNI = %q, want empty when certificate selection failed", cc.CandidateSNI)
	}
	if next.callCount() != 0 {
		t.Fatalf("Next.Handle calls = %d, want 0 after a leaf mint failure", next.callCount())
	}
}

// TestHandle_ConcurrentConnections_EachConnContextRecordsItsOwnSNI asserts
// simultaneous handshakes never cross-contaminate: each ConnContext ends with
// the SNI its own client offered.
func TestHandle_ConcurrentConnections_EachConnContextRecordsItsOwnSNI(t *testing.T) {
	const connections = 8

	// The leaf is minted for testSNI, not for the per-connection names below;
	// the client's InsecureSkipVerify makes the certificate identity irrelevant
	// to this isolation test, which only asserts which SNI each cc recorded.
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)

	names := make([]string, connections)
	ccs := make([]*listener.ConnContext, connections)
	clients := make([]net.Conn, connections)
	handlers := make([]tlsTerminatingConnHandler, connections)
	handleErrs := make([]error, connections)
	for i := 0; i < connections; i++ {
		names[i] = fmt.Sprintf("conn-%d.example.com", i)
		server, client := tcpPipe(t)
		ccs[i] = &listener.ConnContext{Downstream: server}
		clients[i] = client
		handlers[i] = tlsTerminatingConnHandler{Terminator: term, Next: &recordingNext{original: server}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < connections; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			tc := tls.Client(clients[i], clientTLSConfigFor(names[i]))
			_ = tc.HandshakeContext(ctx)
		}(i)
		go func(i int) {
			defer wg.Done()
			handleErrs[i] = handlers[i].Handle(ctx, ccs[i])
		}(i)
	}
	wg.Wait()

	seen := make(map[string]int, connections)
	for i := 0; i < connections; i++ {
		if handleErrs[i] != nil {
			t.Fatalf("connection %d: Handle returned error: %v", i, handleErrs[i])
		}
		if ccs[i].CandidateSNI != names[i] {
			t.Fatalf("connection %d: cc.CandidateSNI = %q, want %q", i, ccs[i].CandidateSNI, names[i])
		}
		seen[ccs[i].CandidateSNI]++
	}
	if len(seen) != connections {
		t.Fatalf("distinct recorded SNIs = %d, want %d (cross-contamination)", len(seen), connections)
	}
}

// TestHandle_HandshakeFailsAfterConfigSelection_RecordsFailureWithCapturedSNI
// asserts a handshake that fails after certificate selection is accounted with
// the identity captured from the ClientHello rather than an empty string. The
// failure is induced by an ALPN mismatch, which is a hard server-side failure
// on this toolchain and occurs strictly after GetConfigForClient has run. This
// branch's audit.MetricsRecorder carries no identity label, so the accounted
// identity is observed through the terminator seam instead.
func TestHandle_HandshakeFailsAfterConfigSelection_RecordsFailureWithCapturedSNI(t *testing.T) {
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	metrics := &fakeTLSMetrics{}
	term := newTestTerminator(t, source, metrics)
	stub := &stubTerminator{Terminator: term, delegateAssert: true}
	server, client := tcpPipe(t)
	next := &recordingNext{original: server}
	h := tlsTerminatingConnHandler{Terminator: stub, Next: next}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		cfg := clientTLSConfigFor(testSNI)
		cfg.NextProtos = []string{"h2"}
		tc := tls.Client(client, cfg)
		_ = tc.HandshakeContext(ctx)
	}()

	cc := &listener.ConnContext{Downstream: server}
	if err := h.Handle(ctx, cc); err == nil {
		t.Fatalf("an ALPN mismatch must fail the handshake")
	}
	if next.callCount() != 0 {
		t.Fatalf("Next.Handle calls = %d, want 0 after a handshake failure", next.callCount())
	}
	if cc.CandidateSNI != testSNI {
		t.Fatalf("cc.CandidateSNI = %q, want %q captured before the failure", cc.CandidateSNI, testSNI)
	}
	failures := stub.handshakeFailureSNIs()
	if len(failures) != 1 {
		t.Fatalf("RecordHandshakeFailure calls = %v, want exactly 1", failures)
	}
	if failures[0] != testSNI {
		t.Fatalf("handshake failure accounted identity %q, want %q", failures[0], testSNI)
	}
	if got := metrics.handshakeFailures(); got != 1 {
		t.Fatalf("terminator handshake failure metric recorded %d times, want exactly 1", got)
	}
}
