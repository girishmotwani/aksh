package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/dataplane/requestpath"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

// recordingAuditSink captures the decisions the pipeline commits, so a test can
// observe the enforcement outcome of a real connection. It satisfies both
// pipeline.AuditSink (Record only) and the wider audit.AuditSink, which also
// requires RecordCompletion for the post-allow completion record.
type recordingAuditSink struct {
	mu          sync.Mutex
	recorded    []pipeline.AuditEvent
	completions []pipeline.AuditEvent
}

func (s *recordingAuditSink) Record(_ context.Context, ev pipeline.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recorded = append(s.recorded, ev)
	return nil
}

// RecordCompletion is kept separate from Record so the decision assertions below
// observe only enforcement decisions, never post-allow completion records.
func (s *recordingAuditSink) RecordCompletion(_ context.Context, ev pipeline.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completions = append(s.completions, ev)
	return nil
}

func (s *recordingAuditSink) events() []pipeline.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]pipeline.AuditEvent(nil), s.recorded...)
}

// upstreamDial captures one DialUpstream invocation.
type upstreamDial struct {
	addr       netip.AddrPort
	serverName string
	credID     string
}

// recordingDialer records the upstream dial arguments and always refuses the
// dial, so the test observes the identity handed to the dialer without relaying.
type recordingDialer struct {
	mu    sync.Mutex
	calls []upstreamDial
}

func (d *recordingDialer) DialUpstream(_ context.Context, addr netip.AddrPort, serverName string, credID string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, upstreamDial{addr: addr, serverName: serverName, credID: credID})
	d.mu.Unlock()
	return nil, errors.New("recording dialer refuses the upstream dial")
}

func (d *recordingDialer) dials() []upstreamDial {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]upstreamDial(nil), d.calls...)
}

// newConsumerPathHandler wires the real request path over the sanitise and
// identity stages, which is the segment of the production chain that consumes
// the captured SNI.
func newConsumerPathHandler(t *testing.T, sink *recordingAuditSink, dialer *recordingDialer) *requestpath.Handler {
	t.Helper()
	pl := pipeline.NewPipeline([]pipeline.Stage{&pipeline.SanitiseStage{}, &pipeline.IdentityStage{}}, sink)
	handler, err := requestpath.NewHandler(pl, dialer, sink, &fakeTLSMetrics{}, requestpath.DefaultOptions())
	if err != nil {
		t.Fatalf("construct request path handler: %v", err)
	}
	return handler
}

// newConsumerPathConnContext builds the ConnContext the accept loop hands over,
// with no CandidateSNI: the handler must supply it.
func newConsumerPathConnContext(server net.Conn, connID string) *listener.ConnContext {
	return &listener.ConnContext{
		Downstream:  server,
		OriginalDst: netip.MustParseAddrPort("10.0.0.1:443"),
		PeerAddr:    netip.MustParseAddrPort("10.1.2.3:52000"),
		ConnID:      connID,
		AcceptedAt:  time.Now(),
	}
}

// TestHandle_EndToEnd_SNIHostMismatch_DeniedByIdentityStage asserts the captured
// SNI reaches the pipeline's confused-deputy check: a request whose Host names a
// different authority than the ClientHello SNI is denied and never dialled.
func TestHandle_EndToEnd_SNIHostMismatch_DeniedByIdentityStage(t *testing.T) {
	sink := &recordingAuditSink{}
	dialer := &recordingDialer{}
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, client := tcpPipe(t)
	h := tlsTerminatingConnHandler{Terminator: term, Next: newConsumerPathHandler(t, sink, dialer)}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cc := newConsumerPathConnContext(server, "conn-mismatch")
	handleDone := make(chan error, 1)
	go func() {
		handleDone <- h.Handle(ctx, cc)
	}()

	tc := tls.Client(client, clientTLSConfig())
	if err := tc.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: other.example.com\r\n\r\n")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := tc.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, readErr := tc.Read(buf)
	if n != 0 {
		t.Fatalf("client read %d bytes (%q), want a silent close on identity mismatch", n, buf[:n])
	}
	if readErr == nil {
		t.Fatalf("client read must fail after the connection is closed")
	}

	select {
	case err := <-handleDone:
		if err != nil {
			t.Fatalf("Handle returned error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("Handle did not return")
	}

	if cc.CandidateSNI != testSNI {
		t.Fatalf("cc.CandidateSNI = %q, want %q", cc.CandidateSNI, testSNI)
	}
	events := sink.events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly 1 (the identity decision)", len(events))
	}
	if events[0].Disposition != pipeline.DispositionDeny {
		t.Fatalf("audit disposition = %v, want deny", events[0].Disposition)
	}
	if events[0].DenyReason != pipeline.ReasonIdentityMismatch {
		t.Fatalf("audit deny reason = %v, want %v", events[0].DenyReason, pipeline.ReasonIdentityMismatch)
	}
	if dials := dialer.dials(); len(dials) != 0 {
		t.Fatalf("upstream dials = %v, want none for a denied request", dials)
	}
}

// TestHandle_EndToEnd_SNIHostMatch_DialsUpstreamWithCapturedSNI asserts a
// matching Host is allowed and that the captured SNI is the identity handed to
// the upstream dialer.
func TestHandle_EndToEnd_SNIHostMatch_DialsUpstreamWithCapturedSNI(t *testing.T) {
	sink := &recordingAuditSink{}
	dialer := &recordingDialer{}
	source := &fakeLeafSource{cert: newLeafCertificate(t, testSNI)}
	term := newTestTerminator(t, source, nil)
	server, client := tcpPipe(t)
	h := tlsTerminatingConnHandler{Terminator: term, Next: newConsumerPathHandler(t, sink, dialer)}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cc := newConsumerPathConnContext(server, "conn-match")
	handleDone := make(chan error, 1)
	go func() {
		handleDone <- h.Handle(ctx, cc)
	}()

	tc := tls.Client(client, clientTLSConfig())
	if err := tc.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: test.example.com\r\n\r\n")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := tc.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 64)
	// The response content is irrelevant here: the recording dialer always
	// refuses the upstream dial, so this Read only unblocks the handler. The
	// enforcement outcome is asserted through the audit sink and the dialer.
	_, _ = tc.Read(buf)

	select {
	case err := <-handleDone:
		if err != nil {
			t.Fatalf("Handle returned error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("Handle did not return")
	}

	// Asserted directly rather than inferred from the downstream effects below:
	// this is the field issue #32 left empty, and the audit identity would still
	// read testSNI if it were sourced from the request Host instead.
	if cc.CandidateSNI != testSNI {
		t.Fatalf("cc.CandidateSNI = %q, want %q", cc.CandidateSNI, testSNI)
	}
	events := sink.events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly 1 (the identity decision)", len(events))
	}
	if events[0].Disposition != pipeline.DispositionAllow {
		t.Fatalf("audit disposition = %v, want allow", events[0].Disposition)
	}
	if events[0].Identity != testSNI {
		t.Fatalf("audit identity = %q, want %q", events[0].Identity, testSNI)
	}
	dials := dialer.dials()
	if len(dials) != 1 {
		t.Fatalf("upstream dials = %d, want exactly 1", len(dials))
	}
	// relay.go passes rc.Facts.Identity as the dialer's serverName argument, and
	// IdentityStage sets Facts.Identity from the captured SNI.
	if dials[0].serverName != testSNI {
		t.Fatalf("upstream dial serverName = %q, want the captured SNI %q", dials[0].serverName, testSNI)
	}
}
