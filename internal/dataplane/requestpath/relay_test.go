package requestpath

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/girishmotwani/aksh/internal/policy"
	"github.com/girishmotwani/aksh/internal/token"
)

type dialCall struct {
	addr       netip.AddrPort
	serverName string
	credID     string
}

type scriptedDialer struct {
	mu    sync.Mutex
	calls []dialCall
	fn    func(context.Context, netip.AddrPort, string, string) (net.Conn, error)
}

func (d *scriptedDialer) DialUpstream(ctx context.Context, addr netip.AddrPort, serverName string, credID string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, dialCall{addr: addr, serverName: serverName, credID: credID})
	d.mu.Unlock()
	return d.fn(ctx, addr, serverName, credID)
}

func (d *scriptedDialer) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

type recordingMetrics struct {
	audit.NopMetricsRecorder
	mu        sync.Mutex
	faults    []bool
	decisions []struct {
		disposition string
		reason      string
		identity    string
	}
}

func (m *recordingMetrics) Decisions(d pipeline.Disposition, r pipeline.DenyReason, transport audit.TransportKind, fault bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.faults = append(m.faults, fault)
	m.decisions = append(m.decisions, struct {
		disposition string
		reason      string
		identity    string
	}{disposition: d.String(), reason: r.String()})
}

// count returns how many decisions were recorded, so a test can assert the
// one-decision-per-connection invariant and not merely that some expected
// reason appeared somewhere among several.
func (m *recordingMetrics) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.decisions)
}

// firstFault reports the fault label of the first recorded decision.
func (m *recordingMetrics) firstFault() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.faults) == 0 {
		return false
	}
	return m.faults[0]
}

func (m *recordingMetrics) saw(reason string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, decision := range m.decisions {
		if decision.reason == reason {
			return true
		}
	}
	return false
}

func TestServe_DecisionAllow_RelaysToUpstream(t *testing.T) {
	sink := &recordingSink{}
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				req, err := http.ReadRequest(bufio.NewReader(upstreamConn))
				if err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				if req.Host != "api.example.com" {
					t.Errorf("upstream Host = %q, want api.example.com", req.Host)
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /resource HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	resp := mustReadResponse(t, br, nil)
	body := readBody(t, resp)
	client.Close()

	if body != "OK" {
		t.Fatalf("response body = %q, want OK", body)
	}
	if dialer.callCount() != 1 {
		t.Fatalf("dial attempts = %d, want 1", dialer.callCount())
	}
	waitServeDone(t, done)
}

func TestEnsureUpstream_UsesCallerContextForDial(t *testing.T) {
	sink := &recordingSink{}
	dialer := &scriptedDialer{
		fn: func(ctx context.Context, _ netip.AddrPort, _ string, _ string) (net.Conn, error) {
			if err := ctx.Err(); err == nil {
				t.Fatal("DialUpstream context was not cancelled")
			}
			return nil, ctx.Err()
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	upstream, ok := handler.ensureUpstream(ctx, &connState{ho: validHandover(nil)}, &pipeline.RequestContext{
		Facts: pipelineFacts("api.example.com", 443),
	}, "cred-1")
	if ok || upstream != nil {
		t.Fatalf("ensureUpstream() = (%v, %v), want (nil, false)", upstream, ok)
	}
}

func TestServe_DecisionDenyUniform_Writes403ThenCloses(t *testing.T) {
	sink := &recordingSink{}
	dialer := &scriptedDialer{fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
		t.Fatal("DialUpstream must not be called for a denied request")
		return nil, nil
	}}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, denyPipeline(sink, pipeline.ReasonNoMatch), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /deny HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	resp := mustReadResponse(t, br, nil)
	client.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("StatusCode = %d, want 403", resp.StatusCode)
	}
	if dialer.callCount() != 0 {
		t.Fatalf("dial attempts = %d, want 0", dialer.callCount())
	}
	waitServeDone(t, done)
}

func TestServe_DecisionDenyIdentityMismatch_ClosesBareNoUniform(t *testing.T) {
	sink := &recordingSink{}
	dialer := &scriptedDialer{fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
		t.Fatal("DialUpstream must not be called for identity mismatch")
		return nil, nil
	}}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, denyPipeline(sink, pipeline.ReasonIdentityMismatch), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)

	writeRequestAsync(client, "GET /deny HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	got := readUntilEOF(client)
	client.Close()

	if got != "" {
		t.Fatalf("response bytes = %q, want empty", got)
	}
	waitServeDone(t, done)
}

func TestServe_PostAuditFaultInjectStageFailure_DenialShapedNoRelayNoSecondAudit(t *testing.T) {
	sink := &recordingSink{}
	dialer := &scriptedDialer{fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
		t.Fatal("DialUpstream must not be called after a post-audit inject failure")
		return nil, nil
	}}

	stages := stageSlice(
		stageFunc{name: "match", fn: func(rc *pipeline.RequestContext) pipeline.Decision {
			rc.MatchResult.PolicyRef = "rule-1"
			return pipeline.Allow()
		}},
		stageFunc{name: "acquire", fn: func(rc *pipeline.RequestContext) pipeline.Decision {
			rc.TokenResult = token.TokenResult{Resolved: token.ResolvedCredential{Identity: "cred-1"}}
			return pipeline.Allow()
		}},
	)
	stages[len(stages)-1] = stageFunc{name: "inject", fn: func(*pipeline.RequestContext) pipeline.Decision {
		return pipeline.DenyFault(pipeline.ReasonInternal, errors.New("inject failed"))
	}}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, pipeline.NewPipeline(stages, sink), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /deny HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	resp := mustReadResponse(t, br, nil)
	client.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("StatusCode = %d, want 403", resp.StatusCode)
	}
	waitAuditCount(t, sink, 1)
	if sink.count() != 1 {
		t.Fatalf("audit count = %d, want 1", sink.count())
	}
	if dialer.callCount() != 0 {
		t.Fatalf("dial attempts = %d, want 0", dialer.callCount())
	}
	waitServeDone(t, done)
}

func TestServe_ReuseConditionsAllSatisfied_ServesSecondRequestOnSameConn(t *testing.T) {
	sink := &recordingSink{}
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				br := bufio.NewReader(upstreamConn)
				for i := 0; i < 2; i++ {
					if _, err := http.ReadRequest(br); err != nil {
						t.Errorf("http.ReadRequest() error = %v", err)
						return
					}
					_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
				}
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /one HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if got := readBody(t, mustReadResponse(t, br, nil)); got != "OK" {
		t.Fatalf("first response body = %q, want OK", got)
	}
	writeRequest(t, client, "GET /two HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if got := readBody(t, mustReadResponse(t, br, nil)); got != "OK" {
		t.Fatalf("second response body = %q, want OK", got)
	}
	client.Close()

	if dialer.callCount() != 1 {
		t.Fatalf("dial attempts = %d, want 1", dialer.callCount())
	}
	waitServeDone(t, done)
}

func TestServe_UpstreamSentConnectionClose_DoesNotReuse(t *testing.T) {
	sink := &recordingSink{}
	var dialNum atomic.Int64
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			n := dialNum.Add(1)
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				if n == 1 {
					_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nTWO")
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /one HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if got := readBody(t, mustReadResponse(t, br, nil)); got != "OK" {
		t.Fatalf("first response body = %q, want OK", got)
	}
	writeRequest(t, client, "GET /two HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if got := readBody(t, mustReadResponse(t, br, nil)); got != "TWO" {
		t.Fatalf("second response body = %q, want TWO", got)
	}
	client.Close()

	if dialer.callCount() != 2 {
		t.Fatalf("dial attempts = %d, want 2", dialer.callCount())
	}
	waitServeDone(t, done)
}

func TestServe_PolicyReEvaluatedPerRequest_SecondRequestDeniedAfterPolicySwap(t *testing.T) {
	sink := &recordingSink{}
	metrics := &recordingMetrics{}
	var matchCalls atomic.Int64
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
			}()
			return handlerConn, nil
		},
	}
	p := pipeline.NewPipeline(stageSlice(
		stageFunc{name: "match", fn: func(rc *pipeline.RequestContext) pipeline.Decision {
			if matchCalls.Add(1) == 1 {
				rc.MatchResult.PolicyRef = "rule-1"
				return pipeline.Allow()
			}
			return pipeline.Deny(pipeline.ReasonNoMatch, nil)
		}},
		stageFunc{name: "acquire", fn: func(rc *pipeline.RequestContext) pipeline.Decision {
			rc.TokenResult = token.TokenResult{Resolved: token.ResolvedCredential{Identity: "cred-1"}}
			return pipeline.Allow()
		}},
	), sink)
	handler := newRelayHandler(t, sink, dialer, metrics, p, DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /one HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if got := readBody(t, mustReadResponse(t, br, nil)); got != "OK" {
		t.Fatalf("first response body = %q, want OK", got)
	}
	writeRequest(t, client, "GET /two HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	resp := mustReadResponse(t, br, nil)
	client.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("StatusCode = %d, want 403", resp.StatusCode)
	}
	if matchCalls.Load() != 2 {
		t.Fatalf("match stage count = %d, want 2", matchCalls.Load())
	}
	waitServeDone(t, done)
}

func TestServe_ShutdownInFlightRequest_CompletesBeforeClosing(t *testing.T) {
	sink := &recordingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	releaseResponse := make(chan struct{})
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				cancel()
				<-releaseResponse
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDONE")
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(ctx, validHandover(downstream)) }()
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /work HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	close(releaseResponse)
	if got := readBody(t, mustReadResponse(t, br, nil)); got != "DONE" {
		t.Fatalf("response body = %q, want DONE", got)
	}
	client.Close()
	waitServeDone(t, done)
}

func TestServe_ShutdownIdleConnection_ClosesPromptly(t *testing.T) {
	sink := &recordingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	handler := newRelayHandler(t, sink, &scriptedDialer{}, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(ctx, validHandover(downstream)) }()

	cancel()
	client.Close()
	waitServeDone(t, done)
}

func TestRequestHeadFlushedBeforeBody(t *testing.T) {
	sink := &recordingSink{}
	headSeen := make(chan string, 1)
	headVerified := make(chan struct{})
	bodyGate := make(chan struct{})
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				raw := readRawHead(t, upstreamConn)
				headSeen <- raw
				_ = upstreamConn.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
				buf := make([]byte, 1)
				if _, err := upstreamConn.Read(buf); err == nil {
					t.Errorf("body byte arrived before test released it")
					return
				}
				close(headVerified)
				<-bodyGate
				_ = upstreamConn.SetReadDeadline(time.Time{})
				if _, err := io.ReadFull(upstreamConn, buf); err != nil {
					t.Errorf("io.ReadFull() error = %v", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	go func() {
		writeRequest(t, client, "POST /upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 1\r\n\r\n")
		<-bodyGate
		writeRequest(t, client, "X")
	}()

	raw := <-headSeen
	if !strings.Contains(raw, "POST /upload HTTP/1.1\r\n") {
		t.Fatalf("upstream head = %q, want request line", raw)
	}
	<-headVerified
	close(bodyGate)
	if got := readBody(t, mustReadResponse(t, br, nil)); got != "OK" {
		t.Fatalf("response body = %q, want OK", got)
	}
	client.Close()
	waitServeDone(t, done)
}

func TestResponseStreamsWithoutBuffering(t *testing.T) {
	sink := &recordingSink{}
	firstChunk := make(chan struct{})
	secondChunk := make(chan struct{})
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello")
				close(firstChunk)
				<-secondChunk
				_, _ = io.WriteString(upstreamConn, "world")
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /stream HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	resp := mustReadResponse(t, br, nil)
	<-firstChunk

	buf := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatalf("io.ReadFull() error = %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("first body chunk = %q, want hello", string(buf))
	}
	close(secondChunk)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatalf("io.ReadFull() error = %v", err)
	}
	if string(buf) != "world" {
		t.Fatalf("second body chunk = %q, want world", string(buf))
	}
	client.Close()
	waitServeDone(t, done)
}

func TestCopyBufferNoResidue(t *testing.T) {
	sink := &recordingSink{}
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				br := bufio.NewReader(upstreamConn)
				if _, err := http.ReadRequest(br); err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nABCDEF")
				if _, err := http.ReadRequest(br); err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /one HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	_ = readBody(t, mustReadResponse(t, br, nil))
	writeRequest(t, client, "GET /two HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if got := readBody(t, mustReadResponse(t, br, nil)); got != "OK" {
		t.Fatalf("second response body = %q, want OK", got)
	}
	client.Close()
	waitServeDone(t, done)
}

func TestUpstreamTargetMatchesCanonicalPath(t *testing.T) {
	sink := &recordingSink{}
	targets := make(chan string, 1)
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				raw := readRawHead(t, upstreamConn)
				requestLine := strings.SplitN(raw, "\r\n", 2)[0]
				parts := strings.Split(requestLine, " ")
				if len(parts) >= 2 {
					targets <- parts[1]
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /a%2Fb HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if got := readBody(t, mustReadResponse(t, br, nil)); got != "OK" {
		t.Fatalf("response body = %q, want OK", got)
	}
	client.Close()

	if got := <-targets; got != "/a%2Fb" {
		t.Fatalf("upstream target = %q, want /a%%2Fb", got)
	}
	waitServeDone(t, done)
}

func TestUpstreamHostIsValidatedIdentity(t *testing.T) {
	sink := &recordingSink{}
	hosts := make(chan string, 1)
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				req, err := http.ReadRequest(bufio.NewReader(upstreamConn))
				if err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				hosts <- req.Host
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET / HTTP/1.1\r\nHost: API.EXAMPLE.COM\r\n\r\n")
	_ = readBody(t, mustReadResponse(t, br, nil))
	client.Close()

	if got := <-hosts; got != "api.example.com" {
		t.Fatalf("upstream Host = %q, want api.example.com", got)
	}
	waitServeDone(t, done)
}

func TestHopByHopStrippedOnResponse(t *testing.T) {
	sink := &recordingSink{}
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive, X-Secret\r\nX-Secret: shh\r\n\r\nOK")
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	resp := mustReadResponse(t, br, nil)
	client.Close()

	if resp.Header.Get("Connection") != "" {
		t.Fatalf("Connection header = %q, want empty", resp.Header.Get("Connection"))
	}
	if resp.Header.Get("X-Secret") != "" {
		t.Fatalf("X-Secret header = %q, want empty", resp.Header.Get("X-Secret"))
	}
	waitServeDone(t, done)
}

func TestHeadResponseNoBody(t *testing.T) {
	sink := &recordingSink{}
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				br := bufio.NewReader(upstreamConn)
				if _, err := http.ReadRequest(br); err != nil {
					t.Errorf("first http.ReadRequest() error = %v", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
				if _, err := http.ReadRequest(br); err != nil {
					t.Errorf("second http.ReadRequest() error = %v", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	headReq := mustReadClientRequest(t, "HEAD /head HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	writeRequest(t, client, "HEAD /head HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if got := readBody(t, mustReadResponse(t, br, headReq)); got != "" {
		t.Fatalf("HEAD response body = %q, want empty", got)
	}
	writeRequest(t, client, "GET /body HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if got := readBody(t, mustReadResponse(t, br, nil)); got != "OK" {
		t.Fatalf("second response body = %q, want OK", got)
	}
	client.Close()
	waitServeDone(t, done)
}

func TestNoRetryAfterAllow(t *testing.T) {
	sink := &recordingSink{}
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /retry HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	resp := mustReadResponse(t, br, nil)
	client.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("StatusCode = %d, want 403", resp.StatusCode)
	}
	if dialer.callCount() != 1 {
		t.Fatalf("dial attempts = %d, want 1", dialer.callCount())
	}
	waitServeDone(t, done)
}

func TestUpstreamReuseRequiresSameIdentity(t *testing.T) {
	t.Run("identity change forces redial", func(t *testing.T) {
		sink := &recordingSink{}
		var matchCalls atomic.Int64
		dialer := &scriptedDialer{
			fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
				handlerConn, upstreamConn := net.Pipe()
				go func() {
					defer upstreamConn.Close()
					if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
						t.Errorf("http.ReadRequest() error = %v", err)
						return
					}
					_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
				}()
				return handlerConn, nil
			},
		}
		p := pipeline.NewPipeline(stageSlice(
			stageFunc{name: "match", fn: func(rc *pipeline.RequestContext) pipeline.Decision {
				matchCalls.Add(1)
				return pipeline.Allow()
			}},
			stageFunc{name: "acquire", fn: func(rc *pipeline.RequestContext) pipeline.Decision {
				rc.TokenResult = token.TokenResult{Resolved: token.ResolvedCredential{Identity: "cred-1"}}
				return pipeline.Allow()
			}},
		), sink)
		handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, p, DefaultOptions())

		downstream, client := net.Pipe()
		done := make(chan error, 1)
		go func() {
			ho := validHandover(downstream)
			ho.SNI = ""
			done <- handler.Serve(context.Background(), ho)
		}()
		br := bufio.NewReader(client)

		writeRequest(t, client, "GET /one HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
		_ = readBody(t, mustReadResponse(t, br, nil))
		writeRequest(t, client, "GET /two HTTP/1.1\r\nHost: other.example.com\r\n\r\n")
		_ = readBody(t, mustReadResponse(t, br, nil))
		client.Close()

		if dialer.callCount() != 2 {
			t.Fatalf("dial attempts = %d, want 2", dialer.callCount())
		}
		waitServeDone(t, done)
	})

	t.Run("credential identity change forces redial", func(t *testing.T) {
		sink := &recordingSink{}
		var acquireCalls atomic.Int64
		dialer := &scriptedDialer{
			fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
				handlerConn, upstreamConn := net.Pipe()
				go func() {
					defer upstreamConn.Close()
					if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
						t.Errorf("http.ReadRequest() error = %v", err)
						return
					}
					_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
				}()
				return handlerConn, nil
			},
		}
		p := pipeline.NewPipeline(stageSlice(
			stageFunc{name: "match", fn: func(rc *pipeline.RequestContext) pipeline.Decision { return pipeline.Allow() }},
			stageFunc{name: "acquire", fn: func(rc *pipeline.RequestContext) pipeline.Decision {
				if acquireCalls.Add(1) == 1 {
					rc.TokenResult = token.TokenResult{Resolved: token.ResolvedCredential{Identity: "cred-1"}}
				} else {
					rc.TokenResult = token.TokenResult{Resolved: token.ResolvedCredential{Identity: "cred-2"}}
				}
				return pipeline.Allow()
			}},
		), sink)
		handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, p, DefaultOptions())

		downstream, client := net.Pipe()
		done := serveHandler(t, handler, downstream)
		br := bufio.NewReader(client)

		writeRequest(t, client, "GET /one HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
		_ = readBody(t, mustReadResponse(t, br, nil))
		writeRequest(t, client, "GET /two HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
		_ = readBody(t, mustReadResponse(t, br, nil))
		client.Close()

		if dialer.callCount() != 2 {
			t.Fatalf("dial attempts = %d, want 2", dialer.callCount())
		}
		waitServeDone(t, done)
	})

	t.Run("port mismatch forces redial", func(t *testing.T) {
		upstream := &upstreamConn{identity: "api.example.com", port: 8443, credID: "cred-1", reusable: true}
		rc := &pipeline.RequestContext{Facts: pipelineFacts("api.example.com", 443)}
		if upstream.reusableFor(rc, validHandover(nil), "cred-1") {
			t.Fatal("reusableFor() = true, want false on port mismatch")
		}
	})
}

func TestProgressDeadlineFiresOnStall(t *testing.T) {
	sink := &recordingSink{}
	metrics := &recordingMetrics{}
	opts := DefaultOptions()
	opts.ProgressDeadline = 80 * time.Millisecond
	opts.UpstreamResponseTimeout = time.Second

	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nO")
				time.Sleep(250 * time.Millisecond)
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, metrics, allowRelayPipeline(sink, "cred-1"), opts)

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)

	writeRequest(t, client, "GET /stall HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	got := readUntilEOF(client)
	client.Close()

	if !strings.Contains(got, "HTTP/1.1 200 OK") {
		t.Fatalf("response = %q, want partial 200 response", got)
	}
	if !metrics.saw("progress_deadline") {
		t.Fatal("RecordDecision did not record progress_deadline")
	}
	waitServeDone(t, done)
}

func TestProgressDeadlineNotFiredOnSlowButSteady(t *testing.T) {
	sink := &recordingSink{}
	metrics := &recordingMetrics{}
	opts := DefaultOptions()
	opts.ProgressDeadline = 80 * time.Millisecond
	opts.UpstreamResponseTimeout = time.Second

	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
				for _, chunk := range []string{"S", "L", "O", "W"} {
					_, _ = io.WriteString(upstreamConn, chunk)
					time.Sleep(20 * time.Millisecond)
				}
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, metrics, allowRelayPipeline(sink, "cred-1"), opts)

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /steady HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if got := readBody(t, mustReadResponse(t, br, nil)); got != "SLOW" {
		t.Fatalf("response body = %q, want SLOW", got)
	}
	client.Close()

	if metrics.saw("progress_deadline") {
		t.Fatal("RecordDecision recorded progress_deadline for slow-but-steady transfer")
	}
	waitServeDone(t, done)
}

func TestProgressDeadlineNotFiredOnSlowResponseHeader(t *testing.T) {
	sink := &recordingSink{}
	metrics := &recordingMetrics{}
	opts := DefaultOptions()
	opts.ProgressDeadline = 80 * time.Millisecond
	opts.UpstreamResponseTimeout = 2 * time.Second

	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				for _, b := range response {
					if _, err := upstreamConn.Write([]byte{b}); err != nil {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, metrics, allowRelayPipeline(sink, "cred-1"), opts)

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)

	writeRequest(t, client, "GET /slow-head HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	if got := readBody(t, mustReadResponse(t, br, nil)); got != "OK" {
		t.Fatalf("response body = %q, want OK", got)
	}
	client.Close()

	if metrics.saw("progress_deadline") {
		t.Fatal("RecordDecision recorded progress_deadline for slow response headers")
	}
	waitServeDone(t, done)
}

func TestWriteRequestHead_TerminatesHeaderBlockWithBlankLine(t *testing.T) {
	req := mustParsedRequest(t, "POST /expect HTTP/1.1\r\nHost: api.example.com\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n")
	var buf bytes.Buffer

	if err := writeRequestHead(&buf, req); err != nil {
		t.Fatalf("writeRequestHead() error = %v", err)
	}
	if !strings.HasSuffix(buf.String(), "\r\n\r\n") {
		t.Fatalf("wire head = %q, want trailing blank line", buf.String())
	}
}

func TestUsesChunkedTransferEncoding_MultiValueEndingChunked(t *testing.T) {
	req := &http.Request{TransferEncoding: []string{"gzip", "chunked"}}

	if !usesChunkedTransferEncoding(req) {
		t.Fatalf("usesChunkedTransferEncoding(%v) = false, want true", req.TransferEncoding)
	}
}

func TestWriteUpstreamRequest_ExpectContinueChunkedPreservesChunkedFraming(t *testing.T) {
	req := mustParsedRequest(t, "POST /expect HTTP/1.1\r\nHost: api.example.com\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n")
	defer req.Body.Close()

	var downstream bytes.Buffer
	var upstream bytes.Buffer
	if err := (&Handler{}).writeUpstreamRequest(&downstream, &upstream, req, true); err != nil {
		t.Fatalf("writeUpstreamRequest() error = %v", err)
	}

	if got := downstream.String(); got != "HTTP/1.1 100 Continue\r\n\r\n" {
		t.Fatalf("downstream = %q, want 100 Continue", got)
	}

	wire := upstream.String()
	if strings.Contains(wire, "Expect:") {
		t.Fatalf("upstream wire = %q, want Expect header stripped", wire)
	}
	if !strings.Contains(wire, "Transfer-Encoding: chunked\r\n") {
		t.Fatalf("upstream wire = %q, want Transfer-Encoding: chunked", wire)
	}
	if !strings.HasSuffix(wire, "\r\n\r\n4\r\ntest\r\n0\r\n\r\n") {
		t.Fatalf("upstream wire = %q, want chunked body framing preserved", wire)
	}
}

func TestIdleTimeoutClosesQuietly(t *testing.T) {
	opts := DefaultOptions()
	opts.IdleTimeout = 20 * time.Millisecond
	sink := &recordingSink{}
	handler := newRelayHandler(t, sink, &scriptedDialer{}, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), opts)

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	client.Close()
	waitServeDone(t, done)
	if sink.count() != 0 {
		t.Fatalf("audit count = %d, want 0", sink.count())
	}
}

func newRelayHandler(t *testing.T, sink *recordingSink, dialer *scriptedDialer, metrics *recordingMetrics, p *pipeline.Pipeline, opts Options) *Handler {
	t.Helper()
	handler, err := NewHandler(p, dialer, sink, metrics, opts)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func allowRelayPipeline(sink pipeline.AuditSink, credID string) *pipeline.Pipeline {
	return pipeline.NewPipeline(stageSlice(
		stageFunc{name: "match", fn: func(rc *pipeline.RequestContext) pipeline.Decision {
			rc.MatchResult.PolicyRef = "rule-1"
			return pipeline.Allow()
		}},
		stageFunc{name: "acquire", fn: func(rc *pipeline.RequestContext) pipeline.Decision {
			rc.TokenResult = token.TokenResult{Resolved: token.ResolvedCredential{Identity: credID}}
			return pipeline.Allow()
		}},
	), sink)
}

func denyPipeline(sink pipeline.AuditSink, reason pipeline.DenyReason) *pipeline.Pipeline {
	return pipeline.NewPipeline(stageSlice(
		stageFunc{name: "match", fn: func(*pipeline.RequestContext) pipeline.Decision {
			return pipeline.Deny(reason, nil)
		}},
		stageFunc{name: "acquire", fn: func(*pipeline.RequestContext) pipeline.Decision {
			return pipeline.Allow()
		}},
	), sink)
}

func serveHandler(t *testing.T, handler *Handler, downstream net.Conn) chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(downstream)) }()
	return done
}

func waitServeDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not return")
	}
}

func mustReadResponse(t *testing.T, br *bufio.Reader, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("http.ReadResponse() error = %v", err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}
	return string(body)
}

func readRawHead(t *testing.T, conn net.Conn) string {
	t.Helper()
	var b strings.Builder
	buf := make([]byte, 1)
	for !strings.Contains(b.String(), "\r\n\r\n") {
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("io.ReadFull() error = %v", err)
		}
		b.WriteByte(buf[0])
	}
	return b.String()
}

func mustReadClientRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("http.ReadRequest() error = %v", err)
	}
	return req
}

func pipelineFacts(identity string, port uint16) policy.RequestFacts {
	return policy.RequestFacts{
		Identity: identity,
		Method:   http.MethodGet,
		Path:     "/",
		Port:     port,
	}
}
