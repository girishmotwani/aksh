package requestpath

import (
	"bufio"
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

	iaudit "github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/girishmotwani/aksh/internal/policy"
	"github.com/girishmotwani/aksh/internal/token"
)

type testDialer struct{}

func (testDialer) DialUpstream(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
	return nil, io.EOF
}

type testMetrics struct{ iaudit.NopMetricsRecorder }

type recordingSink struct {
	mu      sync.Mutex
	events  []pipeline.AuditEvent
	headers []string
}

func (s *recordingSink) Record(_ context.Context, ev pipeline.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	return nil
}

func (s *recordingSink) RecordCompletion(ctx context.Context, ev pipeline.AuditEvent) error {
	return s.Record(ctx, ev)
}

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func (s *recordingSink) last() pipeline.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events[len(s.events)-1]
}

type stageFunc struct {
	name string
	fn   func(*pipeline.RequestContext) pipeline.Decision
}

func (s stageFunc) Name() string { return s.name }
func (s stageFunc) Execute(rc *pipeline.RequestContext) pipeline.Decision {
	if s.fn == nil {
		return pipeline.Allow()
	}
	return s.fn(rc)
}

func TestNewHandler_NilPipeline_ReturnsError(t *testing.T) {
	_, err := NewHandler(nil, testDialer{}, &recordingSink{}, testMetrics{}, DefaultOptions())
	if err == nil {
		t.Fatal("NewHandler() error = nil, want non-nil")
	}
}

func TestNewHandler_NilDialer_ReturnsError(t *testing.T) {
	p := pipeline.NewPipeline(nil, &recordingSink{})
	_, err := NewHandler(p, nil, &recordingSink{}, testMetrics{}, DefaultOptions())
	if err == nil {
		t.Fatal("NewHandler() error = nil, want non-nil")
	}
}

func TestNewHandler_NilSink_ReturnsError(t *testing.T) {
	p := pipeline.NewPipeline(nil, &recordingSink{})
	_, err := NewHandler(p, testDialer{}, nil, testMetrics{}, DefaultOptions())
	if err == nil {
		t.Fatal("NewHandler() error = nil, want non-nil")
	}
}

func TestNewHandler_NilMetrics_ReturnsError(t *testing.T) {
	p := pipeline.NewPipeline(nil, &recordingSink{})
	_, err := NewHandler(p, testDialer{}, &recordingSink{}, nil, DefaultOptions())
	if err == nil {
		t.Fatal("NewHandler() error = nil, want non-nil")
	}
}

func TestNewHandler_InvalidOptions_ReturnsErrorFromOptionsValidate(t *testing.T) {
	p := pipeline.NewPipeline(nil, &recordingSink{})
	opts := Options{}
	want := opts.Validate()
	_, err := NewHandler(p, testDialer{}, &recordingSink{}, testMetrics{}, opts)
	if err == nil || err.Error() != want.Error() {
		t.Fatalf("NewHandler() error = %v, want %v", err, want)
	}
}

func TestServe_HandoverNilTLSConn_ClosesBareWithFault(t *testing.T) {
	handler, sink := newHandler(t)
	if err := handler.Serve(context.Background(), Handover{IsTLS: true, OriginalDst: netip.MustParseAddrPort("10.0.0.7:443")}); err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	waitAuditCount(t, sink, 1)
	if !sink.last().Fault {
		t.Fatalf("fault audit count = %d fault=%v, want 1 true", sink.count(), sink.last().Fault)
	}
}

func TestServe_HandoverNotTLS_ClosesBareWithFault(t *testing.T) {
	handler, sink := newHandler(t)
	server, client := net.Pipe()
	defer client.Close()
	if err := handler.Serve(context.Background(), Handover{TLSConn: server, IsTLS: false, OriginalDst: netip.MustParseAddrPort("10.0.0.7:443")}); err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	waitAuditCount(t, sink, 1)
	if !sink.last().Fault {
		t.Fatalf("fault audit count = %d fault=%v, want 1 true", sink.count(), sink.last().Fault)
	}
}

func TestServe_HandoverZeroOriginalDst_ClosesBareWithFault(t *testing.T) {
	handler, sink := newHandler(t)
	server, client := net.Pipe()
	defer client.Close()
	if err := handler.Serve(context.Background(), Handover{TLSConn: server, IsTLS: true}); err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	waitAuditCount(t, sink, 1)
	if !sink.last().Fault {
		t.Fatalf("fault audit count = %d fault=%v, want 1 true", sink.count(), sink.last().Fault)
	}
}

func TestServe_HandoverOriginalDstNotIPv4_ClosesBareWithFault(t *testing.T) {
	handler, sink := newHandler(t)
	server, client := net.Pipe()
	defer client.Close()
	if err := handler.Serve(context.Background(), Handover{TLSConn: server, IsTLS: true, OriginalDst: netip.MustParseAddrPort("[::1]:443")}); err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	waitAuditCount(t, sink, 1)
	if !sink.last().Fault {
		t.Fatalf("fault audit count = %d fault=%v, want 1 true", sink.count(), sink.last().Fault)
	}
}

func TestServe_HandoverOriginalDstPortZero_ClosesBareWithFault(t *testing.T) {
	handler, sink := newHandler(t)
	server, client := net.Pipe()
	defer client.Close()
	if err := handler.Serve(context.Background(), Handover{TLSConn: server, IsTLS: true, OriginalDst: netip.MustParseAddrPort("10.0.0.7:0")}); err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	waitAuditCount(t, sink, 1)
	if !sink.last().Fault {
		t.Fatalf("fault audit count = %d fault=%v, want 1 true", sink.count(), sink.last().Fault)
	}
}

func TestServe_IdleTimeoutBeforeFirstByte_ClosesQuietlyNoAudit(t *testing.T) {
	opts := DefaultOptions()
	opts.IdleTimeout = 20 * time.Millisecond
	handler, sink := newHandlerWithOptions(t, allowPipeline(), opts)
	server, client := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not return after idle timeout")
	}

	if sink.count() != 0 {
		t.Fatalf("audit count = %d, want 0", sink.count())
	}
}

func TestServe_WaitForRequestUnexpectedError_ReturnsError(t *testing.T) {
	handler, _ := newHandler(t)
	errBoom := errors.New("boom")

	err := handler.Serve(context.Background(), Handover{
		TLSConn:     &errorReadConn{readErr: errBoom},
		IsTLS:       true,
		OriginalDst: netip.MustParseAddrPort("10.0.0.7:443"),
		SNI:         "api.example.com",
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("Serve() error = %v, want %v", err, errBoom)
	}
}

func TestServe_AdmissionSlotAvailable_ProceedsToHeadRead(t *testing.T) {
	var calls atomic.Int64
	p := countingPipeline(&calls)
	handler, _ := newHandlerWithOptions(t, p, DefaultOptions())
	server, client := net.Pipe()
	defer client.Close()

	done := make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()
	writeRequest(t, client, "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	client.Close()

	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("pipeline Execute count = %d, want 1", calls.Load())
	}
}

func TestServe_InflightCapReached_RejectsBeforePolicyBareClose(t *testing.T) {
	var calls atomic.Int64
	opts := DefaultOptions()
	opts.MaxInflightRequests = 1
	handler, sink := newHandlerWithOptions(t, countingPipeline(&calls), opts)
	if !handler.limiter.TryAcquire() {
		t.Fatal("pre-acquire limiter slot failed")
	}
	defer handler.limiter.Release()

	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()
	writeRequest(t, client, "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	response := readUntilEOF(client)
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	waitAuditCount(t, sink, 1)
	if len(response) != 0 {
		t.Fatalf("response = %q, want empty", response)
	}
	if sink.last().DenyReason != pipeline.ReasonResourceLimit {
		t.Fatalf("last audit = %+v, want resource_limit rejection", sink.last())
	}
	if calls.Load() != 0 {
		t.Fatalf("pipeline Execute count = %d, want 0", calls.Load())
	}
}

func TestServe_AdmissionRejection_NeverCallsPipelineExecute(t *testing.T) {
	var calls atomic.Int64
	opts := DefaultOptions()
	opts.MaxInflightRequests = 1
	handler, _ := newHandlerWithOptions(t, countingPipeline(&calls), opts)
	if !handler.limiter.TryAcquire() {
		t.Fatal("pre-acquire limiter slot failed")
	}
	defer handler.limiter.Release()

	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()
	writeRequest(t, client, "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	readUntilEOF(client)
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("pipeline Execute count = %d, want 0", calls.Load())
	}
}

func TestServe_EOFBeforeAnyByte_ClosesCleanNoAudit(t *testing.T) {
	handler, sink := newHandler(t)
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()
	client.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	if sink.count() != 0 {
		t.Fatalf("audit count = %d, want 0", sink.count())
	}
}

func TestServe_EOFPartWayThroughHead_Rejected400(t *testing.T) {
	handler, sink := newHandler(t)
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()
	writeRequest(t, client, "GET / HTTP/1.1\r\nHost: api.example.com")
	client.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	waitAuditCount(t, sink, 1)
	if sink.count() != 1 {
		t.Fatalf("audit count = %d, want 1", sink.count())
	}
}

func TestServe_HeadBoundExactBoundary_AcceptedAt65536Bytes(t *testing.T) {
	var calls atomic.Int64
	handler, _ := newHandlerWithOptions(t, countingPipeline(&calls), DefaultOptions())
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()
	writeRequest(t, client, exactBoundHead(t, DefaultOptions().MaxHeaderBytes))
	client.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("pipeline Execute count = %d, want 1", calls.Load())
	}
}

func TestServe_HeadBoundOneByteOver_Rejected431(t *testing.T) {
	handler, _ := newHandler(t)
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()
	writeRequestAsync(client, exactBoundHead(t, DefaultOptions().MaxHeaderBytes+1))
	response := readUntilEOF(client)
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	if !strings.Contains(response, "431") {
		t.Fatalf("response = %q, want 431 status", response)
	}
}

func TestServe_HeadLongSingleLineExceedsBufioBuffer_Rejected431NoHang(t *testing.T) {
	handler, _ := newHandler(t)
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()
	longValue := strings.Repeat("a", DefaultOptions().MaxHeaderBytes)
	writeRequestAsync(client, "GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Long: "+longValue+"\r\n\r\n")
	response := readUntilEOF(client)
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	if !strings.Contains(response, "431") {
		t.Fatalf("response = %q, want 431 status", response)
	}
}

func TestServe_HeadReadTimeoutStalledPartialHead_ClosesBareAudited(t *testing.T) {
	opts := DefaultOptions()
	opts.HeaderReadTimeout = 20 * time.Millisecond
	handler, sink := newHandlerWithOptions(t, allowPipeline(), opts)
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()
	writeRequest(t, client, "GET / HTTP/1.1\r\nHost: api.example.com")
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not return after header timeout")
	}
	waitAuditCount(t, sink, 1)
	if sink.last().DenyReason != pipeline.ReasonResourceLimit {
		t.Fatalf("last audit = %+v, want resource_limit", sink.last())
	}
}

func TestReadRequest_ReturnsCapturedWireRawHead(t *testing.T) {
	handler, _ := newHandler(t)
	server, client := net.Pipe()
	defer server.Close()

	cs := &connState{
		ho:     validHandover(server),
		source: &prependConn{Conn: server},
	}
	cs.guard = NewHeadGuard(cs.source, DefaultOptions().MaxHeaderBytes)
	cs.br = bufio.NewReaderSize(cs.guard, DefaultOptions().MaxHeaderBytes)

	raw := "GET / HTTP/1.1\r\nhOsT: api.example.com\r\nx-test: one\r\n\r\n"
	go func() {
		defer client.Close()
		_, _ = io.WriteString(client, raw)
	}()

	req, rawHead, ok := handler.readRequest(cs)
	if !ok || req == nil {
		t.Fatalf("readRequest() = (%v, %q, %v), want parsed request and ok", req, rawHead, ok)
	}
	if got := string(rawHead); got != raw {
		t.Fatalf("raw head = %q, want %q", got, raw)
	}
}

func TestReadRequest_TrimsBufferedBodyBytesFromRawHead(t *testing.T) {
	handler, _ := newHandler(t)
	server, client := net.Pipe()
	defer server.Close()

	cs := &connState{
		ho:     validHandover(server),
		source: &prependConn{Conn: server},
	}
	cs.guard = NewHeadGuard(cs.source, DefaultOptions().MaxHeaderBytes)
	cs.br = bufio.NewReaderSize(cs.guard, DefaultOptions().MaxHeaderBytes)

	rawHead := "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\n\r\n"
	go func() {
		defer client.Close()
		_, _ = io.WriteString(client, rawHead+"AB")
	}()

	req, captured, ok := handler.readRequest(cs)
	if !ok || req == nil {
		t.Fatalf("readRequest() = (%v, %q, %v), want parsed request and ok", req, captured, ok)
	}
	if got := string(captured); got != rawHead {
		t.Fatalf("raw head = %q, want %q", got, rawHead)
	}
}

func TestServe_SlotReleasedOnEveryRejectionRow_InFlightReturnsZero(t *testing.T) {
	handler, _ := newHandler(t)
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()
	writeRequest(t, client, "GET / HTTP/1.1\r\nHost: api.example.com")
	client.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	if got := handler.limiter.InFlight(); got != 0 {
		t.Fatalf("InFlight() = %d, want 0", got)
	}
}

func TestServe_StageSliceInjectIsLast_LastStageNameIsInject(t *testing.T) {
	stages := stageSlice(nil, nil)
	if got := stages[len(stages)-1].Name(); got != "inject" {
		t.Fatalf("last stage = %q, want inject", got)
	}
}

func TestServe_StageSliceExactlyOneInject_ExactlyOneStageNamedInject(t *testing.T) {
	stages := stageSlice(nil, nil)
	count := 0
	for _, stage := range stages {
		if stage != nil && stage.Name() == "inject" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("inject stage count = %d, want 1", count)
	}
}

func TestServe_AuditPrecedesInjection_SinkCalledBeforeAuthorizationHeaderAppears(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	req.Host = "api.example.com"
	sink := &recordingSink{}
	stages := stageSlice(
		stageFunc{name: "match", fn: func(rc *pipeline.RequestContext) pipeline.Decision {
			rc.MatchResult.PolicyRef = "rule-1"
			return pipeline.Allow()
		}},
		stageFunc{name: "acquire", fn: func(rc *pipeline.RequestContext) pipeline.Decision {
			rc.TokenResult = token.TokenResult{Token: token.NewToken("secret", time.Now().Add(time.Hour))}
			return pipeline.Allow()
		}},
	)
	p := pipeline.NewPipeline(stages, pipeline.AuditSink(auditRecorder(func(_ context.Context, ev pipeline.AuditEvent) error {
		if req.Header.Get("Authorization") != "" {
			t.Fatalf("Authorization header present before audit: %q", req.Header.Get("Authorization"))
		}
		sink.Record(context.Background(), ev)
		return nil
	})))

	rc := &pipeline.RequestContext{
		Request: req,
		Identity: pipeline.IdentityInput{
			SNI:             "api.example.com",
			AuthorityHost:   "api.example.com",
			DestinationPort: 443,
		},
		Transport: policy.TransportTLS,
	}
	decision := p.Execute(context.Background(), rc)
	if !decision.IsAllow() {
		t.Fatalf("Execute() disposition = %v, want allow", decision.Disposition())
	}
	if req.Header.Get("Authorization") == "" {
		t.Fatal("Authorization header missing after inject")
	}
}

func TestServe_ExecuteCalledOncePerRequest_CountingWrapperSeesNCallsForNRequests(t *testing.T) {
	var calls atomic.Int64
	handler, _ := newHandlerWithOptions(t, countingPipeline(&calls), DefaultOptions())

	for range 2 {
		server, client := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()
		writeRequest(t, client, "GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
		client.Close()
		if err := <-done; err != nil {
			t.Fatalf("Serve() error = %v, want nil", err)
		}
	}

	if calls.Load() != 2 {
		t.Fatalf("pipeline Execute count = %d, want 2", calls.Load())
	}
}

type auditRecorder func(context.Context, pipeline.AuditEvent) error

func (f auditRecorder) Record(ctx context.Context, ev pipeline.AuditEvent) error { return f(ctx, ev) }
func (f auditRecorder) RecordCompletion(ctx context.Context, ev pipeline.AuditEvent) error {
	return f(ctx, ev)
}

func newHandler(t *testing.T) (*Handler, *recordingSink) {
	t.Helper()
	return newHandlerWithOptions(t, allowPipeline(), DefaultOptions())
}

func newHandlerWithOptions(t *testing.T, p *pipeline.Pipeline, opts Options) (*Handler, *recordingSink) {
	t.Helper()
	sink := &recordingSink{}
	handler, err := NewHandler(p, testDialer{}, sink, testMetrics{}, opts)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler, sink
}

func allowPipeline() *pipeline.Pipeline {
	return pipeline.NewPipeline([]pipeline.Stage{
		stageFunc{name: "match", fn: func(*pipeline.RequestContext) pipeline.Decision { return pipeline.Allow() }},
	}, &recordingSink{})
}

func countingPipeline(calls *atomic.Int64) *pipeline.Pipeline {
	return pipeline.NewPipeline([]pipeline.Stage{
		stageFunc{name: "count", fn: func(*pipeline.RequestContext) pipeline.Decision {
			calls.Add(1)
			return pipeline.Allow()
		}},
	}, &recordingSink{})
}

func validHandover(conn net.Conn) Handover {
	return Handover{
		TLSConn:     conn,
		IsTLS:       true,
		OriginalDst: netip.MustParseAddrPort("10.0.0.7:443"),
		SNI:         "api.example.com",
	}
}

func writeRequest(t *testing.T, conn net.Conn, raw string) {
	t.Helper()
	if _, err := io.Copy(conn, strings.NewReader(raw)); err != nil && !isBenignPipeClose(err) {
		t.Fatalf("io.Copy() error = %v", err)
	}
}

func writeRequestAsync(conn net.Conn, raw string) {
	go func() {
		_, _ = io.Copy(conn, strings.NewReader(raw))
	}()
}

func readUntilEOF(conn net.Conn) string {
	var b strings.Builder
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.Copy(&b, bufio.NewReader(conn))
	return b.String()
}

func exactBoundHead(t *testing.T, size int) string {
	t.Helper()
	prefix := "GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Pad: "
	suffix := "\r\n\r\n"
	padding := size - len(prefix) - len(suffix)
	if padding < 0 {
		t.Fatalf("size %d too small for fixed head prefix", size)
	}
	return prefix + strings.Repeat("a", padding) + suffix
}

func isBenignPipeClose(err error) bool {
	return errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "closed pipe")
}

type errorReadConn struct {
	readErr error
}

func (c *errorReadConn) Read([]byte) (int, error)       { return 0, c.readErr }
func (*errorReadConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (*errorReadConn) Close() error                     { return nil }
func (*errorReadConn) LocalAddr() net.Addr              { return stubAddr("local") }
func (*errorReadConn) RemoteAddr() net.Addr             { return stubAddr("remote") }
func (*errorReadConn) SetDeadline(time.Time) error      { return nil }
func (*errorReadConn) SetReadDeadline(time.Time) error  { return nil }
func (*errorReadConn) SetWriteDeadline(time.Time) error { return nil }

type stubAddr string

func (a stubAddr) Network() string { return string(a) }
func (a stubAddr) String() string  { return string(a) }

var _ dataplane.UpstreamDialer = testDialer{}
var _ iaudit.AuditSink = (*recordingSink)(nil)

func waitAuditCount(t *testing.T, sink *recordingSink, want int) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		if sink.count() >= want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %d audit events; got %d", want, sink.count())
		default:
			time.Sleep(time.Millisecond)
		}
	}
}
