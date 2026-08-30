package requestpath

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/dataplane/upstream"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

// countingCloser wraps a reader and counts Close invocations, forwarding the
// close to the wrapped ReadCloser exactly as observed.
type countingCloser struct {
	io.Reader
	closes int
}

func (c *countingCloser) Close() error {
	c.closes++
	return nil
}

// repeatingReader is a synthetic io.Reader that yields the same byte
// endlessly without materialising a buffer proportional to the stream size.
type repeatingReader struct {
	remaining int64
	b         byte
}

func (r *repeatingReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = r.b
	}
	r.remaining -= int64(n)
	return n, nil
}

func TestResponseBodyLimitReader_UnderLimit_ReadsAllBytes(t *testing.T) {
	inner := io.NopCloser(strings.NewReader(strings.Repeat("a", 100)))
	r := newResponseBodyLimitReader(inner, 200)
	n, err := io.Copy(io.Discard, r)
	if n != 100 {
		t.Fatalf("bytes read = %d, want 100", n)
	}
	if err != nil {
		t.Fatalf("io.Copy() error = %v, want nil (EOF absorbed)", err)
	}
	if r.Exceeded() {
		t.Fatal("Exceeded() = true, want false")
	}
}

func TestResponseBodyLimitReader_ExactlyAtLimit_ReadsAllBytes(t *testing.T) {
	const limit = 128
	inner := io.NopCloser(strings.NewReader(strings.Repeat("b", limit)))
	r := newResponseBodyLimitReader(inner, limit)
	n, err := io.Copy(io.Discard, r)
	if n != limit {
		t.Fatalf("bytes read = %d, want %d", n, limit)
	}
	if err != nil {
		t.Fatalf("io.Copy() error = %v, want nil at exactly the limit", err)
	}
	if r.Exceeded() {
		t.Fatal("Exceeded() = true at exactly the limit, want false")
	}
}

func TestResponseBodyLimitReader_OverLimit_ReturnsErrResponseBodyTooLarge(t *testing.T) {
	const limit = 64
	inner := io.NopCloser(strings.NewReader(strings.Repeat("c", limit+1)))
	r := newResponseBodyLimitReader(inner, limit)
	_, err := io.Copy(io.Discard, r)
	if !errors.Is(err, ErrResponseBodyTooLarge) {
		t.Fatalf("io.Copy() error = %v, want ErrResponseBodyTooLarge", err)
	}
	if !r.Exceeded() {
		t.Fatal("Exceeded() = false after breach, want true")
	}
}

func TestResponseBodyLimitReader_Close_ClosesUnderlyingBodyExactlyOnce(t *testing.T) {
	spy := &countingCloser{Reader: strings.NewReader("hello")}
	r := newResponseBodyLimitReader(spy, 1024)
	if err := r.Close(); err != nil {
		t.Fatalf("first Close() error = %v, want nil", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close() error = %v, want nil", err)
	}
	if spy.closes != 1 {
		t.Fatalf("underlying Close count = %d, want 1", spy.closes)
	}
}

func TestResponseBodyLimitReader_O1Memory_LargeStreamDoesNotAllocateProportionally(t *testing.T) {
	measure := func(streamLen, limit int64) float64 {
		buf := make([]byte, 32*1024)
		return testing.AllocsPerRun(50, func() {
			r := newResponseBodyLimitReader(io.NopCloser(&repeatingReader{remaining: streamLen, b: 'z'}), limit)
			for {
				_, err := r.Read(buf)
				if err != nil {
					// ErrResponseBodyTooLarge or io.EOF are the expected
					// loop exits; neither is a failure here.
					break
				}
			}
		})
	}

	small := measure(1*1024*1024, 512*1024)
	large := measure(256*1024*1024, 512*1024)
	if diff := math.Abs(small - large); diff > 1 {
		t.Fatalf("allocs/op differ across stream sizes: 1MiB=%v, 256MiB=%v (diff=%v), want size-independent", small, large, diff)
	}
}

func TestResponseBodyLimitReader_Exceeded_ReflectsState(t *testing.T) {
	const limit = 8
	inner := io.NopCloser(strings.NewReader(strings.Repeat("x", limit+4)))
	r := newResponseBodyLimitReader(inner, limit)
	if r.Exceeded() {
		t.Fatal("Exceeded() = true before any read, want false")
	}
	buf := make([]byte, limit+4)
	for {
		if _, err := r.Read(buf); err != nil {
			break
		}
	}
	if !r.Exceeded() {
		t.Fatal("Exceeded() = false after breach, want true")
	}
}

func TestResponseBodyLimitReader_MultipleSmallReads_CumulativeCountTriggersBreach(t *testing.T) {
	const limit = 10
	inner := io.NopCloser(strings.NewReader(strings.Repeat("y", limit+1)))
	r := newResponseBodyLimitReader(inner, limit)
	buf := make([]byte, 3)
	var total int
	var breached bool
	for {
		n, err := r.Read(buf)
		total += n
		if errors.Is(err, ErrResponseBodyTooLarge) {
			breached = true
			break
		}
		if err != nil {
			break
		}
	}
	if !breached {
		t.Fatal("cumulative small reads did not trigger ErrResponseBodyTooLarge")
	}
	if total <= limit {
		t.Fatalf("total bytes read = %d, want > %d (breach crosses boundary)", total, limit)
	}
}

func TestResponseBodyLimitReader_ConcurrentReadAndClose_NoRace(t *testing.T) {
	spy := &countingCloser{Reader: &repeatingReader{remaining: 1 << 20, b: 'q'}}
	r := newResponseBodyLimitReader(spy, 1<<24)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			if _, err := r.Read(buf); err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		_ = r.Close()
	}()
	wg.Wait()
}

func TestRelay_ZeroMaxResponseBodyBytes_OptionsValidationRejects(t *testing.T) {
	opts := DefaultOptions()
	opts.MaxResponseBodyBytes = 0
	if err := opts.Validate(); err == nil {
		t.Fatal("Validate() error = nil for MaxResponseBodyBytes=0, want rejection at options time")
	}
	sink := &recordingSink{}
	_, err := NewHandler(
		allowRelayPipeline(sink, "cred-1"),
		&scriptedDialer{},
		sink,
		&recordingMetrics{},
		opts,
	)
	if err == nil {
		t.Fatal("NewHandler() error = nil for MaxResponseBodyBytes=0, want non-nil")
	}
}

func TestRelay_MaxResponseBodyBytesMaxInt64_EffectivelyUnlimited(t *testing.T) {
	inner := io.NopCloser(&repeatingReader{remaining: 4 * 1024 * 1024, b: 'u'})
	r := newResponseBodyLimitReader(inner, math.MaxInt64)
	n, err := io.Copy(io.Discard, r)
	if err != nil {
		t.Fatalf("io.Copy() error = %v, want nil with MaxInt64 limit", err)
	}
	if n != 4*1024*1024 {
		t.Fatalf("bytes read = %d, want %d", n, 4*1024*1024)
	}
	if r.Exceeded() {
		t.Fatal("Exceeded() = true with MaxInt64 limit, want false")
	}
}

func TestErrResponseBodyTooLarge_IsStableSentinel(t *testing.T) {
	wrapped := fmt.Errorf("relay: %w", ErrResponseBodyTooLarge)
	if !errors.Is(wrapped, ErrResponseBodyTooLarge) {
		t.Fatal("errors.Is(wrapped, ErrResponseBodyTooLarge) = false, want true")
	}
	if errors.Is(ErrResponseBodyTooLarge, io.EOF) {
		t.Fatal("ErrResponseBodyTooLarge matches io.EOF, want distinct")
	}
	if errors.Is(ErrResponseBodyTooLarge, upstream.ErrUpstreamConcurrency) {
		t.Fatal("ErrResponseBodyTooLarge matches upstream.ErrUpstreamConcurrency, want distinct")
	}
}

// countDecision reports how many recorded decisions match both disposition
// and reason. It complements recordingMetrics.saw, which only tests
// existence by reason.
func (m *recordingMetrics) countDecision(disposition, reason string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := 0
	for _, d := range m.decisions {
		if d.disposition == disposition && d.reason == reason {
			c++
		}
	}
	return c
}

// overLimitUpstreamDialer returns a dialer whose fake upstream reads one
// request then writes a 200 response whose body (64 bytes) exceeds any small
// cap, then blocks until the handler closes the connection.
func overLimitUpstreamDialer(t *testing.T) *scriptedDialer {
	t.Helper()
	return &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				br := bufio.NewReader(upstreamConn)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n"+strings.Repeat("Z", 64))
				buf := make([]byte, 1)
				_, _ = upstreamConn.Read(buf)
				_ = upstreamConn.Close()
			}()
			return handlerConn, nil
		},
	}
}

func TestRelay_UnderLimitResponse_RelaysFullyAndPreservesReuse(t *testing.T) {
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
		t.Fatalf("dial attempts = %d, want 1 (upstream reused under limit)", dialer.callCount())
	}
	waitServeDone(t, done)
}

func TestRelay_OverLimitResponse_ClosesUpstreamAndDownstream(t *testing.T) {
	sink := &recordingSink{}
	upClosed := make(chan struct{})
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				br := bufio.NewReader(upstreamConn)
				if _, err := http.ReadRequest(br); err != nil {
					t.Errorf("http.ReadRequest() error = %v", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n"+strings.Repeat("Z", 64))
				buf := make([]byte, 1)
				_, _ = upstreamConn.Read(buf) // unblocks when the handler closes upstream
				_ = upstreamConn.Close()
				close(upClosed)
			}()
			return handlerConn, nil
		},
	}
	opts := DefaultOptions()
	opts.MaxResponseBodyBytes = 4
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), opts)

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	writeRequestAsync(client, "GET /big HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	got := readUntilEOF(client)

	if !strings.Contains(got, "HTTP/1.1 200 OK") {
		t.Fatalf("response = %q, want a partial 200 header before the abort", got)
	}
	select {
	case <-upClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream connection was not closed after cap breach")
	}
	if _, err := client.Write([]byte("x")); err == nil {
		t.Fatal("downstream write succeeded after cap breach, want closed connection")
	}
	waitServeDone(t, done)
}

func TestRelay_OverLimitResponse_RecordsMetric(t *testing.T) {
	sink := &recordingSink{}
	metrics := &recordingMetrics{}
	dialer := overLimitUpstreamDialer(t)
	opts := DefaultOptions()
	opts.MaxResponseBodyBytes = 4
	handler := newRelayHandler(t, sink, dialer, metrics, allowRelayPipeline(sink, "cred-1"), opts)

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	writeRequestAsync(client, "GET /big HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	_ = readUntilEOF(client)
	client.Close()
	waitServeDone(t, done)

	if got := metrics.countDecision("deny", "resource_limit"); got != 1 {
		t.Fatalf("Decisions(deny, resource_limit) count = %d, want 1", got)
	}
}

func TestRelay_OverLimitResponse_UpstreamNotReusable(t *testing.T) {
	sink := &recordingSink{}
	dialer := overLimitUpstreamDialer(t)
	opts := DefaultOptions()
	opts.MaxResponseBodyBytes = 4
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), opts)

	downstream, client := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, client) }()

	cs := &connState{ho: validHandover(downstream)}
	req := mustReadClientRequest(t, "GET /big HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	rc := &pipeline.RequestContext{Request: req, Facts: pipelineFacts("api.example.com", 443)}

	if handler.relay(context.Background(), cs, rc, false) {
		t.Fatal("relay() = true, want false on cap breach")
	}
	if cs.upstream != nil {
		t.Fatal("cs.upstream != nil after breach, want nil (breached upstream is never reused)")
	}
	downstream.Close()
}

func TestRelay_WrapperAssignedBeforeDefer_SingleClose(t *testing.T) {
	spy := &countingCloser{Reader: strings.NewReader(strings.Repeat("a", 16))}
	resp := &http.Response{Body: spy}

	// Mirror relay.go's ordering exactly: wrap first, assign to resp.Body,
	// then a single deferred Close targets the wrapper (which transitively
	// closes the original body once).
	limited := newResponseBodyLimitReader(resp.Body, 1024)
	resp.Body = limited
	func() {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}()

	if spy.closes != 1 {
		t.Fatalf("underlying body Close count = %d, want exactly 1", spy.closes)
	}
}

func TestRelay_ProgressDeadlineStillFires_WithCapWrapper(t *testing.T) {
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
		t.Fatal("progress deadline did not fire with the cap wrapper present")
	}
	waitServeDone(t, done)
}
