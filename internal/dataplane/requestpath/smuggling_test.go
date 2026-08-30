package requestpath

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitForUpstreamResult_ReturnsConnectionAndError(t *testing.T) {
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	wantErr := errors.New("boom")
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()

	connCh <- conn
	errCh <- wantErr

	gotConn, gotErr, ok := waitForUpstreamResult(connCh, errCh, 50*time.Millisecond)
	if !ok {
		t.Fatal("waitForUpstreamResult() timed out, want result")
	}
	if gotConn != conn {
		t.Fatalf("waitForUpstreamResult() conn = %v, want %v", gotConn, conn)
	}
	if !errors.Is(gotErr, wantErr) {
		t.Fatalf("waitForUpstreamResult() err = %v, want %v", gotErr, wantErr)
	}
}

func TestWaitForUpstreamResult_TimesOut(t *testing.T) {
	start := time.Now()
	gotConn, gotErr, ok := waitForUpstreamResult(make(chan net.Conn), make(chan error), 20*time.Millisecond)
	if ok {
		t.Fatalf("waitForUpstreamResult() ok = true with conn=%v err=%v, want false", gotConn, gotErr)
	}
	if gotConn != nil {
		t.Fatalf("waitForUpstreamResult() conn = %v, want nil", gotConn)
	}
	if gotErr != nil {
		t.Fatalf("waitForUpstreamResult() err = %v, want nil", gotErr)
	}
	if time.Since(start) < 20*time.Millisecond {
		t.Fatalf("waitForUpstreamResult() returned before timeout elapsed")
	}
}

func TestWaitForUpstreamResult_ClosesTimedOutConnection(t *testing.T) {
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error)
	conn, peer := net.Pipe()
	defer peer.Close()

	connCh <- conn

	gotConn, gotErr, ok := waitForUpstreamResult(connCh, errCh, 20*time.Millisecond)
	if ok {
		t.Fatalf("waitForUpstreamResult() ok = true with conn=%v err=%v, want false", gotConn, gotErr)
	}
	if gotConn != nil {
		t.Fatalf("waitForUpstreamResult() conn = %v, want nil", gotConn)
	}
	if gotErr != nil {
		t.Fatalf("waitForUpstreamResult() err = %v, want nil", gotErr)
	}
	if _, err := peer.Write([]byte("x")); err == nil {
		t.Fatal("peer.Write() succeeded after timeout, want closed conn")
	}
}

func TestSmugglingCLandTE(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
	req := mustParsedRequest(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	req.TransferEncoding = []string{"chunked"}
	assertSmugglingValidateRejects(t, req, raw)
}

func TestSmugglingDuplicateCLDiffers(t *testing.T) {
	assertSmugglingScanRejects(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
}

func TestSmugglingDuplicateCLSame(t *testing.T) {
	assertSmugglingScanRejects(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n")
}

func TestSmugglingCLLeadingZeros(t *testing.T) {
	assertSmugglingScanRejects(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0100\r\n\r\n")
}

func TestSmugglingCLPlusSign(t *testing.T) {
	assertSmugglingScanRejects(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: +5\r\n\r\n")
}

func TestSmugglingCLHex(t *testing.T) {
	assertSmugglingServe400(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0x10\r\n\r\n")
}

func TestSmugglingCLNegative(t *testing.T) {
	assertSmugglingServe400(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: -1\r\n\r\n")
}

func TestSmugglingTEDoubleChunked(t *testing.T) {
	assertSmugglingScanRejects(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked, chunked\r\n\r\n")
}

func TestSmugglingTETwoLines(t *testing.T) {
	assertSmugglingScanRejects(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n")
}

func TestSmugglingTEIdentity(t *testing.T) {
	assertSmugglingScanRejects(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: identity\r\n\r\n")
}

func TestSmugglingTESpaceBeforeColon(t *testing.T) {
	assertSmugglingScanRejects(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding : chunked\r\n\r\n")
}

func TestSmugglingTEObsFold(t *testing.T) {
	assertSmugglingScanRejects(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding:\tchunked\r\n folded\r\n\r\n")
}

func TestSmugglingTENearMiss(t *testing.T) {
	assertSmugglingScanRejects(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: xchunked\r\n\r\n")
	assertSmugglingScanRejects(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunkedx\r\n\r\n")
}

func TestSmugglingControlInName(t *testing.T) {
	assertSmugglingScanRejects(t, "GET / HTTP/1.1\r\nHost: api.example.com\r\nBad\x00Name: value\r\n\r\n")
}

func TestSmugglingBareCRInValue(t *testing.T) {
	assertSmugglingScanRejects(t, "GET / HTTP/1.1\r\nHost: api.example.com\r\nX-Test: abc\rdef\r\n\r\n")
}

func TestSmugglingBareLF(t *testing.T) {
	assertSmugglingScanRejects(t, "GET / HTTP/1.1\r\nHost: api.example.com\nX-Test: value\r\n\r\n")
}

func TestSmugglingRequestLineBareLF(t *testing.T) {
	assertSmugglingScanRejects(t, "GET / HTTP/1.1\nHost: api.example.com\r\n\r\n")
}

func TestSmugglingDuplicateHost(t *testing.T) {
	assertSmugglingScanRejects(t, "GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n")
}

func TestSmugglingAbsentHost(t *testing.T) {
	assertSmugglingScanRejects(t, "GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n")
}

func TestSmugglingAbsoluteFormConflict(t *testing.T) {
	raw := "GET https://api.example.com/path HTTP/1.1\r\nHost: other.example.com\r\n\r\n"
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/path", nil)
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	req.Host = "other.example.com"
	assertSmugglingValidateRejects(t, req, raw)
}

func TestSmugglingChunkExtension(t *testing.T) {
	assertSmugglingServeTerminates(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n1;evil=1\r\na\r\n0\r\n\r\n")
}

func TestSmugglingChunkSizeOddities(t *testing.T) {
	assertSmugglingServeTerminates(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n01\r\na\r\n0\r\n\r\n")
	assertSmugglingServeTerminates(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\n\r\n+1\r\na\r\n0\r\n\r\n")
}

func TestSmugglingExcessBodyIsPipelining(t *testing.T) {
	sink := &recordingSink{}
	upstreamErrCh := make(chan error, 1)
	upstreamConnCh := make(chan net.Conn, 1)
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			upstreamConnCh <- upstreamConn
			go func() {
				defer upstreamConn.Close()
				_ = upstreamConn.SetReadDeadline(time.Now().Add(2 * time.Second))
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					upstreamErrCh <- fmt.Errorf("http.ReadRequest() error = %w", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
				upstreamErrCh <- nil
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), fastFailureOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	go func() {
		_, _ = io.WriteString(client, "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 1\r\n\r\nABGET /next HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	}()
	got := readUntilEOF(client)
	client.Close()

	if strings.Contains(got, "HTTP/1.1 200 OK") {
		t.Fatalf("response = %q, want termination before a second successful response", got)
	}
	waitServeDone(t, done)
	upstreamConn, err, ok := waitForUpstreamResult(upstreamConnCh, upstreamErrCh, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for upstream verification")
	}
	if upstreamConn != nil {
		_ = upstreamConn.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestSmugglingShortBody(t *testing.T) {
	sink := &recordingSink{}
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				req, err := http.ReadRequest(bufio.NewReader(upstreamConn))
				if err != nil {
					return
				}
				if req.Body != nil {
					_, _ = io.Copy(io.Discard, req.Body)
					_ = req.Body.Close()
				}
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	defer ln.Close()
	acceptCh := make(chan net.Conn, 1)
	acceptErrCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			acceptErrCh <- err
			return
		}
		acceptCh <- conn
	}()
	rawClient, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() error = %v", err)
	}
	client, ok := rawClient.(*net.TCPConn)
	if !ok {
		rawClient.Close()
		t.Fatal("client is not *net.TCPConn")
	}
	defer client.Close()

	var downstream net.Conn
	select {
	case downstream = <-acceptCh:
	case err := <-acceptErrCh:
		t.Fatalf("Accept() error = %v", err)
	}
	done := serveHandler(t, handler, downstream)
	_, _ = io.WriteString(client, "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 4\r\n\r\nAB")
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	got := readUntilEOF(client)
	client.Close()

	if strings.Contains(got, "403 Forbidden") || strings.Contains(got, "400 Bad Request") {
		t.Fatalf("response = %q, want bare completion close", got)
	}
	waitServeDone(t, done)
}

func TestPipeliningRejected(t *testing.T) {
	sink := &recordingSink{}
	upstreamErrCh := make(chan error, 1)
	upstreamConnCh := make(chan net.Conn, 1)
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			upstreamConnCh <- upstreamConn
			go func() {
				defer upstreamConn.Close()
				_ = upstreamConn.SetReadDeadline(time.Now().Add(2 * time.Second))
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					upstreamErrCh <- fmt.Errorf("http.ReadRequest() error = %w", err)
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
				upstreamErrCh <- nil
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	go func() {
		_, _ = io.WriteString(client, "GET /one HTTP/1.1\r\nHost: api.example.com\r\n\r\nGET /two HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	}()
	got := readUntilEOF(client)
	client.Close()

	if !strings.Contains(got, "HTTP/1.1 400 Bad Request") {
		t.Fatalf("response = %q, want 400 pipelining rejection", got)
	}
	waitServeDone(t, done)
	upstreamConn, err, ok := waitForUpstreamResult(upstreamConnCh, upstreamErrCh, 2*time.Second)
	if !ok {
		t.Fatal("timed out waiting for upstream verification")
	}
	if upstreamConn != nil {
		_ = upstreamConn.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestSmugglingBodyOnBodylessMethod(t *testing.T) {
	assertSmugglingServe400(t, "GET / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 1\r\n\r\nX")
}

func TestHeadBoundExactBoundary(t *testing.T) {
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

	handler, _ = newHandler(t)
	server, client = net.Pipe()
	defer client.Close()
	done = make(chan error, 1)
	go func() { done <- handler.Serve(context.Background(), validHandover(server)) }()
	writeRequestAsync(client, exactBoundHead(t, DefaultOptions().MaxHeaderBytes+1))
	got := readUntilEOF(client)
	if err := <-done; err != nil {
		t.Fatalf("Serve() error = %v, want nil", err)
	}
	if !strings.Contains(got, "431") {
		t.Fatalf("response = %q, want 431", got)
	}
}

func TestExpectContinueOrdering(t *testing.T) {
	sink := &recordingSink{}
	continueSeen := make(chan struct{}, 1)
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				_, _ = io.Copy(io.Discard, upstreamConn)
			}()
			return handlerConn, nil
		},
	}
	handler := newRelayHandler(t, sink, dialer, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	br := bufio.NewReader(client)
	headCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		if _, err := io.WriteString(client, "POST /expect HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n"); err != nil {
			errCh <- err
			return
		}
		head, err := readResponseHead(br)
		if err != nil {
			errCh <- err
			return
		}
		headCh <- head
	}()

	select {
	case err := <-errCh:
		t.Fatalf("reading continue response: %v", err)
	case head := <-headCh:
		if strings.Contains(head, "100 Continue") {
			continueSeen <- struct{}{}
		}
	case <-time.After(time.Second):
		t.Fatal("downstream 100 Continue was not written")
	}
	client.Close()
	waitServeDone(t, done)
}

func TestTrailerCredentialRejected(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: api.example.com\r\nTransfer-Encoding: chunked\r\nTrailer: Authorization\r\n\r\n"
	req := mustParsedRequest(t, raw)
	assertSmugglingValidateRejects(t, req, raw)
}

func TestSmugglingCLPadded(t *testing.T) {
	assertSmugglingScanRejects(t, "POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length:  5  \r\n\r\n")
}

func mustParsedRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("http.ReadRequest() error = %v", err)
	}
	return req
}

func readResponseHead(br *bufio.Reader) (string, error) {
	var b strings.Builder
	for !strings.Contains(b.String(), "\r\n\r\n") {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		b.WriteString(line)
	}
	return b.String(), nil
}

func assertSmugglingScanRejects(t *testing.T, raw string) {
	t.Helper()
	rejection := ScanRawHead([]byte(raw))
	if rejection == nil {
		t.Fatal("ScanRawHead() = nil, want rejection")
	}
	assertT5400(t, rejection)
}

func assertSmugglingValidateRejects(t *testing.T, req *http.Request, raw string) {
	t.Helper()
	rejection := Validate(req, []byte(raw), Handover{}, DefaultOptions())
	if rejection == nil {
		t.Fatal("Validate() = nil, want rejection")
	}
	assertT5400(t, rejection)
}

func assertSmugglingServe400(t *testing.T, raw string) {
	t.Helper()
	sink := &recordingSink{}
	handler := newRelayHandler(t, sink, &scriptedDialer{fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
		handlerConn, upstreamConn := net.Pipe()
		go func() {
			defer upstreamConn.Close()
			_, _ = io.Copy(io.Discard, upstreamConn)
		}()
		return handlerConn, nil
	}}, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), fastFailureOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	writeRequestAsync(client, raw)
	got := readUntilEOF(client)
	client.Close()

	if !strings.Contains(got, "HTTP/1.1 400 Bad Request") {
		t.Fatalf("response = %q, want 400", got)
	}
	waitServeDone(t, done)
}

func assertSmugglingServeTerminates(t *testing.T, raw string) {
	t.Helper()
	sink := &recordingSink{}
	handler := newRelayHandler(t, sink, &scriptedDialer{fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
		handlerConn, upstreamConn := net.Pipe()
		go func() {
			defer upstreamConn.Close()
			_, _ = io.Copy(io.Discard, upstreamConn)
		}()
		return handlerConn, nil
	}}, &recordingMetrics{}, allowRelayPipeline(sink, "cred-1"), fastFailureOptions())

	downstream, client := net.Pipe()
	done := serveHandler(t, handler, downstream)
	writeRequestAsync(client, raw)
	_ = readUntilEOF(client)
	client.Close()
	waitServeDone(t, done)
}

func assertT5400(t *testing.T, rejection *Rejection) {
	t.Helper()
	if rejection.Class != ClassT5 {
		t.Fatalf("Class = %q, want %q", rejection.Class, ClassT5)
	}
	if rejection.Wire != WireWrite400Close {
		t.Fatalf("Wire = %v, want %v", rejection.Wire, WireWrite400Close)
	}
	if rejection.Status != http.StatusBadRequest {
		t.Fatalf("Status = %d, want 400", rejection.Status)
	}
}

func waitForUpstreamResult(connCh <-chan net.Conn, errCh <-chan error, timeout time.Duration) (net.Conn, error, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case conn := <-connCh:
		select {
		case err := <-errCh:
			return conn, err, true
		case <-timer.C:
			_ = conn.Close()
			return nil, nil, false
		}
	case <-timer.C:
		return nil, nil, false
	}
}

func fastFailureOptions() Options {
	opts := DefaultOptions()
	opts.UpstreamResponseTimeout = 20 * time.Millisecond
	opts.ProgressDeadline = 40 * time.Millisecond
	return opts
}
