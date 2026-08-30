package requestpath

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func FuzzReadAndValidate(f *testing.F) {
	for _, seed := range []string{
		"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
		"POST /upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Length:1\r\n\r\nX",
		"POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
		"GET /a%2Fb HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: api.example.com\r\nExpect: 100-continue\r\nContent-Length:1\r\n\r\nX",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if err := readAndValidateFuzzCase(data, parseFuzzRequest); err != nil {
			t.Fatal(err)
		}
	})
}

func TestWithParsedFuzzRequest_ClosesParsedBodies(t *testing.T) {
	parser := &trackingFuzzParser{}

	if err := withParsedFuzzRequest(nil, parser.parse, func(*http.Request) error {
		return withParsedFuzzRequest(nil, parser.parse, func(*http.Request) error {
			return nil
		})
	}); err != nil {
		t.Fatalf("withParsedFuzzRequest() error = %v", err)
	}
	if len(parser.bodies) != 2 {
		t.Fatalf("tracked bodies = %d, want 2", len(parser.bodies))
	}
	for i, body := range parser.bodies {
		if !body.closed {
			t.Fatalf("body %d was not closed", i)
		}
	}
}

func TestReadAndValidateFuzzCase_ReparseErrorReturned(t *testing.T) {
	wantErr := errors.New("reparse failed")
	parser := &reparseFailingFuzzParser{err: wantErr}

	err := readAndValidateFuzzCase([]byte("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"), parser.parse)
	if !errors.Is(err, wantErr) {
		t.Fatalf("readAndValidateFuzzCase() error = %v, want %v", err, wantErr)
	}
}

func TestReadAndValidateFuzzCase_InitialParseErrorIgnored(t *testing.T) {
	wantErr := errors.New("initial parse failed")
	parse := func([]byte) (*http.Request, error) {
		return nil, wantErr
	}

	if err := readAndValidateFuzzCase([]byte("not a request"), parse); err != nil {
		t.Fatalf("readAndValidateFuzzCase() error = %v, want nil", err)
	}
}

func TestReadAndValidateFuzzCase_BodyReadErrorIgnored(t *testing.T) {
	data := []byte("0 / HTTP/1.1\r\nHost:0\r\nTransfer-Encoding:chunked\r\n\r\n")

	if err := readAndValidateFuzzCase(data, parseFuzzRequest); err != nil {
		t.Fatalf("readAndValidateFuzzCase() error = %v, want nil", err)
	}
}

func FuzzScanRawHead(f *testing.F) {
	for _, seed := range []string{
		"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
		"GET / HTTP/1.1\nHost: api.example.com\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: api.example.com\rX-Test: value\r\n\r\n",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		rejection := ScanRawHead(data)
		if requiresScannerRejection(data) && rejection == nil {
			t.Fatalf("ScanRawHead() = nil for scanner-mandated rejection input %q", data)
		}
	})
}

func extractFuzzHead(data []byte) []byte {
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil
	}
	return data[:idx+4]
}

func requiresScannerRejection(data []byte) bool {
	head := extractFuzzHead(data)
	if len(head) == 0 {
		return false
	}
	return hasBareCR(head) || hasBareLF(head) || duplicateHostHeaders(data)
}

func TestRequiresScannerRejection_IgnoresBodyBytesAfterHead(t *testing.T) {
	data := []byte("POST / HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\n\r\nA\n")
	if requiresScannerRejection(data) {
		t.Fatalf("requiresScannerRejection(%q) = true, want false", data)
	}
}

func hasBareCR(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] == '\r' && (i+1 >= len(data) || data[i+1] != '\n') {
			return true
		}
	}
	return false
}

func hasBareLF(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' && (i == 0 || data[i-1] != '\r') {
			return true
		}
	}
	return false
}

func duplicateHostHeaders(data []byte) bool {
	head := extractFuzzHead(data)
	if len(head) == 0 {
		return false
	}
	requestLine, _, ok := bytes.Cut(head, []byte("\r\n"))
	if !ok || bytes.Count(requestLine, []byte(" ")) < 2 {
		return false
	}
	count := 0
	for _, line := range strings.Split(string(head), "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			count++
		}
	}
	return count > 1
}

type fuzzRequestParser func([]byte) (*http.Request, error)

func parseFuzzRequest(data []byte) (*http.Request, error) {
	return http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
}

func readAndValidateFuzzCase(data []byte, parse fuzzRequestParser) error {
	return withParsedFuzzRequest(data, parse, func(req *http.Request) error {
		head := extractFuzzHead(data)
		if len(head) == 0 {
			return nil
		}
		if rejection := Validate(req, head, Handover{}, DefaultOptions()); rejection != nil {
			return nil
		}
		bodyBytes, bodyReady, err := materializeFuzzRequestBody(req)
		if err != nil {
			return nil
		}

		outgoing := cloneRequest(req)
		if bodyReady {
			outgoing.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		outgoing.RequestURI = ""

		var serialized bytes.Buffer
		if err := outgoing.Write(&serialized); err != nil {
			return err
		}
		normalizedHead := normalizeSerializedContentLengthHead(serialized.Bytes())

		return withParsedFuzzRequestStrict(serialized.Bytes(), parse, func(reparsed *http.Request) error {
			if rejection := Validate(reparsed, normalizedHead, Handover{}, DefaultOptions()); rejection != nil {
				return fmt.Errorf("reparsed request was rejected: %+v\nserialized=%q", rejection, serialized.Bytes())
			}
			return nil
		})
	})
}

func closeRequestBody(req *http.Request) {
	if req == nil || req.Body == nil {
		return
	}
	_ = req.Body.Close()
}

func materializeFuzzRequestBody(req *http.Request) ([]byte, bool, error) {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return nil, false, nil
	}

	bodyBytes, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		req.Body = http.NoBody
		return nil, false, err
	}

	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, true, nil
}

func withParsedFuzzRequest(data []byte, parse fuzzRequestParser, fn func(*http.Request) error) error {
	req, err := parse(data)
	if err != nil {
		return nil
	}
	defer closeRequestBody(req)
	return fn(req)
}

func withParsedFuzzRequestStrict(data []byte, parse fuzzRequestParser, fn func(*http.Request) error) error {
	req, err := parse(data)
	if err != nil {
		return err
	}
	defer closeRequestBody(req)
	return fn(req)
}

// normalizeSerializedContentLengthHead rewrites the serialized Content-Length
// header's leading OWS to match ScanRawHead's expectations. Only
// Content-Length is normalized here: other headers written by
// http.Request.Write use a fixed, singular canonical format (no OWS
// variance) so they do not need equivalent handling. If a future header type
// gains configurable OWS-tolerant serialization, extend this normalization.
func normalizeSerializedContentLengthHead(data []byte) []byte {
	head := extractFuzzHead(data)
	if len(head) == 0 {
		return nil
	}

	lines := strings.Split(string(head[:len(head)-4]), "\r\n")
	for i := 1; i < len(lines); i++ {
		name, value, ok := strings.Cut(lines[i], ":")
		if !ok || !strings.EqualFold(name, "Content-Length") {
			continue
		}
		lines[i] = name + ":" + strings.TrimLeft(value, " \t")
	}
	return []byte(strings.Join(lines, "\r\n") + "\r\n\r\n")
}

type trackingFuzzParser struct {
	bodies []*trackingReadCloser
}

func (p *trackingFuzzParser) parse(data []byte) (*http.Request, error) {
	body := &trackingReadCloser{ReadCloser: io.NopCloser(strings.NewReader("X"))}
	p.bodies = append(p.bodies, body)
	return &http.Request{
		Method:        http.MethodPost,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Host:          "api.example.com",
		Header:        http.Header{},
		URL:           &url.URL{Path: "/upload"},
		ContentLength: 1,
		Body:          body,
	}, nil
}

type trackingReadCloser struct {
	io.ReadCloser
	closed bool
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return r.ReadCloser.Close()
}

type reparseFailingFuzzParser struct {
	err   error
	calls int
}

func (p *reparseFailingFuzzParser) parse(data []byte) (*http.Request, error) {
	p.calls++
	if p.calls > 1 {
		return nil, p.err
	}
	return parseFuzzRequest(data)
}
