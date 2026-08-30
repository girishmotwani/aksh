package requestpath

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

// writeFailConn fails every downstream write while leaving reads intact, so the
// handler reads a complete request, relays it, receives a valid upstream
// response, and only then fails to deliver it. That is the precise shape of a
// client that vanished mid-response.
type writeFailConn struct {
	net.Conn
	writes atomic.Int32
}

func (c *writeFailConn) Write(b []byte) (int, error) {
	c.writes.Add(1)
	return 0, errors.New("downstream connection gone")
}

// TestRelay_DownstreamWriteFails_RecordsWriteFailedFaultNotAllow pins the
// second defect found by the compliance audit of this branch.
//
// relay only latched a decision when the response write failed because the body
// exceeded the configured limit. Any other write error returned without
// latching and without recording, so the listener's fallback rollup - which
// fires precisely when nothing else recorded - reported the connection as a
// successful allow.
//
// That is the same defect issue #89 is about: a transport fault landing in the
// allow bucket, inflating the allow ratio and hiding a real failure. A response
// that never reached the client is not an allow.
//
// The distinction from the resource-limit branch is deliberate and is asserted
// here: exceeding the body cap is aksh enforcing its own policy (fault=false),
// whereas failing to write to the client is an I/O fault (fault=true).
func TestRelay_DownstreamWriteFails_RecordsWriteFailedFaultNotAllow(t *testing.T) {
	sink := &recordingSink{}
	dialer := &scriptedDialer{
		fn: func(context.Context, netip.AddrPort, string, string) (net.Conn, error) {
			handlerConn, upstreamConn := net.Pipe()
			go func() {
				defer upstreamConn.Close()
				if _, err := http.ReadRequest(bufio.NewReader(upstreamConn)); err != nil {
					return
				}
				_, _ = io.WriteString(upstreamConn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
			}()
			return handlerConn, nil
		},
	}
	metrics := &recordingMetrics{}
	handler := newRelayHandler(t, sink, dialer, metrics, allowRelayPipeline(sink, "cred-1"), DefaultOptions())

	downstream, client := net.Pipe()
	failing := &writeFailConn{Conn: downstream}
	done := serveHandler(t, handler, failing)

	writeRequest(t, client, "GET /resource HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
	// The handler can never deliver the response, so drain until it gives up
	// and closes rather than waiting for bytes that will not arrive.
	_, _ = io.Copy(io.Discard, client)
	client.Close()
	waitServeDone(t, done)

	if failing.writes.Load() == 0 {
		t.Fatal("the handler never attempted a downstream write, so this test did not " +
			"exercise the response-write failure path at all")
	}
	if metrics.count() != 1 {
		t.Fatalf("decisions recorded = %d, want exactly 1: a connection whose response could "+
			"not be delivered must be accounted once", metrics.count())
	}
	if !metrics.saw(pipeline.ReasonWriteFailed.String()) {
		t.Fatalf("recorded decisions = %+v, want reason %q: without this the connection "+
			"latches nothing and the listener rollup reports the fault as an allow (#89)",
			metrics.decisions, pipeline.ReasonWriteFailed.String())
	}
	if !metrics.firstFault() {
		t.Fatal("fault label = false, want true: failing to write the response to the client " +
			"is an I/O fault, unlike the resource-limit branch where aksh deliberately " +
			"enforces its own cap")
	}
}
