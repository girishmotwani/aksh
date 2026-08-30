package listener_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

type metricsSpy struct {
	audit.NopMetricsRecorder
	mu        sync.Mutex
	decisions []decisionCall
}

type decisionCall struct {
	disposition string
	reason      string
	identity    string
	transport   audit.TransportKind
	fault       bool
}

func (m *metricsSpy) Decisions(d pipeline.Disposition, r pipeline.DenyReason, transport audit.TransportKind, fault bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions = append(m.decisions, decisionCall{disposition: d.String(), reason: r.String(), transport: transport, fault: fault})
}

func TestDiscriminator(t *testing.T) {
	t.Run("Classify_FrozenBehaviourPeekSize_Reads24BytesWithoutConsuming", func(t *testing.T) {
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		conn := newScriptedConn(tlsClientHelloPrefix())
		proto, replay, err := disc.Classify(conn)
		if err != nil {
			t.Fatalf("Classify() error = %v, want nil", err)
		}
		if proto != listener.ProtocolTLS {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolTLS)
		}
		buf := make([]byte, listener.PeekSize)
		if _, err := io.ReadFull(replay, buf); err != nil {
			t.Fatalf("ReadFull() error = %v, want nil", err)
		}
		if !bytes.Equal(buf, tlsClientHelloPrefix()[:listener.PeekSize]) {
			t.Fatalf("replayed bytes = %q, want original prefix", buf)
		}
	})

	t.Run("Classify_TLSClientHello_ReturnsProtocolTLS", func(t *testing.T) {
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		proto, _, err := disc.Classify(newScriptedConn(tlsClientHelloPrefix()))
		if err != nil {
			t.Fatalf("Classify() error = %v, want nil", err)
		}
		if proto != listener.ProtocolTLS {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolTLS)
		}
	})

	t.Run("Classify_HTTP1RequestLine_ReturnsProtocolHTTP1", func(t *testing.T) {
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		proto, _, err := disc.Classify(newScriptedConn([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")))
		if err != nil {
			t.Fatalf("Classify() error = %v, want nil", err)
		}
		if proto != listener.ProtocolHTTP1 {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolHTTP1)
		}
	})

	t.Run("Classify_H2CPreface_ReturnsProtocolH2CPreface", func(t *testing.T) {
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		proto, _, err := disc.Classify(newScriptedConn([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")))
		if err != nil {
			t.Fatalf("Classify() error = %v, want nil", err)
		}
		if proto != listener.ProtocolH2CPreface {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolH2CPreface)
		}
	})

	t.Run("Classify_UnrecognisedBytePattern_ReturnsProtocolUnknown", func(t *testing.T) {
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		proto, _, err := disc.Classify(newScriptedConn([]byte{0xde, 0xad, 0xbe, 0xef}))
		if err != nil {
			t.Fatalf("Classify() error = %v, want nil", err)
		}
		if proto != listener.ProtocolUnknown {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolUnknown)
		}
	})

	t.Run("Classify_ConnectionClosesBeforeFullPeek_ReturnsProtocolUnknownNotError", func(t *testing.T) {
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		proto, _, err := disc.Classify(newScriptedConn([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n")))
		if err != nil {
			t.Fatalf("Classify() error = %v, want nil", err)
		}
		if proto != listener.ProtocolUnknown {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolUnknown)
		}
	})

	t.Run("Classify_NonTimeoutPeekError_ReturnsErrorNotProtocolUnknown", func(t *testing.T) {
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		conn := &failingReadConn{readErr: errors.New("connection reset by peer")}
		proto, replay, err := disc.Classify(conn)
		if err == nil {
			t.Fatalf("Classify() error = nil, want non-nil for a non-timeout peek failure")
		}
		if errors.Is(err, listener.ErrPeekTimeout) {
			t.Fatalf("Classify() error = %v, want a distinct error from ErrPeekTimeout", err)
		}
		if proto != listener.ProtocolUnknown {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolUnknown)
		}
		if replay != nil {
			t.Fatalf("Classify() replay = %v, want nil on peek failure", replay)
		}
	})

	t.Run("Classify_PeekErrorThenDeadlineClearFails_OriginalErrorNotMasked", func(t *testing.T) {
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		conn := &deadlineClearFailsConn{readErr: errors.New("connection reset by peer")}
		_, _, err := disc.Classify(conn)
		if err == nil {
			t.Fatalf("Classify() error = nil, want the original peek error to surface")
		}
		if errors.Is(err, listener.ErrSetDeadlineFailed) {
			t.Fatalf("Classify() error = %v, want original peek error, not masked by deadline-clear failure", err)
		}
	})

	t.Run("Classify_EmptyByteConnection_ReturnsProtocolUnknown", func(t *testing.T) {
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		proto, _, err := disc.Classify(newScriptedConn(nil))
		if err != nil {
			t.Fatalf("Classify() error = %v, want nil", err)
		}
		if proto != listener.ProtocolUnknown {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolUnknown)
		}
	})

	t.Run("Classify_NilConn_ReturnsErrMissingConn", func(t *testing.T) {
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		if _, _, err := disc.Classify(nil); err != listener.ErrMissingConn {
			t.Fatalf("Classify(nil) error = %v, want %v", err, listener.ErrMissingConn)
		}
	})

	t.Run("PeekedConn_Read_ReturnsBufferedBytesBeforeUnderlyingConn", func(t *testing.T) {
		pc := listener.NewPeekedConn(newScriptedConn([]byte("abcdefghijklmnopqrstuvwxyz")), []byte("abc"))
		buf := make([]byte, 5)
		if n, err := pc.Read(buf); err != nil || n != 5 {
			t.Fatalf("Read() = (%d, %v), want (5, nil)", n, err)
		}
		if string(buf) != "abcde" {
			t.Fatalf("Read() bytes = %q, want %q", string(buf), "abcde")
		}
	})

	t.Run("PeekedConn_ZeroLengthReadBuffer_ReturnsZeroNilWithoutBlocking", func(t *testing.T) {
		// Regression test for the dev-review finding that len(b) == 0
		// previously fell through into the skipPending discard loop, which
		// could block on the underlying conn even though io.Reader's
		// contract requires a zero-length b to return (0, nil) (or a
		// non-nil error) without blocking on I/O.
		conn := &stuckConn{scriptedConn: newScriptedConn(nil)}
		pc := listener.NewPeekedConn(conn, []byte("xy"))

		// Drain the buffered peeked bytes first so this Read(nil) actually
		// reaches the skipPending discard loop rather than short-circuiting
		// via the buffered-bytes path (which would trivially return (0,
		// nil) for a zero-length b without ever reaching the loop).
		drain := make([]byte, 2)
		if n, err := pc.Read(drain); err != nil || n != 2 {
			t.Fatalf("drain Read() = (%d, %v), want (2, nil)", n, err)
		}

		done := make(chan struct{})
		var n int
		var err error
		go func() {
			n, err = pc.Read(nil)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("Read(nil) blocked for 2s instead of returning immediately")
		}
		if n != 0 || err != nil {
			t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
		}
	})

	t.Run("PeekedConn_MultipleReadsSmallerThanBuffer_EventuallyDrainAllPeekedBytes", func(t *testing.T) {
		pc := listener.NewPeekedConn(newScriptedConn([]byte("abcdefghijklmnopqrstuvwxyz")), []byte("abcd"))
		var got []byte
		buf := make([]byte, 2)
		for range 3 {
			n, err := pc.Read(buf)
			if err != nil && err != io.EOF {
				t.Fatalf("Read() error = %v, want nil/EOF", err)
			}
			got = append(got, buf[:n]...)
		}
		if string(got[:4]) != "abcd" {
			t.Fatalf("peek drain prefix = %q, want %q", string(got[:4]), "abcd")
		}
	})

	t.Run("PeekedConn_Write_DelegatesDirectlyToUnderlyingConn", func(t *testing.T) {
		conn := newScriptedConn(nil)
		pc := listener.NewPeekedConn(conn, nil)
		if _, err := pc.Write([]byte("hello")); err != nil {
			t.Fatalf("Write() error = %v, want nil", err)
		}
		if got := conn.writes.String(); got != "hello" {
			t.Fatalf("underlying writes = %q, want %q", got, "hello")
		}
	})

	t.Run("PeekedConn_Close_ClosesUnderlyingConnOnce", func(t *testing.T) {
		conn := newScriptedConn(nil)
		pc := listener.NewPeekedConn(conn, nil)
		if err := pc.Close(); err != nil {
			t.Fatalf("first Close() error = %v, want nil", err)
		}
		if err := pc.Close(); err != nil {
			t.Fatalf("second Close() error = %v, want nil", err)
		}
		if conn.closeCount != 1 {
			t.Fatalf("underlying close count = %d, want 1 (Close must dedupe repeated calls, matching this test's own name)", conn.closeCount)
		}
	})

	t.Run("Classify_SlowClientPartialWritesUnderDeadline_StillClassifiesCorrectly", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()
		go func() {
			payload := tlsClientHelloPrefix()
			for _, chunk := range [][]byte{payload[:2], payload[2:10], payload[10:]} {
				_, _ = client.Write(chunk)
				time.Sleep(5 * time.Millisecond)
			}
		}()
		disc := listener.NewDiscriminator(100*time.Millisecond, nil)
		proto, _, err := disc.Classify(server)
		if err != nil {
			t.Fatalf("Classify() error = %v, want nil", err)
		}
		if proto != listener.ProtocolTLS {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolTLS)
		}
	})

	t.Run("Classify_PeekDeadlineExceeded_ReturnsErrPeekTimeout", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()
		disc := listener.NewDiscriminator(10*time.Millisecond, nil)
		if _, _, err := disc.Classify(server); err != listener.ErrPeekTimeout {
			t.Fatalf("Classify() error = %v, want %v", err, listener.ErrPeekTimeout)
		}
	})

	t.Run("Classify_AmbiguousALPNBytes_StillClassifiedByRecordHeaderNotALPN", func(t *testing.T) {
		// Distinct from Classify_TLSClientHello_ReturnsProtocolTLS: this
		// payload carries a synthetic ALPN extension (protocol IDs "h2" and
		// "http/1.1") inside the record body. Classification must still be
		// decided purely from the leading record-header bytes (0x16 0x03 +
		// valid minor version), never by parsing/sniffing the ALPN
		// extension itself.
		alpnBearingRecord := append([]byte{0x16, 0x03, 0x03, 0x00, 0x20},
			[]byte("\x00\x10\x00\x0e\x00\x0c\x02h2\x08http/1.1")...)
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		proto, _, err := disc.Classify(newScriptedConn(alpnBearingRecord))
		if err != nil {
			t.Fatalf("Classify() error = %v, want nil", err)
		}
		if proto != listener.ProtocolTLS {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolTLS)
		}
	})

	t.Run("Classify_TLSRecordHeaderWithInvalidMinorVersion_ReturnsProtocolUnknown", func(t *testing.T) {
		// 0x16 0x03 is a valid TLS content-type/major-version prefix, but the
		// TLS 1.x record-layer minor version byte only ranges 0x00-0x04
		// (SSLv3 through TLS 1.3). A random binary stream that happens to
		// share the first two bytes must not be misclassified as TLS.
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		proto, _, err := disc.Classify(newScriptedConn([]byte{0x16, 0x03, 0xff, 0x00, 0x31}))
		if err != nil {
			t.Fatalf("Classify() error = %v, want nil", err)
		}
		if proto != listener.ProtocolUnknown {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolUnknown)
		}
	})

	t.Run("Classify_ConcurrentClassifyCallsOnDistinctConns_NoSharedState", func(t *testing.T) {
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		inputs := [][]byte{
			tlsClientHelloPrefix(),
			[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
			[]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
			[]byte{0xde, 0xad},
		}
		want := []listener.Protocol{
			listener.ProtocolTLS,
			listener.ProtocolHTTP1,
			listener.ProtocolH2CPreface,
			listener.ProtocolUnknown,
		}
		var wg sync.WaitGroup
		for i := range inputs {
			i := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, _, err := disc.Classify(newScriptedConn(inputs[i]))
				if err != nil {
					t.Errorf("Classify(%d) error = %v, want nil", i, err)
					return
				}
				if got != want[i] {
					t.Errorf("Classify(%d) protocol = %v, want %v", i, got, want[i])
				}
			}()
		}
		wg.Wait()
	})

	t.Run("Classify_UnknownProtocol_RecordDecisionCalled", func(t *testing.T) {
		metrics := &metricsSpy{}
		disc := listener.NewDiscriminator(50*time.Millisecond, metrics)
		proto, _, err := disc.Classify(newScriptedConn([]byte{0xde, 0xad}))
		if err != nil {
			t.Fatalf("Classify() error = %v, want nil", err)
		}
		if proto != listener.ProtocolUnknown {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolUnknown)
		}
		if len(metrics.decisions) != 1 {
			t.Fatalf("RecordDecision calls = %d, want 1", len(metrics.decisions))
		}
		if metrics.decisions[0].reason != listener.RejectUnsupportedProtocol.String() {
			t.Fatalf("RecordDecision reason = %q, want %q", metrics.decisions[0].reason, listener.RejectUnsupportedProtocol.String())
		}
		// An unclassifiable byte pattern is definitionally not a TLS
		// ClientHello (classifyBytes would have returned ProtocolTLS), so
		// the transport label must not misreport it as tls.
		if metrics.decisions[0].transport != audit.TransportPlaintext {
			t.Fatalf("RecordDecision transport = %v, want %v", metrics.decisions[0].transport, audit.TransportPlaintext)
		}
		// An unsupported-protocol rejection is a clean policy denial, not a fault.
		if metrics.decisions[0].fault {
			t.Fatalf("RecordDecision fault = true, want false for unsupported-protocol")
		}
	})

	t.Run("PeekedConn_SetDeadline_DelegatesToUnderlyingConn", func(t *testing.T) {
		conn := newScriptedConn(nil)
		pc := listener.NewPeekedConn(conn, nil)
		when := time.Now().Add(time.Second)
		if err := pc.SetDeadline(when); err != nil {
			t.Fatalf("SetDeadline() error = %v, want nil", err)
		}
		if err := pc.SetReadDeadline(when); err != nil {
			t.Fatalf("SetReadDeadline() error = %v, want nil", err)
		}
		if err := pc.SetWriteDeadline(when); err != nil {
			t.Fatalf("SetWriteDeadline() error = %v, want nil", err)
		}
		if !conn.deadline.Equal(when) || !conn.readDeadline.Equal(when) || !conn.writeDeadline.Equal(when) {
			t.Fatalf("deadlines not delegated correctly")
		}
	})

	t.Run("Classify_SetReadDeadlineFails_ReturnsErrSetDeadlineFailed", func(t *testing.T) {
		// A conn whose SetReadDeadline reports an error (e.g. an already-
		// closed socket) must fail closed rather than silently proceeding to
		// peek on a connection whose deadline state is unknown.
		conn := &deadlineFailingConn{scriptedConn: newScriptedConn(tlsClientHelloPrefix())}
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		proto, replay, err := disc.Classify(conn)
		if err != listener.ErrSetDeadlineFailed {
			t.Fatalf("Classify() error = %v, want %v", err, listener.ErrSetDeadlineFailed)
		}
		if proto != listener.ProtocolUnknown {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolUnknown)
		}
		if replay != nil {
			t.Fatalf("Classify() replay conn = %v, want nil", replay)
		}
	})
	t.Run("Classify_ClearingReadDeadlineFails_ReturnsErrSetDeadlineFailed", func(t *testing.T) {
		// The deferred cleanup call (SetReadDeadline(time.Time{})) can also
		// fail (e.g. the socket was closed concurrently). Classify must not
		// silently discard that error via a bare defer; it must fail closed
		// even though the peek itself otherwise succeeded.
		conn := &clearDeadlineFailingConn{scriptedConn: newScriptedConn(tlsClientHelloPrefix())}
		disc := listener.NewDiscriminator(50*time.Millisecond, nil)
		proto, replay, err := disc.Classify(conn)
		if err != listener.ErrSetDeadlineFailed {
			t.Fatalf("Classify() error = %v, want %v", err, listener.ErrSetDeadlineFailed)
		}
		if proto != listener.ProtocolUnknown {
			t.Fatalf("Classify() protocol = %v, want %v", proto, listener.ProtocolUnknown)
		}
		if replay != nil {
			t.Fatalf("Classify() replay conn = %v, want nil", replay)
		}
	})
	t.Run("PeekedConn_DiscardLoopUnderlyingConnMakesNoProgress_FailsInsteadOfBusySpinning", func(t *testing.T) {
		// If the underlying conn keeps returning (0, nil) during the
		// discard phase, peekedConn must eventually give up with an error
		// rather than spinning forever making no progress.
		conn := &stuckConn{scriptedConn: newScriptedConn(nil)}
		pc := listener.NewPeekedConn(conn, []byte("xy"))

		drain := make([]byte, 2)
		if n, err := pc.Read(drain); err != nil || n != 2 {
			t.Fatalf("drain Read() = (%d, %v), want (2, nil)", n, err)
		}

		buf := make([]byte, 1)
		n, err := pc.Read(buf)
		if !errors.Is(err, listener.ErrNoProgress) {
			t.Fatalf("Read() = (%d, %v), want ErrNoProgress", n, err)
		}
	})
	t.Run("PeekedConn_DiscardSpansMultipleUnderlyingReads_NeverReturnsZeroNilBeforeEOF", func(t *testing.T) {
		// io.Reader forbids returning (0, nil): once the buffered peeked
		// bytes are fully drained, if discarding skipPending bytes from the
		// underlying conn is only partially satisfied by one underlying Read
		// call, peekedConn must loop internally on further underlying reads
		// within the same call rather than returning (0, nil) to the caller.
		conn := newChunkedConn([][]byte{[]byte("x"), []byte("y")}, "live")
		pc := listener.NewPeekedConn(conn, []byte("xy"))

		// First Read fully drains the buffered peeked bytes.
		drain := make([]byte, 2)
		if n, err := pc.Read(drain); err != nil || n != 2 {
			t.Fatalf("drain Read() = (%d, %v), want (2, nil)", n, err)
		}

		// Second Read must discard 2 bytes from the underlying conn (which
		// only yields them 1 byte per call), then continue within the same
		// call to serve live data -- never returning (0, nil).
		buf := make([]byte, 1)
		n, err := pc.Read(buf)
		if n == 0 && err == nil {
			t.Fatalf("Read() = (0, nil), which violates the io.Reader contract")
		}
		if err != nil {
			t.Fatalf("Read() error = %v, want nil", err)
		}
		if string(buf[:n]) != "l" {
			t.Fatalf("Read() bytes = %q, want %q", string(buf[:n]), "l")
		}
	})
	t.Run("PeekedConn_BufferedReaderDrainExactlyAtEOF_DiscardedErrorDoesNotLeakToCaller", func(t *testing.T) {
		// Regression test locking in the documented behavior at the
		// bn, _ := p.buffered.Read(b) discard: bytes.Reader.Read only ever
		// returns io.EOF once fully drained, never any other error, and
		// that io.EOF must not leak to the caller of peekedConn.Read -- the
		// caller should transparently see live conn bytes on the same call.
		conn := newScriptedConn([]byte("live"))
		pc := listener.NewPeekedConn(conn, []byte("xy"))

		buf := make([]byte, 6)
		n, err := pc.Read(buf)
		if err != nil {
			t.Fatalf("Read() error = %v, want nil (buffered io.EOF must not leak to caller)", err)
		}
		// buffered replays "xy" (2 bytes), then skipPending discards the
		// next 2 bytes from conn ("li", assumed duplicates of the peeked
		// prefix), leaving "ve" to flow through as live data.
		if string(buf[:n]) != "xyve" {
			t.Fatalf("Read() bytes = %q, want %q", string(buf[:n]), "xyve")
		}
	})
	t.Run("PeekedConn_DiscardManySmallReads_DoesNotAllocatePerIteration", func(t *testing.T) {
		// Regression test for the dev-review finding that peekedConn.Read's
		// discard loop allocated a new []byte on every iteration via
		// make([]byte, p.skipPending). Drive the discard loop across many
		// single-byte underlying reads and assert peekedConn.Read itself
		// makes only a small constant number of allocations, not one per
		// discard iteration (skip=200 below).
		const skip = 200
		buf := make([]byte, 1)
		drainBuf := make([]byte, skip)
		peeked := make([]byte, skip)

		// Build the chunk byte slices once and reuse them across measured
		// runs (only the outer [][]byte slice header - one allocation - is
		// rebuilt per run, isolating the measurement from the discard
		// loop's own per-iteration allocation behavior).
		sharedChunks := make([][]byte, skip)
		for i := range sharedChunks {
			sharedChunks[i] = []byte{'x'}
		}

		readAllocs := testing.AllocsPerRun(20, func() {
			chunks := make([][]byte, skip)
			copy(chunks, sharedChunks)
			conn := newChunkedConn(chunks, "live")
			pc := listener.NewPeekedConn(conn, peeked)

			// First fully drain the buffered peeked bytes so skipPending's
			// discard loop is what actually runs on the next Read.
			if n, err := pc.Read(drainBuf); err != nil || n != skip {
				t.Fatalf("drain Read() = (%d, %v), want (%d, nil)", n, err, skip)
			}
			// This Read exercises the discard loop across `skip`
			// single-byte underlying reads before returning live data.
			if _, err := pc.Read(buf); err != nil {
				t.Fatalf("Read() error = %v", err)
			}
		})
		// This bound would be violated by the old
		// make([]byte, p.skipPending)-per-iteration code, which allocated
		// once per discard iteration (skip=200 times per Read call). The
		// remaining constant allocations here come from newChunkedConn,
		// NewPeekedConn, and the one make([][]byte, skip) per run, not
		// from the discard loop itself.
		t.Logf("readAllocs=%v", readAllocs)
		if readAllocs > 20 {
			t.Fatalf("peekedConn.Read discard loop allocs = %v, want a small constant well below skipPending=%d iterations", readAllocs, skip)
		}
	})
}

type deadlineFailingConn struct {
	*scriptedConn
}

func (c *deadlineFailingConn) SetReadDeadline(time.Time) error {
	return errors.New("simulated SetReadDeadline failure")
}

// clearDeadlineFailingConn only fails on the deferred cleanup call that
// clears the deadline (an all-zero time.Time), not on the initial set.
type clearDeadlineFailingConn struct {
	*scriptedConn
}

func (c *clearDeadlineFailingConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		return errors.New("simulated clear-deadline failure")
	}
	return c.scriptedConn.SetReadDeadline(t)
}

// chunkedConn is a net.Conn whose Read calls return data from a queue of
// discrete byte chunks (one Read call consumes exactly one chunk, never
// coalescing or splitting), followed by a final "live" chunk once the queue
// is exhausted. This lets tests force multiple distinct underlying Read
// calls where io.Reader semantics (never returning (0, nil)) must be upheld.
type chunkedConn struct {
	*scriptedConn
	chunks [][]byte
	live   []byte
}

func newChunkedConn(chunks [][]byte, live string) *chunkedConn {
	return &chunkedConn{scriptedConn: newScriptedConn(nil), chunks: chunks, live: []byte(live)}
}

func (c *chunkedConn) Read(b []byte) (int, error) {
	for len(c.chunks) > 0 {
		chunk := c.chunks[0]
		c.chunks = c.chunks[1:]
		if len(chunk) == 0 {
			// An empty chunk would otherwise make this Read return (0,
			// nil), which violates io.Reader's contract; skip it and try
			// the next chunk/live data within the same call instead.
			continue
		}
		return copy(b, chunk), nil
	}
	n := copy(b, c.live)
	c.live = c.live[n:]
	if n == 0 {
		// No chunks and no live data left: report a clean EOF instead of
		// returning (0, nil), which would also violate io.Reader.
		return 0, io.EOF
	}
	return n, nil
}

// stuckConn is a net.Conn whose Read always returns (0, nil), simulating a
// misbehaving underlying connection that never makes progress. Used to
// verify peekedConn's discard loop fails rather than busy-spinning forever.
type stuckConn struct {
	*scriptedConn
}

func (c *stuckConn) Read(b []byte) (int, error) { return 0, nil }

type scriptedConn struct {
	reader        *bytes.Reader
	writes        bytes.Buffer
	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time
	closeCount    int
}

func newScriptedConn(payload []byte) *scriptedConn {
	return &scriptedConn{reader: bytes.NewReader(payload)}
}

func (c *scriptedConn) Read(p []byte) (int, error)         { return c.reader.Read(p) }
func (c *scriptedConn) Write(p []byte) (int, error)        { return c.writes.Write(p) }
func (c *scriptedConn) Close() error                       { c.closeCount++; return nil }
func (c *scriptedConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (c *scriptedConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (c *scriptedConn) SetDeadline(t time.Time) error      { c.deadline = t; return nil }
func (c *scriptedConn) SetReadDeadline(t time.Time) error  { c.readDeadline = t; return nil }
func (c *scriptedConn) SetWriteDeadline(t time.Time) error { c.writeDeadline = t; return nil }

// failingReadConn.Read always returns a non-timeout, non-EOF error (e.g.
// simulating "connection reset by peer"), used to verify Classify does not
// silently discard a genuine transport failure as ProtocolUnknown.
type failingReadConn struct {
	scriptedConn
	readErr error
}

func (c *failingReadConn) Read(p []byte) (int, error) { return 0, c.readErr }

// deadlineClearFailsConn succeeds on the initial SetReadDeadline (arming the
// peek) but fails every subsequent SetReadDeadline call (clearing it), and
// its Read always fails with a non-timeout error; used to verify a genuine
// peek error is not masked by a later, unrelated deadline-clear failure.
type deadlineClearFailsConn struct {
	scriptedConn
	setCount int
	readErr  error
}

func (c *deadlineClearFailsConn) Read(p []byte) (int, error) { return 0, c.readErr }

func (c *deadlineClearFailsConn) SetReadDeadline(t time.Time) error {
	c.setCount++
	if c.setCount == 1 {
		return nil
	}
	return errors.New("simulated: failed to clear deadline")
}

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

func tlsClientHelloPrefix() []byte {
	return []byte{
		0x16, 0x03, 0x03, 0x00, 0x31, 0x01, 0x00, 0x00,
		0x2d, 0x03, 0x03, 0x5b, 0x90, 0x8c, 0x5b, 0x90,
		0x8c, 0x5b, 0x90, 0x8c, 0x5b, 0x90, 0x8c, 0x5b,
	}
}
