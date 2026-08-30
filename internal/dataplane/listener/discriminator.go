package listener

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

// PeekSize is the fixed number of leading bytes the discriminator inspects
// before classifying a connection's protocol, per design section 10.1. It is
// a named constant (rather than inlined) so the peek size used in production
// code and the test assertions has exactly one definition.
const PeekSize = 24

// maxZeroProgressReads bounds how many consecutive (0, nil) reads
// peekedConn's discard loop tolerates from the underlying conn before
// concluding it is stuck and failing, rather than busy-spinning forever.
const maxZeroProgressReads = 100

// discardScratchSize is the size of the fixed scratch buffer peekedConn.Read
// reuses across iterations of its discard loop, instead of allocating a new
// []byte every iteration. It matches PeekSize: skipPending can never exceed
// the number of bytes peeked in the first place, so a scratch buffer larger
// than PeekSize would only waste memory on every peekedConn instance.
const discardScratchSize = PeekSize

// h2cPreface is the exact HTTP/2 cleartext connection preface (RFC 7540 3.5).
// It is a string constant (immutable), not a []byte var: any accidental
// mutation of a package-level []byte var would corrupt protocol detection
// for every subsequent connection classified by this package.
const h2cPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Discriminator peeks the leading bytes of a freshly-accepted connection and
// classifies its wire framing without consuming those bytes from the stream
// (design section 10.1, "Peek, without consuming").
type Discriminator struct {
	peekTimeout time.Duration
	metrics     audit.MetricsRecorder
}

// NewDiscriminator constructs a Discriminator with the given peek deadline and
// an optional metrics recorder (nil disables Decisions calls).
func NewDiscriminator(peekTimeout time.Duration, metrics audit.MetricsRecorder) *Discriminator {
	return &Discriminator{peekTimeout: peekTimeout, metrics: metrics}
}

// Classify peeks up to PeekSize bytes from conn via a bufio.Reader (a real
// read at the socket level, but one that does not advance the bufio.Reader's
// own consumption cursor) and returns the detected Protocol along with a
// net.Conn that replays those bytes before any caller observes genuinely new
// bytes from conn. A short peek (connection closed before PeekSize bytes
// arrive, including zero bytes) is a valid ProtocolUnknown outcome, not an
// error; only a genuine deadline expiry surfaces as ErrPeekTimeout.
//
// Classify takes ownership of conn's read deadline for the duration of the
// peek: it sets its own deadline and unconditionally clears it (resets to
// the zero time, meaning "no deadline") afterwards, rather than attempting
// to save and restore any deadline the caller may have previously set.
// net.Conn exposes no getter for the current deadline, so a caller-supplied
// deadline cannot be recovered and re-applied here; callers that need their
// own read deadline enforced must re-apply it themselves after Classify
// returns.
func (d *Discriminator) Classify(conn net.Conn) (proto Protocol, replay net.Conn, err error) {
	if conn == nil {
		return ProtocolUnknown, nil, ErrMissingConn
	}

	if d.peekTimeout > 0 {
		if setErr := conn.SetReadDeadline(time.Now().Add(d.peekTimeout)); setErr != nil {
			return ProtocolUnknown, nil, ErrSetDeadlineFailed
		}
		defer func() {
			// Clearing the deadline can fail too (e.g. the socket was
			// closed concurrently). Only surface that as err if the peek
			// itself did not already fail: a non-nil err at this point
			// means the deferred deadline-clear failure would otherwise
			// mask a more specific, already-diagnosed peek error, so it
			// is deliberately not overwritten here.
			if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil && err == nil {
				proto = ProtocolUnknown
				replay = nil
				err = ErrSetDeadlineFailed
			}
		}()
	}

	br := bufio.NewReaderSize(conn, PeekSize)
	peeked, peekErr := br.Peek(PeekSize)
	if peekErr != nil {
		if isDeadlineExceeded(peekErr) {
			return ProtocolUnknown, nil, ErrPeekTimeout
		}
		// io.EOF / io.ErrUnexpectedEOF mean the client closed having sent
		// fewer than PeekSize bytes: classification proceeds on whatever
		// prefix arrived, since a short peek is a valid outcome, not a
		// failure. Any other error (connection reset, other I/O failures)
		// is a genuine transport failure and must not be silently
		// downgraded to a ProtocolUnknown classification: return it so
		// the deferred deadline-clear cannot mask it (err == nil guard
		// above) and so callers do not record misleading
		// unsupported-protocol metrics for a broken connection.
		if !errors.Is(peekErr, io.EOF) && !errors.Is(peekErr, io.ErrUnexpectedEOF) {
			return ProtocolUnknown, nil, fmt.Errorf("listener: peek failed: %w", peekErr)
		}
	}

	p := classifyBytes(peeked)
	// Classify returns a net.Conn stacked two layers deep:
	//   caller -> peekedConn -> bufioConn -> conn (raw socket)
	// This is deliberate, not redundant: br.Peek already consumed PeekSize
	// bytes at the socket level into bufio.Reader's internal buffer, so
	// bufioConn's job is solely to route subsequent Read calls back through
	// that same bufio.Reader (replaying its buffered bytes before any new
	// socket read). peekedConn's job is different: replaying the exact
	// `peeked` byte slice captured here to the *caller*, then discarding
	// (not replaying) that same number of bytes as they re-emerge from
	// bufioConn/br, so the caller never has to know a peek happened. Each
	// layer owns exactly one replay responsibility; collapsing them would
	// require peekedConn to reach into bufio.Reader internals directly.
	r := NewPeekedConn(&bufioConn{Conn: conn, br: br}, append([]byte(nil), peeked...))

	if p == ProtocolUnknown && d.metrics != nil {
		// An unclassified byte pattern is not a TLS ClientHello (classifyBytes
		// would have returned ProtocolTLS), so label the rejection plaintext.
		d.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonUnsupportedProtocol, audit.TransportPlaintext, false)
	}

	return p, r, nil
}

// bufioConn adapts a bufio.Reader wrapping conn back into a net.Conn: reads go
// through the bufio.Reader (so bytes already consumed into its internal
// buffer via Peek are served again before new socket reads happen), while
// every other method delegates to the original conn.
//
// Close/CloseRead and any net.Buffers-consuming WriteTo caller are not
// overridden: they delegate straight to the embedded net.Conn (via
// net.Conn's own default embedding, not a bufioConn method), bypassing
// br's buffered bytes entirely. This is safe today because bufioConn is
// only ever wrapped by peekedConn (see NewPeekedConn below), whose own
// Close simply forwards to the underlying conn -- there is no remaining
// buffered data a Close/CloseRead call needs to account for, and nothing
// in this package calls WriteTo on a peeked connection. If bufioConn is
// ever reused outside peekedConn, or a caller starts relying on WriteTo,
// revisit this: an override may become necessary to flush or account for
// br's buffer first.
type bufioConn struct {
	net.Conn
	br *bufio.Reader
}

func (b *bufioConn) Read(p []byte) (int, error) { return b.br.Read(p) }

func isDeadlineExceeded(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded)
}

func classifyBytes(b []byte) Protocol {
	// h2cPreface is compared via a fresh []byte(h2cPreface) conversion
	// (not a shared package-level []byte var) specifically so nothing can
	// mutate the comparison target and corrupt protocol detection for
	// every subsequent connection. This local conversion does not
	// actually allocate: escape analysis proves it never escapes
	// classifyBytes (it is consumed immediately by bytes.Equal and
	// discarded), so the compiler stack-allocates it -- confirmed by
	// TestClassifyBytes_H2CPrefaceMatch_DoesNotAllocate remaining at 0
	// allocs/op after this change.
	switch {
	case len(b) >= len(h2cPreface) && bytes.Equal(b[:len(h2cPreface)], []byte(h2cPreface)):
		return ProtocolH2CPreface
	case len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] >= 0x01 && b[2] <= 0x04:
		// TLS record-layer minor version 0x01 (TLS 1.0) through 0x04 (TLS
		// 1.3) classifies as TLS. Minor version 0x00 (SSLv3, deprecated
		// and insecure per POODLE) is deliberately excluded rather than
		// accepted alongside genuine TLS versions.
		return ProtocolTLS
	case isHTTP1RequestLine(b):
		return ProtocolHTTP1
	default:
		return ProtocolUnknown
	}
}

// httpMethods are the request-line tokens the discriminator recognises. A
// prefix match against any of these, in the leading bytes, classifies the
// connection as ProtocolHTTP1.
var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
	[]byte("HEAD "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
	[]byte("TRACE "),
}

func isHTTP1RequestLine(b []byte) bool {
	for _, m := range httpMethods {
		if len(b) >= len(m) && bytes.Equal(b[:len(m)], m) {
			return true
		}
	}
	return false
}

// peekedConn wraps a net.Conn so that previously-peeked bytes are replayed to
// the first Read calls. Because the peeked bytes were obtained through a
// non-destructive peek (they remain available from conn's own Read once, per
// bufioConn above, or -- in isolated tests -- are simply assumed still
// present), peekedConn discards exactly len(peeked) bytes from conn the first
// time its own buffered copy drains, so the caller never sees the peeked
// prefix duplicated.
type peekedConn struct {
	net.Conn
	buffered       *bytes.Reader
	skipPending    int
	discardScratch [discardScratchSize]byte
	closeOnce      sync.Once
	closeErr       error
}

// NewPeekedConn returns a net.Conn that replays peeked before delegating
// further reads to conn. conn must not have consumed peeked away already (a
// true, non-destructive peek): once buffered is drained, peekedConn discards
// len(peeked) bytes read from conn exactly once, then passes all further
// reads straight through.
//
// peekedConn.Read is not safe for concurrent use by multiple goroutines
// (matching the general net.Conn convention that Read calls must not
// overlap): it mutates skipPending and buffered without synchronization.
func NewPeekedConn(conn net.Conn, peeked []byte) net.Conn {
	return &peekedConn{Conn: conn, buffered: bytes.NewReader(peeked), skipPending: len(peeked)}
}

func (p *peekedConn) Read(b []byte) (int, error) {
	// Per the io.Reader contract, a zero-length b must return (0, nil)
	// (or occasionally a non-nil error) without blocking. Previously,
	// len(b) == 0 fell through into the skipPending discard loop below,
	// which could block on the underlying conn's Read even though the
	// caller asked to read zero bytes.
	if len(b) == 0 {
		return 0, nil
	}
	var n int
	if p.buffered.Len() > 0 {
		// bytes.Reader.Read only ever returns io.EOF (never any other
		// error) once its internal buffer is exhausted; that io.EOF is
		// expected and deliberately discarded here, since it only signals
		// "buffered is now empty," which the p.buffered.Len() > 0 guard and
		// fallthrough to the skipPending discard loop below already handle.
		bn, _ := p.buffered.Read(b)
		n += bn
		if n == len(b) {
			return n, nil
		}
		// The peeked buffer just drained mid-call: fall through so the
		// remainder of the caller's buffer is filled within this same call,
		// rather than requiring a second Read to observe conn's own bytes.
	}
	if p.skipPending > 0 {
		// Discard len(skipPending) bytes from the underlying conn before any
		// caller-visible bytes, looping across multiple underlying Read
		// calls if needed since a single call may not fully satisfy it.
		// Never return (0, nil) up to this point (io.Reader contract), but
		// also guard against a misbehaving underlying conn that repeatedly
		// makes no progress: after enough consecutive zero-progress reads,
		// fail rather than busy-spin forever.
		zeroStreak := 0
		for p.skipPending > 0 {
			discard := p.discardScratch[:]
			if p.skipPending < len(discard) {
				discard = discard[:p.skipPending]
			}
			dn, err := p.Conn.Read(discard)
			p.skipPending -= dn
			if err != nil {
				return n, err
			}
			if dn == 0 {
				zeroStreak++
				if zeroStreak >= maxZeroProgressReads {
					return n, ErrNoProgress
				}
				continue
			}
			zeroStreak = 0
		}
	}
	more, err := p.Conn.Read(b[n:])
	return n + more, err
}

func (p *peekedConn) Close() error {
	p.closeOnce.Do(func() {
		p.closeErr = p.Conn.Close()
	})
	return p.closeErr
}
