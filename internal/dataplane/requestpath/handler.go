package requestpath

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/girishmotwani/aksh/internal/policy"
)

// Handler serves HTTP/1.1 requests from a handed-over downstream connection.
type Handler struct {
	pipeline *pipeline.Pipeline
	dialer   dataplane.UpstreamDialer
	sink     audit.AuditSink
	metrics  audit.MetricsRecorder
	limiter  *Limiter
	reject   *audit.RejectionRecorder
	opts     Options
	bufPool  *sync.Pool
	now      func() time.Time
}

// NewHandler constructs a request-path handler.
func NewHandler(
	p *pipeline.Pipeline,
	dialer dataplane.UpstreamDialer,
	sink audit.AuditSink,
	metrics audit.MetricsRecorder,
	opts Options,
) (*Handler, error) {
	switch {
	case p == nil:
		return nil, fmt.Errorf("pipeline is required")
	case dialer == nil:
		return nil, fmt.Errorf("dialer is required")
	case sink == nil:
		return nil, fmt.Errorf("audit sink is required")
	case metrics == nil:
		return nil, fmt.Errorf("metrics are required")
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	return &Handler{
		pipeline: p,
		dialer:   dialer,
		sink:     sink,
		metrics:  metrics,
		limiter:  NewLimiter(opts.MaxInflightRequests),
		reject:   audit.NewRejectionRecorder(sink, metrics, opts.MaxRejectionAudits, opts.RejectionAuditTimeout, nil),
		opts:     opts,
		bufPool: &sync.Pool{
			New: func() any {
				buf := make([]byte, opts.CopyBufferBytes)
				return &buf
			},
		},
		now: time.Now,
	}, nil
}

// Serve handles one downstream connection.
func (h *Handler) Serve(ctx context.Context, ho Handover) error {
	if rejection := handoverRejection(ho); rejection != nil {
		rejection.ConnID = ho.ConnID
		h.recordRejection(*rejection)
		if ho.TLSConn != nil {
			_ = ho.TLSConn.Close()
		}
		return nil
	}

	cs := &connState{
		ho:     ho,
		source: &prependConn{Conn: ho.TLSConn},
	}
	cs.guard = NewHeadGuard(cs.source, h.opts.MaxHeaderBytes)
	cs.br = bufio.NewReaderSize(cs.guard, h.opts.MaxHeaderBytes)
	defer ho.TLSConn.Close()
	defer func() {
		if cs.upstream != nil {
			cs.upstream.close()
		}
	}()

	for {
		if ctx != nil && ctx.Err() != nil {
			return nil
		}

		if err := h.waitForRequest(ctx, ho.TLSConn, cs.source); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || isTimeout(err) || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}

		keepAlive := h.serveOne(ctx, cs)
		if !keepAlive {
			return nil
		}
		if ctx != nil && ctx.Err() != nil {
			return nil
		}
		if cs.br.Buffered() > 0 {
			h.rejectAndWrite(cs, Rejection{
				Class:  ClassT5,
				Reason: pipeline.ReasonUnsupportedProtocol,
				Bound:  "pipelining",
				Wire:   WireWrite400Close,
				Status: http.StatusBadRequest,
			})
			return nil
		}
	}
}

func (h *Handler) waitForRequest(ctx context.Context, conn net.Conn, source *prependConn) error {
	if err := conn.SetReadDeadline(h.now().Add(h.opts.IdleTimeout)); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)

	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				_ = conn.SetReadDeadline(time.Now())
			case <-done:
			}
		}()
	}

	var b [1]byte
	n, err := conn.Read(b[:])
	_ = conn.SetReadDeadline(time.Time{})
	if n > 0 {
		source.Prepend(b[:n])
		return nil
	}
	if ctx != nil && ctx.Err() != nil && isTimeout(err) {
		return context.Canceled
	}
	return err
}

func (h *Handler) serveOne(ctx context.Context, cs *connState) bool {
	if !h.limiter.TryAcquire() {
		h.rejectAndWrite(cs, Rejection{
			Class:  ClassT7,
			Reason: pipeline.ReasonResourceLimit,
			Bound:  "max_inflight_requests",
			Wire:   WireCloseBare,
		})
		return false
	}
	defer h.limiter.Release()

	req, rawHead, ok := h.readRequest(cs)
	if !ok {
		return false
	}
	if req == nil {
		return false
	}

	expectContinue := hasContinueExpectation(req)
	rejection := Validate(req, rawHead, cs.ho, h.opts)
	if rejection != nil {
		h.rejectAndWrite(cs, *rejection)
		return false
	}

	authorityHost, authorityPort, _ := splitAuthority(req.Host)
	rc := &pipeline.RequestContext{
		Request: req,
		Identity: pipeline.IdentityInput{
			SNI:             stringsLower(cs.ho.SNI),
			AuthorityHost:   authorityHost,
			AuthorityPort:   authorityPort,
			DestinationPort: cs.ho.OriginalDst.Port(),
		},
		Transport: policy.TransportTLS,
		StartTime: h.now(),
		RequestID: requestID(cs.ho.ConnID, cs.served+1),
	}

	decision := h.pipeline.Execute(ctx, rc)
	if !decision.IsAllow() {
		// The most important security event this product emits: record the
		// policy verdict here (#60), whatever wire behaviour follows. Only
		// deny is recorded — allow is observed at connection granularity by
		// the listener's fallback (listener.go), so a per-request handler
		// allow here would double count against that coarser series rather
		// than fill a real gap.
		//
		// Claiming the latch is what stops the listener fallback from then
		// recording this same connection as an ALLOW (issue #89).
		if cs.ho.MarkDecided() {
			h.metrics.Decisions(decision.Disposition(), decision.Reason, audit.TransportTLS, decision.Fault)
		}
		if decision.Reason == pipeline.ReasonIdentityMismatch {
			return false
		}
		writeUniformDeny(cs.ho.TLSConn)
		return false
	}

	if !h.relay(ctx, cs, rc, expectContinue) {
		return false
	}
	if h.hasImmediateNextByte(cs.ho.TLSConn) {
		h.rejectAndWrite(cs, Rejection{
			Class:  ClassT5,
			Reason: pipeline.ReasonUnsupportedProtocol,
			Bound:  "pipelining",
			Wire:   WireWrite400Close,
			Status: http.StatusBadRequest,
		})
		return false
	}
	cs.served++
	return true
}

func (h *Handler) readRequest(cs *connState) (*http.Request, []byte, bool) {
	if err := cs.ho.TLSConn.SetReadDeadline(h.now().Add(h.opts.HeaderReadTimeout)); err == nil {
		defer cs.ho.TLSConn.SetReadDeadline(time.Time{})
	}
	cs.guard.Arm()
	req, err := http.ReadRequest(cs.br)
	rawHead := append([]byte(nil), cs.guard.Head()...)
	if end := bytes.Index(rawHead, []byte("\r\n\r\n")); end >= 0 {
		rawHead = rawHead[:end+4]
	}
	cs.guard.Disarm()
	if err == nil {
		return req, rawHead, true
	}

	switch {
	case errors.Is(err, ErrHeadTooLarge), errors.Is(err, bufio.ErrBufferFull), len(rawHead) >= h.opts.MaxHeaderBytes:
		h.rejectAndWrite(cs, Rejection{
			Class:  ClassT7,
			Reason: pipeline.ReasonResourceLimit,
			Bound:  "max_header_bytes",
			Wire:   WireWrite431Close,
			Status: http.StatusRequestHeaderFieldsTooLarge,
		})
	case isTimeout(err):
		h.rejectAndWrite(cs, Rejection{
			Class:  ClassT7,
			Reason: pipeline.ReasonResourceLimit,
			Bound:  "request_header_read_timeout",
			Wire:   WireCloseBare,
		})
	default:
		h.rejectAndWrite(cs, Rejection{
			Class:  ClassT5,
			Reason: pipeline.ReasonUnsupportedProtocol,
			Wire:   WireWrite400Close,
			Status: http.StatusBadRequest,
		})
	}
	return nil, rawHead, false
}

func handoverRejection(ho Handover) *Rejection {
	switch {
	case ho.TLSConn == nil || !ho.IsTLS:
		return &Rejection{Class: ClassT5, Reason: pipeline.ReasonUnsupportedProtocol, Bound: "handover", Fault: true, Wire: WireCloseBare}
	case !isValidOriginalDst(ho.OriginalDst):
		return &Rejection{Class: ClassT1, Reason: pipeline.ReasonInternal, Bound: "handover", Fault: true, Wire: WireCloseBare}
	default:
		return nil
	}
}

func (h *Handler) rejectAndWrite(cs *connState, rej Rejection) {
	rej.ConnID = cs.ho.ConnID
	rej.Port = cs.ho.OriginalDst.Port()
	h.recordRejection(rej)
	// A rejection is a terminal deny for this connection. Before the latch
	// existed this path recorded only the T-class rejection counter and its
	// audit record, never a decision, so the listener rollup then counted the
	// rejected connection as an ALLOW (issue #89).
	if h.metrics != nil && cs.ho.MarkDecided() {
		h.metrics.Decisions(pipeline.DispositionDeny, rej.Reason, audit.TransportTLS, rej.Fault)
	}
	switch rej.Wire {
	case WireWrite431Close:
		writeStatusThenClose(cs.ho.TLSConn, http.StatusRequestHeaderFieldsTooLarge)
	case WireWrite400Close:
		writeStatusThenClose(cs.ho.TLSConn, http.StatusBadRequest)
	}
}

func (h *Handler) recordRejection(rej Rejection) {
	if h == nil || h.reject == nil {
		return
	}
	h.reject.Record(audit.Rejection{
		Class:     string(rej.Class),
		Reason:    rej.Reason,
		Bound:     rej.Bound,
		Fault:     rej.Fault,
		RequestID: rej.RequestID,
		ConnID:    rej.ConnID,
		Port:      rej.Port,
		Method:    rej.Method,
		Path:      rej.Path,
	})
}

func writeStatusThenClose(conn io.Writer, statusCode int) {
	statusText := http.StatusText(statusCode)
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", statusCode, statusText)
}

func isTimeout(err error) bool {
	type timeout interface{ Timeout() bool }
	var netErr timeout
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isValidOriginalDst(addr netip.AddrPort) bool {
	return addr.IsValid() && addr.Addr().Is4() && addr.Port() != 0
}

func requestID(connID string, ordinal int) string {
	if connID == "" {
		return fmt.Sprintf("req-%d", ordinal)
	}
	return fmt.Sprintf("%s-%d", connID, ordinal)
}

func stringsLower(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToLower(s)
}

func hasContinueExpectation(req *http.Request) bool {
	values := req.Header.Values("Expect")
	return len(values) == 1 && strings.EqualFold(strings.TrimSpace(values[0]), "100-continue")
}

func (h *Handler) hasImmediateNextByte(conn net.Conn) bool {
	var b [1]byte
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		return false
	}
	defer conn.SetReadDeadline(time.Time{})
	n, err := conn.Read(b[:])
	if n > 0 {
		return true
	}
	return err == nil
}

type prependConn struct {
	net.Conn
	prefix []byte
}

func (c *prependConn) Prepend(p []byte) {
	if len(p) == 0 {
		return
	}
	c.prefix = append(append([]byte(nil), p...), c.prefix...)
}

func (c *prependConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func syntheticRawHead(req *http.Request) []byte {
	if req == nil {
		return nil
	}
	var b bytes.Buffer
	target := req.RequestURI
	if target == "" && req.URL != nil {
		target = req.URL.RequestURI()
	}
	if target == "" {
		target = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, target)
	if req.Host != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", req.Host)
	}
	for name, values := range req.Header {
		if strings.EqualFold(name, "Host") {
			continue
		}
		for _, value := range values {
			fmt.Fprintf(&b, "%s: %s\r\n", name, value)
		}
	}
	b.WriteString("\r\n")
	return b.Bytes()
}
