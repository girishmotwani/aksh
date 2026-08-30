package requestpath

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

type connState struct {
	ho       Handover
	source   *prependConn
	br       *bufio.Reader
	guard    *HeadGuard
	upstream *upstreamConn
	served   int
}

type upstreamConn struct {
	conn     net.Conn
	br       *bufio.Reader
	identity string
	port     uint16
	credID   string
	reusable bool
}

func (u *upstreamConn) close() {
	if u == nil || u.conn == nil {
		return
	}
	_ = u.conn.Close()
	u.conn = nil
}

func (u *upstreamConn) reusableFor(rc *pipeline.RequestContext, ho Handover, credID string) bool {
	return u != nil &&
		u.conn != nil &&
		u.reusable &&
		u.identity == rc.Facts.Identity &&
		u.port == ho.OriginalDst.Port() &&
		u.credID == credID
}

type progressConn struct {
	net.Conn
	stamp *atomic.Int64
	now   func() time.Time
}

func (c *progressConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *progressConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *progressConn) touch() {
	if c == nil || c.stamp == nil || c.now == nil {
		return
	}
	c.stamp.Store(c.now().UnixNano())
}

func (h *Handler) relay(ctx context.Context, cs *connState, rc *pipeline.RequestContext, expectContinue bool) bool {
	credID := credentialIdentity(rc)
	upstream, ok := h.ensureUpstream(ctx, cs, rc, credID)
	if !ok {
		writeUniformDeny(cs.ho.TLSConn)
		return false
	}

	var stamp atomic.Int64
	stamp.Store(h.now().UnixNano())
	downstream := &progressConn{Conn: cs.ho.TLSConn, stamp: &stamp, now: h.now}
	upstreamProgress := &progressConn{Conn: upstream.conn, stamp: &stamp, now: h.now}
	upstream.br = bufio.NewReader(upstreamProgress)

	done := make(chan struct{})
	var timedOut atomic.Bool
	go h.watchProgress(cs.ho, &stamp, cs.ho.TLSConn, upstream.conn, done, &timedOut)
	defer close(done)
	req := cloneRequest(rc.Request)
	req.RequestURI = ""
	if err := h.writeUpstreamRequest(cs.ho.TLSConn, upstreamProgress, req, expectContinue); err != nil {
		if !timedOut.Load() {
			if cs.ho.MarkDecided() {
				h.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonWriteFailed, audit.TransportTLS, true)
			}
			if malformedChunkedBodyError(err) {
				writeStatusThenClose(cs.ho.TLSConn, http.StatusBadRequest)
			}
		}
		upstream.close()
		cs.upstream = nil
		return false
	}

	if err := upstream.conn.SetReadDeadline(h.now().Add(h.opts.UpstreamResponseTimeout)); err == nil {
		defer upstream.conn.SetReadDeadline(time.Time{})
	}
	resp, err := http.ReadResponse(upstream.br, req)
	if err != nil {
		if !timedOut.Load() && cs.ho.MarkDecided() {
			h.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonResponseFailed, audit.TransportTLS, true)
		}
		upstream.close()
		cs.upstream = nil
		return false
	}
	limited := newResponseBodyLimitReader(resp.Body, h.opts.MaxResponseBodyBytes)
	resp.Body = limited
	defer resp.Body.Close()
	stripHopByHop(resp.Header)
	if err := resp.Write(downstream); err != nil {
		if errors.Is(err, ErrResponseBodyTooLarge) || limited.Exceeded() {
			if cs.ho.MarkDecided() {
				h.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonResourceLimit, audit.TransportTLS, false)
			}
		} else if cs.ho.MarkDecided() {
			// Any other failure to write the response downstream is a transport
			// fault, not a successful request. Without this the connection
			// latches nothing and the listener rollup reports it as an allow -
			// the same "a fault counted as a success" defect as #89.
			h.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonWriteFailed, audit.TransportTLS, true)
		}
		upstream.close()
		cs.upstream = nil
		return false
	}

	if resp.Close {
		upstream.close()
		cs.upstream = nil
	}
	if req.Close {
		return false
	}

	upstream.identity = rc.Facts.Identity
	upstream.port = cs.ho.OriginalDst.Port()
	upstream.credID = credID
	upstream.reusable = true
	return true
}

func (h *Handler) ensureUpstream(ctx context.Context, cs *connState, rc *pipeline.RequestContext, credID string) (*upstreamConn, bool) {
	if cs.upstream != nil && cs.upstream.reusableFor(rc, cs.ho, credID) {
		return cs.upstream, true
	}
	if cs.upstream != nil {
		cs.upstream.close()
		cs.upstream = nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	dialCtx, cancel := context.WithTimeout(ctx, h.opts.UpstreamDialTimeout)
	defer cancel()

	conn, err := h.dialer.DialUpstream(dialCtx, cs.ho.OriginalDst, rc.Facts.Identity, credID)
	if err != nil {
		// The dialer already recorded the *specific* reason it failed
		// (loop_guard, resource_limit, dial_failed, handshake_failed,
		// registry_add_failed, internal). Recording a second, coarser
		// dial_failed here double-counted every failed dial — an upstream TLS
		// handshake failure produced handshake_failed AND dial_failed for one
		// request (issue #89). Claim the latch so the listener fallback does
		// not add a third sample, but record nothing: the dialer's reason is
		// strictly more informative than this one.
		cs.ho.MarkDecided()
		return nil, false
	}

	cs.upstream = &upstreamConn{
		conn:     conn,
		br:       bufio.NewReader(conn),
		identity: rc.Facts.Identity,
		port:     cs.ho.OriginalDst.Port(),
		credID:   credID,
		reusable: true,
	}
	return cs.upstream, true
}

func (h *Handler) watchProgress(
	ho Handover,
	stamp *atomic.Int64,
	downstream net.Conn,
	upstream net.Conn,
	done <-chan struct{},
	timedOut *atomic.Bool,
) {
	interval := h.opts.ProgressDeadline / 4
	if interval <= 0 {
		interval = h.opts.ProgressDeadline
	}
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			last := time.Unix(0, stamp.Load())
			if h.now().Sub(last) < h.opts.ProgressDeadline {
				continue
			}
			if timedOut != nil {
				timedOut.Store(true)
			}
			if ho.MarkDecided() {
				h.metrics.Decisions(pipeline.DispositionDeny, pipeline.ReasonProgressDeadline, audit.TransportTLS, true)
			}
			_ = upstream.Close()
			_ = downstream.Close()
			return
		}
	}
}

func cloneRequest(req *http.Request) *http.Request {
	cloned := new(http.Request)
	*cloned = *req
	cloned.Header = req.Header.Clone()
	return cloned
}

func stripHopByHop(header http.Header) {
	for _, name := range connectionTokenNames(header.Values("Connection")) {
		header.Del(name)
	}
	for _, name := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
}

func connectionTokenNames(values []string) []string {
	var names []string
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			trimmed := strings.TrimSpace(token)
			if trimmed != "" {
				names = append(names, http.CanonicalHeaderKey(trimmed))
			}
		}
	}
	return names
}

func credentialIdentity(rc *pipeline.RequestContext) string {
	if rc != nil && rc.TokenResult.Resolved.Identity != "" {
		return rc.TokenResult.Resolved.Identity
	}
	return "none"
}

func writeUniformDeny(w io.Writer) {
	_, _ = io.WriteString(w, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
}

func (h *Handler) writeUpstreamRequest(downstream io.Writer, upstream io.Writer, req *http.Request, expectContinue bool) error {
	if !expectContinue {
		return req.Write(upstream)
	}

	if err := writeRequestHead(upstream, req); err != nil {
		return err
	}
	if _, err := io.WriteString(downstream, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
		return err
	}
	if usesChunkedTransferEncoding(req) {
		chunked := httputil.NewChunkedWriter(upstream)
		if req.Body != nil && req.Body != http.NoBody {
			if _, err := io.Copy(chunked, req.Body); err != nil {
				_ = chunked.Close()
				return err
			}
		}
		if err := chunked.Close(); err != nil {
			return err
		}
		_, err := io.WriteString(upstream, "\r\n")
		return err
	}
	if req.Body == nil || req.Body == http.NoBody {
		return nil
	}
	_, err := io.Copy(upstream, req.Body)
	return err
}

func writeRequestHead(w io.Writer, req *http.Request) error {
	target := req.URL.RequestURI()
	if target == "" {
		target = "/"
	}
	if _, err := fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", req.Method, target); err != nil {
		return err
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	if host != "" {
		if _, err := fmt.Fprintf(w, "Host: %s\r\n", host); err != nil {
			return err
		}
	}

	header := req.Header.Clone()
	header.Del("Expect")
	if usesChunkedTransferEncoding(req) {
		header.Del("Content-Length")
		header.Set("Transfer-Encoding", "chunked")
	}
	if req.ContentLength >= 0 && header.Get("Content-Length") == "" && !usesChunkedTransferEncoding(req) {
		header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	}
	if err := header.Write(w); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func malformedChunkedBodyError(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "malformed chunked encoding") ||
		strings.Contains(text, "chunk length") ||
		strings.Contains(text, "invalid byte")
}

// usesChunkedTransferEncoding reports whether req's final transfer-coding is
// "chunked" per RFC 7230 §3.3.1 (chunked must be the last coding applied, so
// only the last element of a multi-valued Transfer-Encoding list matters,
// e.g. "gzip, chunked" is a chunked body).
func usesChunkedTransferEncoding(req *http.Request) bool {
	n := len(req.TransferEncoding)
	return n > 0 && strings.EqualFold(req.TransferEncoding[n-1], "chunked")
}
