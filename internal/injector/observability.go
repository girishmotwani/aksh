package injector

import (
	"io"
	"log/slog"
	"strings"
	"unicode/utf8"
)

// maxTLSErrorLen bounds the TLS error string that is logged so a hostile or
// verbose handshake error can neither bloat a log line nor smuggle unbounded
// data into observability output. TLS handshake errors never contain private
// key material, but the length is capped defensively regardless.
const maxTLSErrorLen = 256

// discardLogger returns a *slog.Logger that discards all records. It is the
// default logger for a WebhookServer, PKI generation, and the caBundle
// reconciler so observability is opt-in via WithLogger and callers never need a
// nil check before logging.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// boundedTLSError normalises and bounds a TLS error message for logging. It
// collapses interior whitespace/newlines to single spaces and truncates to at
// most maxTLSErrorLen BYTES, backing off to the nearest rune boundary so a
// multi-byte UTF-8 rune is never split. The emitted `error` field is therefore
// always a single-line, byte-bounded value that cannot shape or forge
// multi-line log output.
func boundedTLSError(msg string) string {
	collapsed := strings.Join(strings.Fields(msg), " ")
	if len(collapsed) <= maxTLSErrorLen {
		return collapsed
	}
	truncated := collapsed[:maxTLSErrorLen]
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}

// tlsErrorLogWriter adapts the net/http server ErrorLog to the observability
// seam: it detects TLS handshake failures, increments aksh_webhook_tls_errors_total,
// and emits a single bounded error log without any key material.
type tlsErrorLogWriter struct {
	server *WebhookServer
}

func (w tlsErrorLogWriter) Write(p []byte) (int, error) {
	if w.server == nil {
		return len(p), nil
	}
	msg := string(p)
	if strings.Contains(msg, "TLS handshake error") {
		w.server.recordTLSError(boundedTLSError(msg))
	} else {
		// Non-TLS net/http server errors are still surfaced (bounded, without a
		// TLS-metric increment) so the ErrorLog adapter never silently drops them.
		w.server.logger.Error("aksh-injector: webhook server error", "error", boundedTLSError(msg))
	}
	return len(p), nil
}

// recordTLSError increments the TLS error metric and emits a bounded error log.
// It is the single seam through which both real handshake failures (routed via
// the http.Server ErrorLog) and cert-load failures report TLS trouble.
func (s *WebhookServer) recordTLSError(boundedMsg string) {
	s.metrics.WebhookTLSError()
	s.logger.Error("aksh-injector: webhook TLS error", "error", boundedMsg)
}

// compile-time assertion that the ErrorLog adapter is an io.Writer.
var _ io.Writer = tlsErrorLogWriter{}
