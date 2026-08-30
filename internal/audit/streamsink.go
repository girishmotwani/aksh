package audit

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

// StreamSink writes newline-delimited JSON audit records. It is a simple
// synchronous AuditSink that serialises via the canonical AuditRecordEncoder
// (F7), so its records are the design-conformant aksh.dev/audit/v1 nested shape
// — schema and payload agree — and decision vs completion records use the
// correct per-kind serialisation.
type StreamSink struct {
	mu    sync.Mutex
	w     io.Writer
	clock func() time.Time
	enc   *AuditRecordEncoder
}

// NewStreamSink constructs a JSON-lines audit sink.
func NewStreamSink(w io.Writer) *StreamSink {
	return &StreamSink{
		w:     w,
		clock: time.Now,
		enc:   NewAuditRecordEncoder(),
	}
}

// Record writes one complete decision record unless ctx is already cancelled.
func (s *StreamSink) Record(ctx context.Context, ev pipeline.AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := s.enc.Encode(s.withTimestamp(ev))
	if err != nil {
		return err
	}
	return s.write(data)
}

// RecordCompletion writes one best-effort completion record via the encoder's
// completion-kind serialisation. A failure is returned to the caller as a
// completion failure, never as a denial.
func (s *StreamSink) RecordCompletion(ctx context.Context, ev pipeline.AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := s.enc.EncodeCompletion(s.withTimestamp(ev))
	if err != nil {
		return err
	}
	return s.write(data)
}

// withTimestamp defaults a zero event timestamp to the sink clock so records
// always carry a ts.
func (s *StreamSink) withTimestamp(ev pipeline.AuditEvent) pipeline.AuditEvent {
	if ev.Timestamp.IsZero() && s.clock != nil {
		ev.Timestamp = s.clock()
	}
	return ev
}

// write emits one already-encoded NDJSON record under the sink mutex so
// concurrent callers never interleave partial lines.
func (s *StreamSink) write(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.w.Write(data)
	return err
}
