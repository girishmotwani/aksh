package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

// Bounded defaults applied when the constructor receives non-positive values.
const (
	// defaultBufferSize bounds the number of records that may be in flight
	// before backpressure denies; the buffer is never unbounded (INV, §2).
	defaultBufferSize = 256
	// defaultFlushInterval is the short batching interval applied when the
	// caller passes a zero interval so batching still occurs.
	defaultFlushInterval = 100 * time.Millisecond
	// bufferFullGrace is the brief bounded block a decision Record tolerates
	// on a full buffer before returning a terminal audit failure (deny).
	bufferFullGrace = 25 * time.Millisecond
)

// ErrSinkClosed is returned by Record/RecordCompletion after Close.
var ErrSinkClosed = errors.New("buffered audit sink closed")

// ErrAuditBufferFull is the terminal audit failure returned when the bounded
// buffer is full and a decision record cannot be admitted; the caller must
// deny rather than let evidence queue unbounded.
var ErrAuditBufferFull = errors.New("audit buffer full")

// realClock is the default time seam used when a nil Clock is supplied.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// bsSubmission is one record handed to the serialized writer goroutine.
type bsSubmission struct {
	data []byte
	kind AuditRecordKind
	// done is non-nil only for decision records, whose caller blocks until
	// the record is part of a completed write(2) (durable, INV-6).
	done chan error
}

// BufferedSink is the durable, bounded, batching AuditSink. A single writer
// goroutine drains a bounded channel and coalesces submissions into one
// write(2) per flush, so records never interleave and a decision caller blocks
// until its batch has completed a write (ADR-S6-01: durable == completed
// write(2), no fsync).
type BufferedSink struct {
	w        io.Writer
	enc      *AuditRecordEncoder
	metrics  MetricsRecorder
	clock    Clock
	interval time.Duration
	bufSize  int

	queue    chan bsSubmission
	flushReq chan chan struct{}

	closeOnce sync.Once
	closeCh   chan struct{}
	doneCh    chan struct{}
}

// NewBufferedSink constructs the durable buffered sink and starts its writer
// goroutine. A nil writer is a construction error; non-positive buffer/flush
// values clamp to bounded defaults; a nil clock defaults to time.Now.
func NewBufferedSink(w io.Writer, bufSize int, flush time.Duration, clock Clock, enc *AuditRecordEncoder, m MetricsRecorder) (*BufferedSink, error) {
	if w == nil {
		return nil, errors.New("buffered audit sink requires a non-nil writer")
	}
	if bufSize <= 0 {
		bufSize = defaultBufferSize
	}
	if flush <= 0 {
		flush = defaultFlushInterval
	}
	if clock == nil {
		clock = realClock{}
	}
	if enc == nil {
		enc = NewAuditRecordEncoder()
	}
	s := &BufferedSink{
		w:        w,
		enc:      enc,
		metrics:  m,
		clock:    clock,
		interval: flush,
		bufSize:  bufSize,
		queue:    make(chan bsSubmission, bufSize),
		flushReq: make(chan chan struct{}),
		closeCh:  make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	go s.run()
	return s, nil
}

// run is the single serialized writer goroutine: it accumulates submissions
// into a batch and flushes on a full batch, on the interval timer, on an
// explicit Flush, and finally on Close.
func (s *BufferedSink) run() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	var batch []bsSubmission
	failed := false

	flush := func() {
		if len(batch) == 0 {
			return
		}
		var buf bytes.Buffer
		for _, sub := range batch {
			buf.Write(sub.data)
		}
		start := s.clock.Now()
		_, err := s.w.Write(buf.Bytes())
		dur := s.clock.Now().Sub(start)
		if s.metrics != nil {
			s.metrics.AuditWriteDuration(dur)
		}
		for _, sub := range batch {
			if err == nil && s.metrics != nil {
				s.metrics.AuditRecord(sub.kind)
			}
			if sub.done != nil {
				sub.done <- err
			}
		}
		if err != nil {
			if !failed {
				failed = true
				if s.metrics != nil {
					s.metrics.AuditUnavailable(true)
				}
			}
		} else if failed {
			failed = false
			if s.metrics != nil {
				s.metrics.AuditUnavailable(false)
			}
		}
		batch = batch[:0]
	}

	// drain moves every already-submitted record still sitting in the bounded
	// queue into the current batch without blocking. It is used before an
	// explicit Flush so Flush guarantees that everything enqueued before the
	// call is part of the resulting write(2) — otherwise the writer's select
	// could service the flush request before the queued submission and leave it
	// unwritten until the next tick.
	drain := func() {
		for {
			select {
			case sub := <-s.queue:
				batch = append(batch, sub)
			default:
				return
			}
		}
	}

	for {
		select {
		case sub := <-s.queue:
			batch = append(batch, sub)
			if len(batch) >= s.bufSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case ack := <-s.flushReq:
			drain()
			flush()
			close(ack)
		case <-s.closeCh:
			for {
				select {
				case sub := <-s.queue:
					batch = append(batch, sub)
				default:
					flush()
					close(s.doneCh)
					return
				}
			}
		}
	}
}

// Record durably records a decision, blocking the caller until the record is
// part of a completed write(2) (stage ⑥, INV-6). A full bounded buffer blocks
// briefly then returns a terminal audit failure (deny); write(2) errors and an
// exceeded S4 detached deadline also surface as terminal failures.
func (s *BufferedSink) Record(ctx context.Context, ev pipeline.AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-s.closeCh:
		return ErrSinkClosed
	default:
	}

	data, err := s.enc.Encode(ev)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	sub := bsSubmission{data: data, kind: AuditRecordDecision, done: done}

	grace := time.NewTimer(bufferFullGrace)
	defer grace.Stop()
	select {
	case s.queue <- sub:
	case <-ctx.Done():
		return fmt.Errorf("audit record aborted before durable: %w", ctx.Err())
	case <-s.closeCh:
		return ErrSinkClosed
	case <-grace.C:
		return ErrAuditBufferFull
	}

	select {
	case werr := <-done:
		if werr != nil {
			return fmt.Errorf("audit write failed: %w", werr)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("audit record deadline exceeded: %w", ctx.Err())
	case <-s.closeCh:
		select {
		case werr := <-done:
			if werr != nil {
				return fmt.Errorf("audit write failed: %w", werr)
			}
			return nil
		default:
			return ErrSinkClosed
		}
	}
}

// RecordCompletion best-effort records a completion (stage ⑨). It never blocks
// the caller on a flush and never denies: a full buffer or a later write
// failure loses detail, not evidence (§2.2).
func (s *BufferedSink) RecordCompletion(ctx context.Context, ev pipeline.AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-s.closeCh:
		return ErrSinkClosed
	default:
	}

	data, err := s.enc.EncodeCompletion(ev)
	if err != nil {
		return err
	}
	sub := bsSubmission{data: data, kind: AuditRecordCompletion}

	select {
	case s.queue <- sub:
	default:
		// Best-effort: drop rather than block or deny.
	}
	return nil
}

// Flush forces the accumulated batch to be written now.
func (s *BufferedSink) Flush() {
	select {
	case <-s.closeCh:
		return
	default:
	}
	ack := make(chan struct{})
	select {
	case s.flushReq <- ack:
		<-ack
	case <-s.closeCh:
	}
}

// Close flushes any buffered records and stops the writer goroutine. It is
// idempotent.
func (s *BufferedSink) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
	<-s.doneCh
	return nil
}
