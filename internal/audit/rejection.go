package audit

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

const defaultRejectionAuditTimeout = 250 * time.Millisecond

// Rejection is the audit-facing description of a refusal that never reached
// the policy pipeline.
type Rejection struct {
	Class     string
	Reason    pipeline.DenyReason
	Bound     string
	Fault     bool
	RequestID string
	ConnID    string
	Port      uint16
	Method    string
	Path      string
}

// RejectionRecorder emits bounded, detached audit records for refusals.
type RejectionRecorder struct {
	sink    AuditSink
	metrics MetricsRecorder
	timeout time.Duration
	slots   chan struct{}
	dropped atomic.Uint64
	emerg   func(format string, args ...any)
}

// NewRejectionRecorder constructs a bounded rejection recorder.
func NewRejectionRecorder(
	sink AuditSink,
	metrics MetricsRecorder,
	maxConcurrent int,
	timeout time.Duration,
	emerg func(format string, args ...any),
) *RejectionRecorder {
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	if timeout <= 0 {
		timeout = defaultRejectionAuditTimeout
	}
	return &RejectionRecorder{
		sink:    sink,
		metrics: metrics,
		timeout: timeout,
		slots:   make(chan struct{}, maxConcurrent),
		emerg:   emerg,
	}
}

// Record emits one rejection record without blocking the caller on the sink.
func (r *RejectionRecorder) Record(rej Rejection) {
	if r == nil {
		return
	}
	if !r.tryAcquire() {
		r.dropped.Add(1)
		r.emergencyf("rejection audit dropped: %s", rejectionMetricReason(rej))
		return
	}

	if r.metrics != nil {
		r.metrics.TransportReject(RejectClassFromString(rej.Class), BoundNameFromString(rej.Bound))
	}

	go func() {
		defer r.release()
		if r.sink == nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
		defer cancel()

		if err := r.sink.Record(ctx, rejectionAuditEvent(rej)); err != nil {
			r.emergencyf("rejection audit failed: %v", err)
		}
	}()
}

// Dropped reports the number of shed records.
func (r *RejectionRecorder) Dropped() uint64 {
	if r == nil {
		return 0
	}
	return r.dropped.Load()
}

func (r *RejectionRecorder) tryAcquire() bool {
	select {
	case r.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (r *RejectionRecorder) release() {
	select {
	case <-r.slots:
	default:
		panic("audit: rejection recorder release without acquire")
	}
}

func (r *RejectionRecorder) emergencyf(format string, args ...any) {
	if r != nil && r.emerg != nil {
		r.emerg(format, args...)
	}
}

func rejectionAuditEvent(rej Rejection) pipeline.AuditEvent {
	faultClass := pipeline.FaultClassNone
	if rej.Fault {
		faultClass = pipeline.FaultClassLocal
	}

	return pipeline.AuditEvent{
		Timestamp:    time.Now(),
		RequestID:    rej.RequestID,
		Method:       rej.Method,
		Path:         rej.Path,
		Port:         rej.Port,
		Disposition:  pipeline.DispositionDeny,
		DenyReason:   rej.Reason,
		Fault:        rej.Fault,
		FaultClass:   faultClass,
		CredentialID: "none",
	}
}

func rejectionMetricReason(rej Rejection) string {
	if rej.Class == "" {
		return rej.Reason.String()
	}
	if rej.Bound != "" {
		return fmt.Sprintf("%s:%s", rej.Class, rej.Bound)
	}
	return rej.Class
}
