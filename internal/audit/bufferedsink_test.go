package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

// bsClock is a manual clock seam for BufferedSink tests.
type bsClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *bsClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.t.IsZero() {
		c.t = time.Unix(0, 0)
	}
	c.t = c.t.Add(time.Millisecond)
	return c.t
}

// bsWriter is a controllable io.Writer test double: it records every write,
// can fail, and can gate each Write on a channel to simulate a slow/blocked
// syscall.
type bsWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	writes int
	chunks [][]byte
	err    error
	gate   chan struct{}
}

func (w *bsWriter) Write(p []byte) (int, error) {
	if w.gate != nil {
		<-w.gate
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	w.writes++
	cp := append([]byte(nil), p...)
	w.chunks = append(w.chunks, cp)
	return w.buf.Write(p)
}

func (w *bsWriter) bytesWritten() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

func (w *bsWriter) writeCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writes
}

func (w *bsWriter) writeChunks() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([][]byte, len(w.chunks))
	for i, c := range w.chunks {
		out[i] = append([]byte(nil), c...)
	}
	return out
}

func (w *bsWriter) setErr(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.err = err
}

// bsMetrics captures the audit metric calls BufferedSink emits.
type bsMetrics struct {
	mu          sync.Mutex
	records     []AuditRecordKind
	writeDurs   []time.Duration
	unavailable []bool
}

func (m *bsMetrics) AuditRecord(kind AuditRecordKind) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = append(m.records, kind)
}

func (m *bsMetrics) AuditWriteDuration(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writeDurs = append(m.writeDurs, d)
}

func (m *bsMetrics) AuditUnavailable(unavailable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unavailable = append(m.unavailable, unavailable)
}

func (m *bsMetrics) recordKinds() []AuditRecordKind {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]AuditRecordKind(nil), m.records...)
}

func (m *bsMetrics) writeDurationCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.writeDurs)
}

func (m *bsMetrics) unavailableCalls() []bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]bool(nil), m.unavailable...)
}

// The remaining MetricsRecorder methods are no-ops for these tests.
func (m *bsMetrics) Decisions(pipeline.Disposition, pipeline.DenyReason, TransportKind, bool) {}
func (m *bsMetrics) StageDuration(StageName, time.Duration)                                   {}
func (m *bsMetrics) TransportReject(RejectClass, BoundName)                                   {}
func (m *bsMetrics) LeafCacheHit()                                                            {}
func (m *bsMetrics) LeafCacheMiss()                                                           {}
func (m *bsMetrics) SnapshotAge(time.Duration)                                                {}
func (m *bsMetrics) SnapshotVersion(string)                                                   {}
func (m *bsMetrics) PolicyCompileFailure()                                                    {}
func (m *bsMetrics) PolicyStaleDeny()                                                         {}
func (m *bsMetrics) PolicyListForbidden()                                                     {}
func (m *bsMetrics) CAExpiry(time.Duration)                                                   {}
func (m *bsMetrics) TokenAcquisition(ProviderID, Result, AcquireErrorClass)                   {}
func (m *bsMetrics) TokenAcquisitionDuration(ProviderID, time.Duration)                       {}
func (m *bsMetrics) TokenCacheHit(ProviderID)                                                 {}
func (m *bsMetrics) TokenCacheMiss(ProviderID)                                                {}
func (m *bsMetrics) TokenCacheEviction(ProviderID, CredentialID)                              {}
func (m *bsMetrics) TokenRefreshFailure(ProviderID, CredentialID)                             {}
func (m *bsMetrics) TokenBreakerState(ProviderID, CredentialID, BreakerState)                 {}
func (m *bsMetrics) UpstreamRequest(UpstreamResult)                                           {}
func (m *bsMetrics) AdmissionRequest(WebhookName, AdmissionResult)                            {}
func (m *bsMetrics) AdmissionDuration(WebhookName, time.Duration)                             {}
func (m *bsMetrics) AdmissionRejection(AdmissionRule)                                         {}
func (m *bsMetrics) InjectorCertExpiry(time.Duration)                                         {}
func (m *bsMetrics) AdmissionPatchBytes(int)                                                  {}
func (m *bsMetrics) CABundlePatch(WebhookConfigName, PatchResult)                             {}
func (m *bsMetrics) WebhookTLSError()                                                         {}
func (m *bsMetrics) ProxyCgroupResolutionError()                                              {}

// sampleEvent returns a fully-populated decision AuditEvent for write-path tests.
func sampleEvent(requestID string) pipeline.AuditEvent {
	return pipeline.AuditEvent{
		Timestamp:    time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		RequestID:    requestID,
		Identity:     "sa-agent",
		Method:       "GET",
		Path:         "/v1/models",
		Port:         443,
		PodNamespace: "team-a",
		PodName:      "agent-0",
		PodUID:       "uid-123",
	}
}

var _ io.Writer = (*bsWriter)(nil)
var _ MetricsRecorder = (*bsMetrics)(nil)
var _ = errors.New
var _ = context.Background
