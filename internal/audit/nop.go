package audit

import (
	"time"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

// NopMetricsRecorder is a no-op MetricsRecorder. It is the default recorder for
// dataplane collaborators (e.g. the TLS terminator/leaf source) and runtime
// seams that have no real Prometheus backend injected, so callers never need a
// nil check before recording. Every method discards its arguments.
type NopMetricsRecorder struct{}

var _ MetricsRecorder = NopMetricsRecorder{}

func (NopMetricsRecorder) Decisions(pipeline.Disposition, pipeline.DenyReason, TransportKind, bool) {
}
func (NopMetricsRecorder) StageDuration(StageName, time.Duration)                   {}
func (NopMetricsRecorder) TransportReject(RejectClass, BoundName)                   {}
func (NopMetricsRecorder) LeafCacheHit()                                            {}
func (NopMetricsRecorder) LeafCacheMiss()                                           {}
func (NopMetricsRecorder) AuditRecord(AuditRecordKind)                              {}
func (NopMetricsRecorder) AuditWriteDuration(time.Duration)                         {}
func (NopMetricsRecorder) AuditUnavailable(bool)                                    {}
func (NopMetricsRecorder) SnapshotAge(time.Duration)                                {}
func (NopMetricsRecorder) SnapshotVersion(string)                                   {}
func (NopMetricsRecorder) PolicyCompileFailure()                                    {}
func (NopMetricsRecorder) CAExpiry(time.Duration)                                   {}
func (NopMetricsRecorder) TokenAcquisition(ProviderID, Result, AcquireErrorClass)   {}
func (NopMetricsRecorder) TokenAcquisitionDuration(ProviderID, time.Duration)       {}
func (NopMetricsRecorder) TokenCacheHit(ProviderID)                                 {}
func (NopMetricsRecorder) TokenCacheMiss(ProviderID)                                {}
func (NopMetricsRecorder) TokenCacheEviction(ProviderID, CredentialID)              {}
func (NopMetricsRecorder) TokenRefreshFailure(ProviderID, CredentialID)             {}
func (NopMetricsRecorder) TokenBreakerState(ProviderID, CredentialID, BreakerState) {}
func (NopMetricsRecorder) UpstreamRequest(UpstreamResult)                           {}
func (NopMetricsRecorder) AdmissionRequest(WebhookName, AdmissionResult)            {}
func (NopMetricsRecorder) AdmissionDuration(WebhookName, time.Duration)             {}
func (NopMetricsRecorder) AdmissionRejection(AdmissionRule)                         {}
func (NopMetricsRecorder) InjectorCertExpiry(time.Duration)                         {}
func (NopMetricsRecorder) AdmissionPatchBytes(int)                                  {}
func (NopMetricsRecorder) CABundlePatch(WebhookConfigName, PatchResult)             {}
func (NopMetricsRecorder) WebhookTLSError()                                         {}
func (NopMetricsRecorder) ProxyCgroupResolutionError()                              {}
