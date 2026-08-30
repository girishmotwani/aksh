// Package audit defines the S6 observability interfaces:
// the audit sink for durable decision records and the metrics recorder.
package audit

import (
	"context"
	"time"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

// AuditSink durably records enforcement decisions. Receives S4's
// immutable AuditEvent, never the mutable RequestContext. Its error
// is the fail-closed trigger (INV-4, INV-6).
type AuditSink interface {
	Record(ctx context.Context, event pipeline.AuditEvent) error
	// RecordCompletion durably-best-effort records the post-allow completion
	// record (F11, stage ⑨). A completion-record write failure is a completion
	// failure, never a denial (§2.2).
	RecordCompletion(ctx context.Context, event pipeline.AuditEvent) error
}

// Clock is the injectable time seam. A nil Clock defaults to a real
// time.Now-backed clock in the constructors that consume it.
type Clock interface {
	Now() time.Time
}

// MetricsRecorder is the cardinality-safe, closed-enum metrics contract of S6.
// Every label parameter is a closed enum type from labels.go (or a pre-existing
// pipeline enum); there is no free-string label field an agent-controlled value
// could be assigned to — that unassignability is the security property S6 §4.1
// protects. Slice 1 declares the core always-on daemon methods; the
// token/upstream/injector methods are added in Slice 2.
type MetricsRecorder interface {
	// Decisions increments aksh_decisions_total{disposition,reason,fault,transport}.
	// The transport label is sourced from the closed TransportKind enum
	// (Findings F16); the design sketch omitted it but UT #44/#75 require it.
	Decisions(d pipeline.Disposition, r pipeline.DenyReason, transport TransportKind, fault bool)
	// StageDuration observes aksh_decision_duration_seconds{stage}.
	StageDuration(stage StageName, d time.Duration)
	// TransportReject increments aksh_transport_reject_total{class,bound}.
	TransportReject(class RejectClass, bound BoundName)
	// LeafCacheHit increments aksh_leaf_cache_hits_total.
	LeafCacheHit()
	// LeafCacheMiss increments aksh_leaf_cache_misses_total.
	LeafCacheMiss()
	// AuditRecord increments aksh_audit_records_total{kind}.
	AuditRecord(kind AuditRecordKind)
	// AuditWriteDuration observes aksh_audit_write_duration_seconds.
	AuditWriteDuration(d time.Duration)
	// AuditUnavailable sets aksh_audit_unavailable to 1/0.
	AuditUnavailable(unavailable bool)
	// SnapshotAge sets aksh_policy_snapshot_age_seconds.
	SnapshotAge(d time.Duration)
	// SnapshotVersion sets aksh_policy_snapshot_version_info{version}. The
	// version label changes at operator CRD-edit rate (documented non-structural
	// bound, UT #73), so a string is acceptable here.
	SnapshotVersion(version string)
	// PolicyCompileFailure increments aksh_policy_compile_failures_total.
	PolicyCompileFailure()
	// CAExpiry sets aksh_ca_expiry_seconds.
	CAExpiry(d time.Duration)

	// --- Slice 2: token metric family (§4) ---

	// TokenAcquisition increments
	// aksh_token_acquisitions_total{provider,result,class}.
	TokenAcquisition(provider ProviderID, result Result, class AcquireErrorClass)
	// TokenAcquisitionDuration observes
	// aksh_token_acquisition_duration_seconds{provider}.
	TokenAcquisitionDuration(provider ProviderID, d time.Duration)
	// TokenCacheHit increments aksh_token_cache_hits_total{provider}.
	TokenCacheHit(provider ProviderID)
	// TokenCacheMiss increments aksh_token_cache_misses_total{provider}.
	TokenCacheMiss(provider ProviderID)
	// TokenCacheEviction increments
	// aksh_token_cache_evictions_total{provider,credential}. The credential
	// label is the bounded S3 §2.3 hash (capped by the 256-entry cache).
	TokenCacheEviction(provider ProviderID, credential CredentialID)
	// TokenRefreshFailure increments
	// aksh_token_refresh_failures_total{provider,credential} (S3 §9
	// silent-degradation detector).
	TokenRefreshFailure(provider ProviderID, credential CredentialID)
	// TokenBreakerState sets the aksh_token_breaker_state{provider,credential}
	// gauge to the numeric BreakerState value.
	TokenBreakerState(provider ProviderID, credential CredentialID, state BreakerState)

	// --- Slice 2: upstream metric family (§4) ---

	// UpstreamRequest increments aksh_upstream_requests_total{result}.
	UpstreamRequest(result UpstreamResult)

	// --- Slice 2: injector metric family (§4) ---

	// AdmissionRequest increments aksh_admission_requests_total{webhook,result}.
	AdmissionRequest(webhook WebhookName, result AdmissionResult)
	// AdmissionDuration observes aksh_admission_duration_seconds{webhook}.
	AdmissionDuration(webhook WebhookName, d time.Duration)
	// AdmissionRejection increments aksh_admission_rejections_total{rule} — the
	// INV-10 admissibility check that fired.
	AdmissionRejection(rule AdmissionRule)
	// InjectorCertExpiry sets aksh_injector_cert_expiry_seconds (no labels).
	InjectorCertExpiry(d time.Duration)

	// --- Slice 6: injector/proxy observability family (§4) ---

	// AdmissionPatchBytes observes aksh_admission_patch_bytes (no labels) — the
	// size in bytes of the JSONPatch produced by an allowed mutation.
	AdmissionPatchBytes(nBytes int)
	// CABundlePatch increments
	// aksh_webhook_cabundle_patch_total{configuration,result}.
	CABundlePatch(config WebhookConfigName, result PatchResult)
	// WebhookTLSError increments aksh_webhook_tls_errors_total (no labels) — a
	// TLS handshake or serving-cert load failure.
	WebhookTLSError()
	// ProxyCgroupResolutionError increments
	// aksh_proxy_cgroup_resolution_errors_total (no labels) — a proxy pod-cgroup
	// derivation or resolution failure at startup.
	ProxyCgroupResolutionError()
}
