package audit

import (
	"errors"
	"strings"
	"time"

	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// ErrNilRegistry is returned when NewPromMetricsRecorder is given a nil
// registerer.
var ErrNilRegistry = errors.New("audit: nil prometheus registerer")

// PromMetricsRecorder implements the typed, closed-enum MetricsRecorder over a
// Prometheus registry. Every label value flows from a closed enum's String(),
// so an agent-controlled free string can never become a label (S6 §4.1).
type PromMetricsRecorder struct {
	gatherer prometheus.Gatherer

	decisions             *prometheus.CounterVec
	stageDuration         *prometheus.HistogramVec
	snapshotAge           prometheus.Gauge
	snapshotVersion       *prometheus.GaugeVec
	policyCompileFailures prometheus.Counter
	transportReject       *prometheus.CounterVec
	leafCacheHits         prometheus.Counter
	leafCacheMisses       prometheus.Counter
	auditRecords          *prometheus.CounterVec
	auditWriteDuration    prometheus.Histogram
	auditUnavailable      prometheus.Gauge
	caExpiry              prometheus.Gauge

	tokenAcquisitions        *prometheus.CounterVec
	tokenAcquisitionDuration *prometheus.HistogramVec
	tokenCacheHits           *prometheus.CounterVec
	tokenCacheMisses         *prometheus.CounterVec
	tokenCacheEvictions      *prometheus.CounterVec
	tokenRefreshFailures     *prometheus.CounterVec
	tokenBreakerState        *prometheus.GaugeVec

	upstreamRequests *prometheus.CounterVec

	admissionRequests   *prometheus.CounterVec
	admissionDuration   *prometheus.HistogramVec
	admissionRejections *prometheus.CounterVec
	injectorCertExpiry  prometheus.Gauge

	admissionPatchBytes  prometheus.Histogram
	cabundlePatch        *prometheus.CounterVec
	webhookTLSErrors     prometheus.Counter
	proxyCgroupResErrors prometheus.Counter
}

var _ MetricsRecorder = (*PromMetricsRecorder)(nil)

// NewPromMetricsRecorder constructs the core §4 collectors and registers them
// with reg. A nil reg returns ErrNilRegistry; a duplicate registration (e.g.
// re-registering on the same registry) returns the registration error rather
// than panicking.
func NewPromMetricsRecorder(reg prometheus.Registerer) (*PromMetricsRecorder, error) {
	if reg == nil {
		return nil, ErrNilRegistry
	}

	p := &PromMetricsRecorder{
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aksh_decisions_total",
			Help: "Total enforcement decisions by disposition, reason, fault and transport.",
		}, []string{"disposition", "reason", "fault", "transport"}),
		stageDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "aksh_decision_duration_seconds",
			Help: "Per-stage decision latency in seconds.",
		}, []string{"stage"}),
		snapshotAge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "aksh_policy_snapshot_age_seconds",
			Help: "Age of the active policy snapshot in seconds.",
		}),
		snapshotVersion: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "aksh_policy_snapshot_version_info",
			Help: "Info gauge carrying the active policy snapshot version label.",
		}, []string{"version"}),
		policyCompileFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aksh_policy_compile_failures_total",
			Help: "Total policy compilation failures.",
		}),
		transportReject: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aksh_transport_reject_total",
			Help: "Total transport-layer rejections by class and bound.",
		}, []string{"class", "bound"}),
		leafCacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aksh_leaf_cache_hits_total",
			Help: "Total leaf-certificate cache hits.",
		}),
		leafCacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aksh_leaf_cache_misses_total",
			Help: "Total leaf-certificate cache misses.",
		}),
		auditRecords: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aksh_audit_records_total",
			Help: "Total audit records emitted by kind.",
		}, []string{"kind"}),
		auditWriteDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "aksh_audit_write_duration_seconds",
			Help: "Audit sink write latency in seconds.",
		}),
		auditUnavailable: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "aksh_audit_unavailable",
			Help: "1 when the audit path is unavailable (fail-closed), else 0.",
		}),
		caExpiry: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "aksh_ca_expiry_seconds",
			Help: "Seconds until the pod CA certificate expires.",
		}),
		tokenAcquisitions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aksh_token_acquisitions_total",
			Help: "Total token acquisitions by provider, result and error class.",
		}, []string{"provider", "result", "class"}),
		tokenAcquisitionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "aksh_token_acquisition_duration_seconds",
			Help: "Token acquisition latency in seconds by provider.",
		}, []string{"provider"}),
		tokenCacheHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aksh_token_cache_hits_total",
			Help: "Total token cache hits by provider.",
		}, []string{"provider"}),
		tokenCacheMisses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aksh_token_cache_misses_total",
			Help: "Total token cache misses by provider.",
		}, []string{"provider"}),
		tokenCacheEvictions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aksh_token_cache_evictions_total",
			Help: "Total token cache evictions by provider and credential.",
		}, []string{"provider", "credential"}),
		tokenRefreshFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aksh_token_refresh_failures_total",
			Help: "Total token refresh failures by provider and credential.",
		}, []string{"provider", "credential"}),
		tokenBreakerState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "aksh_token_breaker_state",
			Help: "Token acquisition circuit-breaker state (0=closed,1=open,2=half_open) by provider and credential.",
		}, []string{"provider", "credential"}),
		upstreamRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aksh_upstream_requests_total",
			Help: "Total upstream requests by result.",
		}, []string{"result"}),
		admissionRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aksh_admission_requests_total",
			Help: "Total injector admission requests by webhook and result.",
		}, []string{"webhook", "result"}),
		admissionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "aksh_admission_duration_seconds",
			Help: "Injector admission latency in seconds by webhook.",
		}, []string{"webhook"}),
		admissionRejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aksh_admission_rejections_total",
			Help: "Total injector admission rejections by the INV-10 rule that fired.",
		}, []string{"rule"}),
		injectorCertExpiry: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "aksh_injector_cert_expiry_seconds",
			Help: "Seconds until the injector webhook serving certificate expires.",
		}),
		admissionPatchBytes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "aksh_admission_patch_bytes",
			Help: "Size in bytes of the JSONPatch produced by an allowed mutation.",
			// Byte-scale buckets: the default Prometheus buckets (.005-10) are
			// for latency seconds and would collapse every JSONPatch (hundreds
			// to a few thousand bytes) into +Inf, making the histogram useless
			// for percentiles.
			Buckets: []float64{64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384},
		}),
		cabundlePatch: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aksh_webhook_cabundle_patch_total",
			Help: "Total webhook caBundle patch attempts by configuration and result.",
		}, []string{"configuration", "result"}),
		webhookTLSErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aksh_webhook_tls_errors_total",
			Help: "Total webhook TLS handshake or serving-cert load failures.",
		}),
		proxyCgroupResErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aksh_proxy_cgroup_resolution_errors_total",
			Help: "Total proxy pod-cgroup derivation or resolution failures at startup.",
		}),
	}

	collectors := []prometheus.Collector{
		p.decisions,
		p.stageDuration,
		p.snapshotAge,
		p.snapshotVersion,
		p.policyCompileFailures,
		p.transportReject,
		p.leafCacheHits,
		p.leafCacheMisses,
		p.auditRecords,
		p.auditWriteDuration,
		p.auditUnavailable,
		p.caExpiry,
		p.tokenAcquisitions,
		p.tokenAcquisitionDuration,
		p.tokenCacheHits,
		p.tokenCacheMisses,
		p.tokenCacheEvictions,
		p.tokenRefreshFailures,
		p.tokenBreakerState,
		p.upstreamRequests,
		p.admissionRequests,
		p.admissionDuration,
		p.admissionRejections,
		p.injectorCertExpiry,
		p.admissionPatchBytes,
		p.cabundlePatch,
		p.webhookTLSErrors,
		p.proxyCgroupResErrors,
	}
	registered := make([]prometheus.Collector, 0, len(collectors))
	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			// Roll back partial registration so the registry is not left in an
			// inconsistent state and a caller can retry on the same registry.
			for _, r := range registered {
				reg.Unregister(r)
			}
			return nil, err
		}
		registered = append(registered, c)
	}

	if g, ok := reg.(prometheus.Gatherer); ok {
		p.gatherer = g
	}
	return p, nil
}

// Gather exposes the recorder's metric families for prometheus/testutil and
// exposition. It is available only when the recorder was constructed over a
// registerer that is also a Gatherer (the common *prometheus.Registry case).
func (p *PromMetricsRecorder) Gather() ([]*dto.MetricFamily, error) {
	if p.gatherer == nil {
		return nil, errors.New("audit: recorder registerer is not a Gatherer")
	}
	return p.gatherer.Gather()
}

func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Decisions increments aksh_decisions_total.
func (p *PromMetricsRecorder) Decisions(d pipeline.Disposition, r pipeline.DenyReason, transport TransportKind, fault bool) {
	p.decisions.WithLabelValues(d.String(), r.String(), boolLabel(fault), transport.String()).Inc()
}

// StageDuration observes aksh_decision_duration_seconds.
func (p *PromMetricsRecorder) StageDuration(stage StageName, d time.Duration) {
	p.stageDuration.WithLabelValues(stage.String()).Observe(d.Seconds())
}

// TransportReject increments aksh_transport_reject_total.
func (p *PromMetricsRecorder) TransportReject(class RejectClass, bound BoundName) {
	p.transportReject.WithLabelValues(class.String(), bound.String()).Inc()
}

// LeafCacheHit increments aksh_leaf_cache_hits_total.
func (p *PromMetricsRecorder) LeafCacheHit() { p.leafCacheHits.Inc() }

// LeafCacheMiss increments aksh_leaf_cache_misses_total.
func (p *PromMetricsRecorder) LeafCacheMiss() { p.leafCacheMisses.Inc() }

// AuditRecord increments aksh_audit_records_total.
func (p *PromMetricsRecorder) AuditRecord(kind AuditRecordKind) {
	p.auditRecords.WithLabelValues(kind.String()).Inc()
}

// AuditWriteDuration observes aksh_audit_write_duration_seconds.
func (p *PromMetricsRecorder) AuditWriteDuration(d time.Duration) {
	p.auditWriteDuration.Observe(d.Seconds())
}

// AuditUnavailable sets aksh_audit_unavailable to 1/0.
func (p *PromMetricsRecorder) AuditUnavailable(unavailable bool) {
	if unavailable {
		p.auditUnavailable.Set(1)
		return
	}
	p.auditUnavailable.Set(0)
}

// SnapshotAge sets aksh_policy_snapshot_age_seconds.
func (p *PromMetricsRecorder) SnapshotAge(d time.Duration) {
	p.snapshotAge.Set(d.Seconds())
}

// SnapshotVersion sets aksh_policy_snapshot_version_info. The prior version
// series is reset first so the info gauge tracks the single current version
// (operator CRD-edit rate) rather than accreting one series per value.
func (p *PromMetricsRecorder) SnapshotVersion(version string) {
	p.snapshotVersion.Reset()
	p.snapshotVersion.WithLabelValues(sanitiseVersionLabel(version)).Set(1)
}

// sanitiseVersionLabel enforces a structural bound on the one non-enum label on
// the recorder. The version is operator-sourced (CRD generation) and so changes
// at operator rate, but S6 §4.1 is a security property this project does not
// leave to convention: cap the length and restrict to printable ASCII so an
// unexpected value can neither explode label cardinality nor corrupt exposition.
func sanitiseVersionLabel(v string) string {
	const maxLen = 64
	if len(v) > maxLen {
		v = v[:maxLen]
	}
	return strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 {
			return r
		}
		return '_'
	}, v)
}

// PolicyCompileFailure increments aksh_policy_compile_failures_total.
func (p *PromMetricsRecorder) PolicyCompileFailure() { p.policyCompileFailures.Inc() }

// CAExpiry sets aksh_ca_expiry_seconds.
func (p *PromMetricsRecorder) CAExpiry(d time.Duration) { p.caExpiry.Set(d.Seconds()) }

// TokenAcquisition increments aksh_token_acquisitions_total.
func (p *PromMetricsRecorder) TokenAcquisition(provider ProviderID, result Result, class AcquireErrorClass) {
	p.tokenAcquisitions.WithLabelValues(provider.String(), result.String(), class.String()).Inc()
}

// TokenAcquisitionDuration observes aksh_token_acquisition_duration_seconds.
func (p *PromMetricsRecorder) TokenAcquisitionDuration(provider ProviderID, d time.Duration) {
	p.tokenAcquisitionDuration.WithLabelValues(provider.String()).Observe(d.Seconds())
}

// TokenCacheHit increments aksh_token_cache_hits_total.
func (p *PromMetricsRecorder) TokenCacheHit(provider ProviderID) {
	p.tokenCacheHits.WithLabelValues(provider.String()).Inc()
}

// TokenCacheMiss increments aksh_token_cache_misses_total.
func (p *PromMetricsRecorder) TokenCacheMiss(provider ProviderID) {
	p.tokenCacheMisses.WithLabelValues(provider.String()).Inc()
}

// TokenCacheEviction increments aksh_token_cache_evictions_total. The credential
// label is the bounded S3 §2.3 hash, capped by the 256-entry cache.
func (p *PromMetricsRecorder) TokenCacheEviction(provider ProviderID, credential CredentialID) {
	p.tokenCacheEvictions.WithLabelValues(provider.String(), credential.String()).Inc()
}

// TokenRefreshFailure increments aksh_token_refresh_failures_total.
func (p *PromMetricsRecorder) TokenRefreshFailure(provider ProviderID, credential CredentialID) {
	p.tokenRefreshFailures.WithLabelValues(provider.String(), credential.String()).Inc()
}

// TokenBreakerState sets aksh_token_breaker_state to the numeric BreakerState.
func (p *PromMetricsRecorder) TokenBreakerState(provider ProviderID, credential CredentialID, state BreakerState) {
	p.tokenBreakerState.WithLabelValues(provider.String(), credential.String()).Set(float64(state))
}

// UpstreamRequest increments aksh_upstream_requests_total.
func (p *PromMetricsRecorder) UpstreamRequest(result UpstreamResult) {
	p.upstreamRequests.WithLabelValues(result.String()).Inc()
}

// AdmissionRequest increments aksh_admission_requests_total.
func (p *PromMetricsRecorder) AdmissionRequest(webhook WebhookName, result AdmissionResult) {
	p.admissionRequests.WithLabelValues(webhook.String(), result.String()).Inc()
}

// AdmissionDuration observes aksh_admission_duration_seconds.
func (p *PromMetricsRecorder) AdmissionDuration(webhook WebhookName, d time.Duration) {
	p.admissionDuration.WithLabelValues(webhook.String()).Observe(d.Seconds())
}

// AdmissionRejection increments aksh_admission_rejections_total.
func (p *PromMetricsRecorder) AdmissionRejection(rule AdmissionRule) {
	p.admissionRejections.WithLabelValues(rule.String()).Inc()
}

// InjectorCertExpiry sets aksh_injector_cert_expiry_seconds.
func (p *PromMetricsRecorder) InjectorCertExpiry(d time.Duration) {
	p.injectorCertExpiry.Set(d.Seconds())
}

// AdmissionPatchBytes observes aksh_admission_patch_bytes.
func (p *PromMetricsRecorder) AdmissionPatchBytes(nBytes int) {
	// nBytes is a JSONPatch byte length from len(...) and is therefore never
	// negative; it is observed directly.
	p.admissionPatchBytes.Observe(float64(nBytes))
}

// CABundlePatch increments aksh_webhook_cabundle_patch_total.
func (p *PromMetricsRecorder) CABundlePatch(config WebhookConfigName, result PatchResult) {
	p.cabundlePatch.WithLabelValues(config.String(), result.String()).Inc()
}

// WebhookTLSError increments aksh_webhook_tls_errors_total.
func (p *PromMetricsRecorder) WebhookTLSError() { p.webhookTLSErrors.Inc() }

// ProxyCgroupResolutionError increments aksh_proxy_cgroup_resolution_errors_total.
func (p *PromMetricsRecorder) ProxyCgroupResolutionError() { p.proxyCgroupResErrors.Inc() }
