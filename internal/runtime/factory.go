package runtime

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/dataplane/listener"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

// MakeProductionListenerFactory returns an injectable production ListenerFactory
// that threads the given real destination resolver and typed metrics recorder
// into listener.New. The returned closure parses and validates
// cfg.Listener.Address (IPv4-loopback defense-in-depth) before binding, exactly
// as the noop-defaulted ProductionListenerFactory did. S5 binds this with the
// real BPF resolver + PromMetricsRecorder from run() (exported so cmd/aksh-proxy
// package main can construct the factory directly).
func MakeProductionListenerFactory(resolver dataplane.DestinationResolver, m audit.MetricsRecorder) ListenerFactory {
	return func(cfg config.Config, h listener.ConnHandler, log *slog.Logger) (Listener, error) {
		addr, err := netip.ParseAddrPort(cfg.Listener.Address)
		if err != nil {
			return nil, fmt.Errorf("runtime: invalid listener address %q: %w", cfg.Listener.Address, err)
		}
		// Defense-in-depth: enforce the IPv4-loopback invariant at the point
		// that actually hands the address to the kernel, independent of whether
		// the caller invoked config.Validate first. This factory must never
		// bind a non-loopback address regardless of call site.
		if ip := addr.Addr().Unmap(); !ip.Is4() || !ip.IsLoopback() {
			return nil, fmt.Errorf("runtime: listener address %q must be IPv4 loopback", cfg.Listener.Address)
		}
		opts := listener.DefaultOptions()
		opts.ListenAddr = addr
		return listener.New(opts, resolver, h, m, log)
	}
}

// ProductionListenerFactory is the noop-defaulted fallback kept for the
// orchestrator nil-default and cmd/aksh-proxy until S5 injects
// MakeProductionListenerFactory directly. It delegates to
// MakeProductionListenerFactory with the local no-op resolver and metrics.
func ProductionListenerFactory(cfg config.Config, h listener.ConnHandler, log *slog.Logger) (Listener, error) {
	return MakeProductionListenerFactory(noopResolver{}, noopTypedMetrics{})(cfg, h, log)
}

// noopResolver satisfies dataplane.DestinationResolver. The 5A listener stores
// but does not read the resolver, so returning an error here is never reached
// on the skeleton serve path; a later slice supplies the real BPF resolver.
type noopResolver struct{}

func (noopResolver) Resolve(net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, fmt.Errorf("runtime: destination resolver not wired in slice 1")
}

// noopTypedMetrics satisfies the typed audit.MetricsRecorder with no-op
// recording. It is the default for the orchestrator's typed DataMetrics seam
// when no real PromMetricsRecorder is injected.
type noopTypedMetrics struct{}

func (noopTypedMetrics) Decisions(pipeline.Disposition, pipeline.DenyReason, audit.TransportKind, bool) {
}
func (noopTypedMetrics) StageDuration(audit.StageName, time.Duration)       {}
func (noopTypedMetrics) TransportReject(audit.RejectClass, audit.BoundName) {}
func (noopTypedMetrics) LeafCacheHit()                                      {}
func (noopTypedMetrics) LeafCacheMiss()                                     {}
func (noopTypedMetrics) AuditRecord(audit.AuditRecordKind)                  {}
func (noopTypedMetrics) AuditWriteDuration(time.Duration)                   {}
func (noopTypedMetrics) AuditUnavailable(bool)                              {}
func (noopTypedMetrics) SnapshotAge(time.Duration)                          {}
func (noopTypedMetrics) SnapshotVersion(string)                             {}
func (noopTypedMetrics) PolicyCompileFailure()                              {}
func (noopTypedMetrics) CAExpiry(time.Duration)                             {}
func (noopTypedMetrics) TokenAcquisition(audit.ProviderID, audit.Result, audit.AcquireErrorClass) {
}
func (noopTypedMetrics) TokenAcquisitionDuration(audit.ProviderID, time.Duration) {}
func (noopTypedMetrics) TokenCacheHit(audit.ProviderID)                           {}
func (noopTypedMetrics) TokenCacheMiss(audit.ProviderID)                          {}
func (noopTypedMetrics) TokenCacheEviction(audit.ProviderID, audit.CredentialID)  {}
func (noopTypedMetrics) TokenRefreshFailure(audit.ProviderID, audit.CredentialID) {}
func (noopTypedMetrics) TokenBreakerState(audit.ProviderID, audit.CredentialID, audit.BreakerState) {
}
func (noopTypedMetrics) UpstreamRequest(audit.UpstreamResult)                      {}
func (noopTypedMetrics) AdmissionRequest(audit.WebhookName, audit.AdmissionResult) {}
func (noopTypedMetrics) AdmissionDuration(audit.WebhookName, time.Duration)        {}
func (noopTypedMetrics) AdmissionRejection(audit.AdmissionRule)                    {}
func (noopTypedMetrics) InjectorCertExpiry(time.Duration)                          {}
func (noopTypedMetrics) AdmissionPatchBytes(int)                                   {}
func (noopTypedMetrics) CABundlePatch(audit.WebhookConfigName, audit.PatchResult)  {}
func (noopTypedMetrics) WebhookTLSError()                                          {}
func (noopTypedMetrics) ProxyCgroupResolutionError()                               {}

// Compile-time assertions that the local no-ops satisfy the dataplane/audit
// contracts and that the real listener satisfies the runtime Listener seam.
var (
	_ dataplane.DestinationResolver = noopResolver{}
	_ audit.MetricsRecorder         = noopTypedMetrics{}
	_ Listener                      = (*listener.Listener)(nil)
)
