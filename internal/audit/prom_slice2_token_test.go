package audit_test

import (
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	dto "github.com/prometheus/client_model/go"
)

// gaugeWith returns the gauge value for the series whose labels match want, or
// -1 if no such series exists.
func gaugeWith(fam *dto.MetricFamily, want map[string]string) float64 {
	if fam == nil {
		return -1
	}
	for _, m := range fam.GetMetric() {
		got := labelsOf(m)
		if len(got) != len(want) {
			continue
		}
		match := true
		for k, v := range want {
			if got[k] != v {
				match = false
				break
			}
		}
		if match {
			return m.GetGauge().GetValue()
		}
	}
	return -1
}

// #47
func TestTokenAcquisition_ProviderResultClass_RecordsTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.TokenAcquisition(audit.ProviderEntra, audit.ResultFailure, audit.AcquireErrorTransient)
	fam := family(t, reg, "aksh_token_acquisitions_total")
	want := map[string]string{
		"provider": "entra",
		"result":   "failure",
		"class":    "transient",
	}
	if got := counterWith(fam, want); got != 1 {
		t.Fatalf("aksh_token_acquisitions_total%v = %v, want 1", want, got)
	}
}

// #48
func TestTokenAcquisitionDuration_Provider_RecordsHistogram(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.TokenAcquisitionDuration(audit.ProviderEntra, 7*time.Millisecond)
	fam := family(t, reg, "aksh_token_acquisition_duration_seconds")
	if fam == nil {
		t.Fatal("aksh_token_acquisition_duration_seconds not present")
	}
	if fam.GetType() != dto.MetricType_HISTOGRAM {
		t.Fatalf("type = %v, want HISTOGRAM", fam.GetType())
	}
	m := fam.GetMetric()[0]
	if labelsOf(m)["provider"] != "entra" {
		t.Fatalf("provider label = %q, want entra", labelsOf(m)["provider"])
	}
	if c := m.GetHistogram().GetSampleCount(); c != 1 {
		t.Fatalf("sample count = %d, want 1", c)
	}
}

// #49
func TestTokenCacheHit_Provider_RecordsHitsTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.TokenCacheHit(audit.ProviderEntra)
	rec.TokenCacheHit(audit.ProviderEntra)
	fam := family(t, reg, "aksh_token_cache_hits_total")
	if got := counterWith(fam, map[string]string{"provider": "entra"}); got != 2 {
		t.Fatalf("aksh_token_cache_hits_total{provider=entra} = %v, want 2", got)
	}
}

// #50
func TestTokenCacheMiss_Provider_RecordsMissesTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.TokenCacheMiss(audit.ProviderEntra)
	fam := family(t, reg, "aksh_token_cache_misses_total")
	if got := counterWith(fam, map[string]string{"provider": "entra"}); got != 1 {
		t.Fatalf("aksh_token_cache_misses_total{provider=entra} = %v, want 1", got)
	}
}

// #51
func TestTokenCacheEviction_ProviderCredential_RecordsTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.TokenCacheEviction(audit.ProviderEntra, audit.CredentialID("cafebabe"))
	fam := family(t, reg, "aksh_token_cache_evictions_total")
	want := map[string]string{"provider": "entra", "credential": "cafebabe"}
	if got := counterWith(fam, want); got != 1 {
		t.Fatalf("aksh_token_cache_evictions_total%v = %v, want 1", want, got)
	}
}

// #52
func TestTokenRefreshFailure_ProviderCredential_RecordsTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.TokenRefreshFailure(audit.ProviderEntra, audit.CredentialID("cafebabe"))
	fam := family(t, reg, "aksh_token_refresh_failures_total")
	want := map[string]string{"provider": "entra", "credential": "cafebabe"}
	if got := counterWith(fam, want); got != 1 {
		t.Fatalf("aksh_token_refresh_failures_total%v = %v, want 1", want, got)
	}
}

// #53
func TestTokenBreakerState_ProviderCredential_SetsGauge(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.TokenBreakerState(audit.ProviderEntra, audit.CredentialID("cafebabe"), audit.BreakerOpen)
	fam := family(t, reg, "aksh_token_breaker_state")
	if fam == nil {
		t.Fatal("aksh_token_breaker_state not present")
	}
	if fam.GetType() != dto.MetricType_GAUGE {
		t.Fatalf("type = %v, want GAUGE", fam.GetType())
	}
	want := map[string]string{"provider": "entra", "credential": "cafebabe"}
	if got := gaugeWith(fam, want); got != float64(audit.BreakerOpen) {
		t.Fatalf("aksh_token_breaker_state%v = %v, want %v", want, got, float64(audit.BreakerOpen))
	}
}
