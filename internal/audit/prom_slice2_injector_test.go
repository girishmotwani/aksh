package audit_test

import (
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	dto "github.com/prometheus/client_model/go"
)

// #65
func TestAdmissionRequest_WebhookResult_RecordsTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.AdmissionRequest(audit.WebhookMutate, audit.AdmissionResultAllowed)
	rec.AdmissionRequest(audit.WebhookValidate, audit.AdmissionResultDenied)
	fam := family(t, reg, "aksh_admission_requests_total")
	if got := counterWith(fam, map[string]string{"webhook": "mutate", "result": "allowed"}); got != 1 {
		t.Fatalf("aksh_admission_requests_total{mutate,allowed} = %v, want 1", got)
	}
	if got := counterWith(fam, map[string]string{"webhook": "validate", "result": "denied"}); got != 1 {
		t.Fatalf("aksh_admission_requests_total{validate,denied} = %v, want 1", got)
	}
}

// #66
func TestAdmissionDuration_Webhook_RecordsHistogram(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.AdmissionDuration(audit.WebhookValidate, 3*time.Millisecond)
	fam := family(t, reg, "aksh_admission_duration_seconds")
	if fam == nil {
		t.Fatal("aksh_admission_duration_seconds not present")
	}
	if fam.GetType() != dto.MetricType_HISTOGRAM {
		t.Fatalf("type = %v, want HISTOGRAM", fam.GetType())
	}
	m := fam.GetMetric()[0]
	if labelsOf(m)["webhook"] != "validate" {
		t.Fatalf("webhook label = %q, want validate", labelsOf(m)["webhook"])
	}
	if c := m.GetHistogram().GetSampleCount(); c != 1 {
		t.Fatalf("sample count = %d, want 1", c)
	}
}

// #67
func TestAdmissionRejection_Rule_RecordsTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.AdmissionRejection(audit.AdmissionRuleRunAsUser)
	rec.AdmissionRejection(audit.AdmissionRuleRunAsUser)
	rec.AdmissionRejection(audit.AdmissionRuleCapabilities)
	fam := family(t, reg, "aksh_admission_rejections_total")
	if got := counterWith(fam, map[string]string{"rule": "run_as_user"}); got != 2 {
		t.Fatalf("aksh_admission_rejections_total{run_as_user} = %v, want 2", got)
	}
	if got := counterWith(fam, map[string]string{"rule": "capabilities"}); got != 1 {
		t.Fatalf("aksh_admission_rejections_total{capabilities} = %v, want 1", got)
	}
}

// #68
func TestInjectorCertExpiry_NoLabels_SetsGauge(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.InjectorCertExpiry(90 * time.Minute)
	fam := family(t, reg, "aksh_injector_cert_expiry_seconds")
	if fam == nil {
		t.Fatal("aksh_injector_cert_expiry_seconds not present")
	}
	if fam.GetType() != dto.MetricType_GAUGE {
		t.Fatalf("type = %v, want GAUGE", fam.GetType())
	}
	m := fam.GetMetric()[0]
	if len(m.GetLabel()) != 0 {
		t.Fatalf("labels = %v, want none", m.GetLabel())
	}
	if got := m.GetGauge().GetValue(); got != (90 * time.Minute).Seconds() {
		t.Fatalf("aksh_injector_cert_expiry_seconds = %v, want %v", got, (90 * time.Minute).Seconds())
	}
}
