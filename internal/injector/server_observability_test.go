package injector

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/prometheus/client_golang/prometheus"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func obsServer(t *testing.T, inj Injector) (*WebhookServer, *prometheus.Registry, *syncBuffer) {
	t.Helper()
	rec, reg := newTestMetrics(t)
	logger, sb := newCaptureLogger()
	server, err := NewWebhookServer(WebhookServerOptions{}, inj, WithMetrics(rec), WithLogger(logger))
	if err != nil {
		t.Fatalf("NewWebhookServer() error = %v", err)
	}
	return server, reg, sb
}

// 146
func TestMutateAdmission_AllowedRequest_IncrementsAdmissionRequestsMetric(t *testing.T) {
	server, reg, _ := obsServer(t, testInjector{})
	postAdmissionReview(t, server, mutateReview(types.UID("u"), metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, admissionv1.Create))
	fam := metricFamily(t, reg, "aksh_admission_requests_total")
	if got := counterValueWith(fam, map[string]string{"webhook": "mutate", "result": "allowed"}); got != 1 {
		t.Fatalf("aksh_admission_requests_total{mutate,allowed} = %v, want 1", got)
	}
}

// 147
func TestMutateAdmission_DeniedRequest_IncrementsAdmissionDeniedMetric(t *testing.T) {
	server, reg, _ := obsServer(t, testInjector{})
	postAdmissionReview(t, server, mutateReview(types.UID("u"), metav1.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}, admissionv1.Create))
	fam := metricFamily(t, reg, "aksh_admission_requests_total")
	if got := counterValueWith(fam, map[string]string{"webhook": "mutate", "result": "denied"}); got != 1 {
		t.Fatalf("aksh_admission_requests_total{mutate,denied} = %v, want 1", got)
	}
}

// 148
func TestMutateAdmission_DecodeFailure_IncrementsDecodeErrorMetric(t *testing.T) {
	server, reg, _ := obsServer(t, testInjector{})
	rec := httptest.NewRecorder()
	server.HandleMutate(rec, httptest.NewRequest(http.MethodPost, "/mutate", strings.NewReader("{")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	fam := metricFamily(t, reg, "aksh_admission_requests_total")
	if got := counterValueWith(fam, map[string]string{"webhook": "mutate", "result": "errored"}); got != 1 {
		t.Fatalf("aksh_admission_requests_total{mutate,errored} = %v, want 1", got)
	}
}

// 149
func TestMutateAdmission_SuccessfulPatch_ObservesPatchBytesMetric(t *testing.T) {
	server, reg, _ := obsServer(t, testInjector{})
	postAdmissionReview(t, server, mutateReview(types.UID("u"), metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, admissionv1.Create))
	fam := metricFamily(t, reg, "aksh_admission_patch_bytes")
	if fam == nil {
		t.Fatal("aksh_admission_patch_bytes not present")
	}
	if got := histogramSampleCountWith(fam, map[string]string{}); got != 1 {
		t.Fatalf("aksh_admission_patch_bytes sample count = %d, want 1", got)
	}
}

// 150
func TestValidateAdmission_AllowedRequest_IncrementsAdmissionRequestsMetric(t *testing.T) {
	server, reg, _ := obsServer(t, testInjector{})
	postValidateAdmissionReview(t, server, validateReviewForPod(t, workloadPod(), admissionv1.Create, ""))
	fam := metricFamily(t, reg, "aksh_admission_requests_total")
	if got := counterValueWith(fam, map[string]string{"webhook": "validate", "result": "allowed"}); got != 1 {
		t.Fatalf("aksh_admission_requests_total{validate,allowed} = %v, want 1", got)
	}
}

// 151
func TestValidateAdmission_DeniedRequest_IncrementsAdmissionDeniedMetric(t *testing.T) {
	server, reg, _ := obsServer(t, validateErrorInjector{err: AdmissionError{Field: "spec.hostNetwork", Reason: "denied"}})
	postValidateAdmissionReview(t, server, validateReviewForPod(t, workloadPod(), admissionv1.Create, ""))
	fam := metricFamily(t, reg, "aksh_admission_requests_total")
	if got := counterValueWith(fam, map[string]string{"webhook": "validate", "result": "denied"}); got != 1 {
		t.Fatalf("aksh_admission_requests_total{validate,denied} = %v, want 1", got)
	}
}

// 152
func TestValidateAdmission_DecodeFailure_IncrementsDecodeErrorMetric(t *testing.T) {
	server, reg, _ := obsServer(t, testInjector{})
	rec := httptest.NewRecorder()
	server.HandleValidate(rec, httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader("{")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	fam := metricFamily(t, reg, "aksh_admission_requests_total")
	if got := counterValueWith(fam, map[string]string{"webhook": "validate", "result": "errored"}); got != 1 {
		t.Fatalf("aksh_admission_requests_total{validate,errored} = %v, want 1", got)
	}
}

// 153
func TestValidateAdmission_Denial_LogsFieldAndReasonWithoutSecrets(t *testing.T) {
	server, _, sb := obsServer(t, validateErrorInjector{err: AdmissionError{Field: "spec.hostNetwork", Reason: "hostNetwork must be false"}})
	postValidateAdmissionReview(t, server, validateReviewForPod(t, workloadPod(), admissionv1.Create, ""))

	record, ok := findLogRecord(t, sb, "aksh-injector: pod admission denied")
	if !ok {
		t.Fatalf("denial log not found; records=%s", sb.String())
	}
	if record["field"] != "spec.hostNetwork" {
		t.Fatalf("field = %v, want spec.hostNetwork", record["field"])
	}
	if record["reason"] != "hostNetwork must be false" {
		t.Fatalf("reason = %v, want hostNetwork must be false", record["reason"])
	}
	// The bounded denial log must never carry the raw pod object, key material,
	// or a service-account token. The only legitimate fields are namespace,
	// name, uid, field, and reason. Assert that pod-spec markers and the
	// workloadPod() container name/image never appear, and that no PEM key
	// material or JWT/token markers leak. On failure, report only the buffer
	// length so CI logs never echo the (potentially sensitive) leaked content.
	leaked := sb.String()
	for _, sentinel := range []string{
		"PRIVATE KEY", "BEGIN CERTIFICATE", // key material
		"eyJ", "serviceAccountName", "ServiceAccountToken", // token markers
		"containers", "busybox", "workload", // raw pod-spec / workload markers
	} {
		if strings.Contains(leaked, sentinel) {
			t.Fatalf("denial log leaked sensitive marker %q (buffer length: %d bytes)", sentinel, len(leaked))
		}
	}
}

// 176
func TestMutateAdmission_AllowedRequest_LogsPodMutationAllowedWithPatchBytes(t *testing.T) {
	server, _, sb := obsServer(t, testInjector{})
	review := mutateReview(types.UID("pod-uid"), metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, admissionv1.Create)
	review.Request.Namespace = "team-a"
	review.Request.Name = "agent-0"
	postAdmissionReview(t, server, review)

	record, ok := findLogRecord(t, sb, "aksh-injector: pod mutation allowed")
	if !ok {
		t.Fatalf("mutation-allowed log not found; records=%s", sb.String())
	}
	if record["namespace"] != "team-a" {
		t.Fatalf("namespace = %v, want team-a", record["namespace"])
	}
	if record["name"] != "agent-0" {
		t.Fatalf("name = %v, want agent-0", record["name"])
	}
	if record["uid"] != "pod-uid" {
		t.Fatalf("uid = %v, want pod-uid", record["uid"])
	}
	if _, present := record["patchBytes"]; !present {
		t.Fatalf("patchBytes field missing; record=%v", record)
	}
}

// 177
func TestAdmissionHandler_Request_ObservesAdmissionDurationMetricWithOperation(t *testing.T) {
	server, reg, _ := obsServer(t, testInjector{})
	postAdmissionReview(t, server, mutateReview(types.UID("u"), metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, admissionv1.Create))
	postValidateAdmissionReview(t, server, validateReviewForPod(t, workloadPod(), admissionv1.Create, ""))

	fam := metricFamily(t, reg, "aksh_admission_duration_seconds")
	if fam == nil {
		t.Fatal("aksh_admission_duration_seconds not present")
	}
	if got := histogramSampleCountWith(fam, map[string]string{"webhook": "mutate"}); got != 1 {
		t.Fatalf("duration sample count for webhook=mutate = %d, want 1", got)
	}
	if got := histogramSampleCountWith(fam, map[string]string{"webhook": "validate"}); got != 1 {
		t.Fatalf("duration sample count for webhook=validate = %d, want 1", got)
	}
}

// 171
func TestAdmissionHandlers_ConcurrentRequests_DoNotMutateSharedServerConfig(t *testing.T) {
	opts := WebhookServerOptions{
		Addr:                           ":9443",
		MutatingWebhookConfiguration:   testMutatingName,
		ValidatingWebhookConfiguration: testValidatingName,
		ServiceName:                    testServiceName,
		ServiceNamespace:               testServiceNamespace,
	}
	rec, _ := newTestMetrics(t)
	logger, _ := newCaptureLogger()
	server, err := NewWebhookServer(opts, testInjector{}, WithMetrics(rec), WithLogger(logger))
	if err != nil {
		t.Fatalf("NewWebhookServer() error = %v", err)
	}

	optsBefore := server.opts

	mutateBody := mustMarshalReview(t, mutateReview(types.UID("u"), metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, admissionv1.Create))
	validateBody := mustMarshalReview(t, validateReviewForPod(t, workloadPod(), admissionv1.Create, ""))

	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan string, workers*2)
	for i := 0; i < workers; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			r := httptest.NewRecorder()
			server.Handler.ServeHTTP(r, httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(mutateBody)))
			if !responseAllowed(r) {
				errs <- "mutate not allowed"
			}
		}()
		go func() {
			defer wg.Done()
			r := httptest.NewRecorder()
			server.Handler.ServeHTTP(r, httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(validateBody)))
			if !responseAllowed(r) {
				errs <- "validate not allowed"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("non-deterministic response: %s", e)
	}

	if server.opts != optsBefore {
		t.Fatalf("shared server config mutated: before=%#v after=%#v", optsBefore, server.opts)
	}
}

func mustMarshalReview(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func responseAllowed(r *httptest.ResponseRecorder) bool {
	if r.Code != http.StatusOK {
		return false
	}
	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(r.Body.Bytes(), &review); err != nil {
		return false
	}
	return review.Response != nil && review.Response.Allowed
}

var _ = audit.WebhookMutate
