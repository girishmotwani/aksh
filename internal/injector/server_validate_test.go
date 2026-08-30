package injector

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func validateReviewForPod(t *testing.T, pod *corev1.Pod, operation admissionv1.Operation, subResource string) admissionv1.AdmissionReview {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:         types.UID("validate-uid"),
			Kind:        metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Operation:   operation,
			SubResource: subResource,
			Object:      runtime.RawExtension{Raw: raw},
		},
	}
}

func postValidateAdmissionReview(t *testing.T, server *WebhookServer, review admissionv1.AdmissionReview) admissionv1.AdmissionReview {
	t.Helper()
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	recorder := httptest.NewRecorder()
	server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response admissionv1.AdmissionReview
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return response
}

func validateServer(t *testing.T, inj Injector) *WebhookServer {
	t.Helper()
	server, err := NewWebhookServer(WebhookServerOptions{}, inj)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

type validateErrorInjector struct{ err error }

func (v validateErrorInjector) Patch(pod *corev1.Pod) (*corev1.Pod, error) { return pod, nil }
func (v validateErrorInjector) Validate(*corev1.Pod) error                 { return v.err }

type recordingValidateInjector struct {
	validated *corev1.Pod
	err       error
}

func (r *recordingValidateInjector) Patch(pod *corev1.Pod) (*corev1.Pod, error) { return pod, nil }
func (r *recordingValidateInjector) Validate(pod *corev1.Pod) error {
	r.validated = pod
	return r.err
}

func TestValidateAdmission_ValidPod_EchoesRequestUID(t *testing.T) {
	server := validateServer(t, testInjector{})
	review := validateReviewForPod(t, workloadPod(), admissionv1.Create, "")
	response := postValidateAdmissionReview(t, server, review)
	if response.Response.UID != review.Request.UID {
		t.Fatalf("response UID = %q, want %q", response.Response.UID, review.Request.UID)
	}
}

func TestValidateAdmission_ValidPod_ReturnsAllowedTrue(t *testing.T) {
	server := validateServer(t, testInjector{})
	response := postValidateAdmissionReview(t, server, validateReviewForPod(t, workloadPod(), admissionv1.Create, ""))
	if !response.Response.Allowed {
		t.Fatalf("Allowed = false, want true: %#v", response.Response.Result)
	}
}

func TestValidateAdmission_AdmissionError_ReturnsAllowedFalseAndHTTP403Status(t *testing.T) {
	server := validateServer(t, validateErrorInjector{err: AdmissionError{Field: "spec.hostNetwork", Reason: "denied"}})
	response := postValidateAdmissionReview(t, server, validateReviewForPod(t, workloadPod(), admissionv1.Create, ""))
	if response.Response.Allowed {
		t.Fatal("Allowed = true, want false")
	}
	if response.Response.Result == nil || response.Response.Result.Code != http.StatusForbidden {
		t.Fatalf("Result = %#v, want code 403", response.Response.Result)
	}
	if response.Response.Result.Message != "spec.hostNetwork: denied" {
		t.Fatalf("Message = %q, want %q", response.Response.Result.Message, "spec.hostNetwork: denied")
	}
}

func TestValidateAdmission_UnexpectedError_ReturnsAllowedFalseAndHTTP500Status(t *testing.T) {
	server := validateServer(t, validateErrorInjector{err: errors.New("boom")})
	response := postValidateAdmissionReview(t, server, validateReviewForPod(t, workloadPod(), admissionv1.Create, ""))
	if response.Response.Allowed {
		t.Fatal("Allowed = true, want false")
	}
	if response.Response.Result == nil || response.Response.Result.Code != http.StatusInternalServerError {
		t.Fatalf("Result = %#v, want code 500", response.Response.Result)
	}
	if response.Response.Result.Message == "" {
		t.Fatal("empty denial message")
	}
}

func TestValidateAdmission_MalformedAdmissionReview_FailsClosed(t *testing.T) {
	server := validateServer(t, testInjector{})
	recorder := httptest.NewRecorder()
	server.HandleValidate(recorder, httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader("{")))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestValidateAdmission_MissingRequest_FailsClosed(t *testing.T) {
	server := validateServer(t, testInjector{})
	response := postValidateAdmissionReview(t, server, admissionv1.AdmissionReview{})
	if response.Response == nil || response.Response.Allowed {
		t.Fatalf("response = %#v, want denied", response.Response)
	}
}

func TestValidateAdmission_NonPodKind_ReturnsAdmissionDenied(t *testing.T) {
	server := validateServer(t, testInjector{})
	review := validateReviewForPod(t, workloadPod(), admissionv1.Create, "")
	review.Request.Kind = metav1.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}
	response := postValidateAdmissionReview(t, server, review)
	if response.Response == nil || response.Response.Allowed {
		t.Fatalf("response = %#v, want denied", response.Response)
	}
}

func TestValidateAdmission_NonCreateNonEphemeralUpdateOperation_ReturnsAdmissionDenied(t *testing.T) {
	server := validateServer(t, testInjector{})
	review := validateReviewForPod(t, workloadPod(), admissionv1.Update, "")
	response := postValidateAdmissionReview(t, server, review)
	if response.Response == nil || response.Response.Allowed {
		t.Fatalf("response = %#v, want denied", response.Response)
	}
}

func TestValidateAdmission_EphemeralContainersUpdate_ValidatesFinalPod(t *testing.T) {
	inj := &recordingValidateInjector{}
	server := validateServer(t, inj)
	review := validateReviewForPod(t, workloadPod(), admissionv1.Update, "ephemeralcontainers")
	response := postValidateAdmissionReview(t, server, review)
	if !response.Response.Allowed {
		t.Fatalf("Allowed = false, want true: %#v", response.Response.Result)
	}
	if inj.validated == nil {
		t.Fatal("Validate was not called for ephemeralcontainers UPDATE")
	}
	if inj.validated.Spec.Containers[0].Name != "workload" {
		t.Fatalf("validated pod = %#v, want decoded final pod", inj.validated.Spec.Containers)
	}
}

func TestValidateAdmission_BodyTooLarge_FailsClosed(t *testing.T) {
	server := validateServer(t, testInjector{})
	recorder := httptest.NewRecorder()
	server.HandleValidate(recorder, httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(strings.Repeat("x", int(maxAdmissionBodyBytes+1)))))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}
