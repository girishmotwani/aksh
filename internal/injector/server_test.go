package injector

import (
	"bytes"
	"encoding/json"
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

func TestMutateAdmission_ValidPod_EchoesRequestUID(t *testing.T) {
	server := newTestWebhookServer(t)
	review := mutateReview(types.UID("request-uid"), metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, admissionv1.Create)

	response := postAdmissionReview(t, server, review)

	if response.Response.UID != review.Request.UID {
		t.Fatalf("response UID = %q, want %q", response.Response.UID, review.Request.UID)
	}
}

func TestMutateAdmission_ValidPod_ReturnsAllowedTrue(t *testing.T) {
	server := newTestWebhookServer(t)
	review := mutateReview(types.UID("request-uid"), metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, admissionv1.Create)

	response := postAdmissionReview(t, server, review)

	if !response.Response.Allowed {
		t.Fatal("response Allowed = false, want true")
	}
}

func TestMutateAdmission_MalformedAdmissionReview_FailsClosed(t *testing.T) {
	server := newTestWebhookServer(t)
	request := httptest.NewRequest(http.MethodPost, "/mutate", strings.NewReader("{"))
	recorder := httptest.NewRecorder()

	server.HandleMutate(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestMutateAdmission_MissingRequest_FailsClosed(t *testing.T) {
	server := newTestWebhookServer(t)
	response := postAdmissionReview(t, server, admissionv1.AdmissionReview{})

	if response.Response == nil || response.Response.Allowed {
		t.Fatalf("response = %#v, want denied AdmissionReview response", response.Response)
	}
}

func TestMutateAdmission_NonPodKind_ReturnsAdmissionDenied(t *testing.T) {
	server := newTestWebhookServer(t)
	review := mutateReview(types.UID("request-uid"), metav1.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}, admissionv1.Create)

	response := postAdmissionReview(t, server, review)

	if response.Response == nil || response.Response.Allowed {
		t.Fatalf("response = %#v, want denied AdmissionReview response", response.Response)
	}
}

func TestMutateAdmission_NonCreateOperation_ReturnsAdmissionDenied(t *testing.T) {
	server := newTestWebhookServer(t)
	review := mutateReview(types.UID("request-uid"), metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, admissionv1.Update)

	response := postAdmissionReview(t, server, review)

	if response.Response == nil || response.Response.Allowed {
		t.Fatalf("response = %#v, want denied AdmissionReview response", response.Response)
	}
}

func TestMutateAdmission_BodyTooLarge_FailsClosed(t *testing.T) {
	server := newTestWebhookServer(t)
	request := httptest.NewRequest(http.MethodPost, "/mutate", strings.NewReader(strings.Repeat("x", int(maxAdmissionBodyBytes+1))))
	recorder := httptest.NewRecorder()

	server.HandleMutate(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestWebhookServer_HealthzProcessAlive_ReturnsOKWithoutCABundleReadiness(t *testing.T) {
	server := newTestWebhookServer(t)

	healthz := httptest.NewRecorder()
	server.Handler.ServeHTTP(healthz, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if healthz.Code != http.StatusOK {
		t.Fatalf("/healthz status = %d, want %d", healthz.Code, http.StatusOK)
	}

	readyz := httptest.NewRecorder()
	server.Handler.ServeHTTP(readyz, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if readyz.Code == http.StatusOK {
		t.Fatal("/readyz status = 200, want not-ready")
	}
}

func newTestWebhookServer(t *testing.T) *WebhookServer {
	t.Helper()

	server, err := NewWebhookServer(WebhookServerOptions{}, testInjector{})
	if err != nil {
		t.Fatalf("NewWebhookServer() error = %v", err)
	}
	return server
}

type testInjector struct{}

func (testInjector) Patch(pod *corev1.Pod) (*corev1.Pod, error) {
	return pod, nil
}

func (testInjector) Validate(*corev1.Pod) error {
	return nil
}

func mutateReview(uid types.UID, kind metav1.GroupVersionKind, operation admissionv1.Operation) admissionv1.AdmissionReview {
	pod, err := json.Marshal(&corev1.Pod{})
	if err != nil {
		panic(err)
	}
	return admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       uid,
			Kind:      kind,
			Operation: operation,
			Object:    runtime.RawExtension{Raw: pod},
		},
	}
}

func postAdmissionReview(t *testing.T, server *WebhookServer, review admissionv1.AdmissionReview) admissionv1.AdmissionReview {
	t.Helper()
	body, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	recorder := httptest.NewRecorder()
	server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response admissionv1.AdmissionReview
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return response
}
