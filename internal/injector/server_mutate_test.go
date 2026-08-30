package injector

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	jsonpatch "gomodules.xyz/jsonpatch/v2"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func TestMutateAdmission_ValidPod_ReturnsJSONPatchPatchType(t *testing.T) {
	response := postMutateToRealInjector(t, workloadPod())
	if response.Response.PatchType == nil || *response.Response.PatchType != admissionv1.PatchTypeJSONPatch {
		t.Fatalf("PatchType=%v", response.Response.PatchType)
	}
}

func TestMutateAdmission_ValidPod_UsesMarshalAndCreatePatchCompatiblePatch(t *testing.T) {
	original := workloadPod()
	response := postMutateToRealInjector(t, original)
	if !response.Response.Allowed {
		t.Fatalf("denied: %#v", response.Response.Result)
	}
	var ops []jsonpatch.Operation
	if err := json.Unmarshal(response.Response.Patch, &ops); err != nil {
		t.Fatalf("patch is not RFC6902 JSON: %v; %s", err, string(response.Response.Patch))
	}
	patched := original.DeepCopy()
	if len(ops) == 0 {
		t.Fatal("patch empty for non-canonical pod")
	}
	if !bytes.Contains(response.Response.Patch, []byte("/spec/containers")) {
		t.Fatalf("patch did not target containers: %s", string(response.Response.Patch))
	}
	if patched == nil {
		t.Fatal("unreachable")
	}
}

func TestMutateAdmission_NoOpPatch_ReturnsEmptyJSONPatchArray(t *testing.T) {
	response := postMutateToRealInjector(t, goldenPod(t))
	if !response.Response.Allowed {
		t.Fatalf("denied: %#v", response.Response.Result)
	}
	if string(response.Response.Patch) != "[]" {
		t.Fatalf("patch=%s want []", string(response.Response.Patch))
	}
}

func TestMutateAdmission_InjectorPatchError_ReturnsAdmissionDenied(t *testing.T) {
	server, err := NewWebhookServer(WebhookServerOptions{}, patchErrorInjector{err: AdmissionError{Field: "spec.containers[name=aksh]", Reason: "conflict"}})
	if err != nil {
		t.Fatal(err)
	}
	response := postAdmissionReview(t, server, mutateReviewForPod(t, workloadPod()))
	if response.Response.Allowed || response.Response.Result == nil || response.Response.Result.Message != "spec.containers[name=aksh]: conflict" {
		t.Fatalf("response=%#v", response.Response)
	}
}

func TestMutateAdmission_OriginalMarshalError_ReturnsAdmissionDeniedFailClosed(t *testing.T) {
	withMarshalFailure(t, 1, func() {
		response := postMutateToRealInjector(t, workloadPod())
		assertDeniedFailClosed(t, response)
	})
}

func TestMutateAdmission_PatchedMarshalError_ReturnsAdmissionDeniedFailClosed(t *testing.T) {
	withMarshalFailure(t, 2, func() {
		response := postMutateToRealInjector(t, workloadPod())
		assertDeniedFailClosed(t, response)
	})
}

func TestMutateAdmission_CreatePatchError_ReturnsAdmissionDeniedFailClosed(t *testing.T) {
	old := createPatch
	createPatch = func(_, _ []byte) ([]jsonpatch.Operation, error) { return nil, errors.New("boom") }
	t.Cleanup(func() { createPatch = old })
	response := postMutateToRealInjector(t, workloadPod())
	assertDeniedFailClosed(t, response)
}

func postMutateToRealInjector(t *testing.T, pod *corev1.Pod) admissionv1.AdmissionReview {
	t.Helper()
	inj := testInjectorForPatch(t)
	server, err := NewWebhookServer(WebhookServerOptions{}, inj)
	if err != nil {
		t.Fatal(err)
	}
	return postAdmissionReview(t, server, mutateReviewForPod(t, pod))
}

func mutateReviewForPod(t *testing.T, pod *corev1.Pod) admissionv1.AdmissionReview {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return admissionv1.AdmissionReview{Request: &admissionv1.AdmissionRequest{UID: types.UID("request-uid"), Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Pod"}, Operation: admissionv1.Create, Object: runtime.RawExtension{Raw: raw}}}
}

type patchErrorInjector struct{ err error }

func (p patchErrorInjector) Patch(*corev1.Pod) (*corev1.Pod, error) { return nil, p.err }
func (p patchErrorInjector) Validate(*corev1.Pod) error             { return nil }

func withMarshalFailure(t *testing.T, failAt int, fn func()) {
	t.Helper()
	old := marshalJSON
	calls := 0
	marshalJSON = func(v any) ([]byte, error) {
		calls++
		if calls == failAt {
			return nil, errors.New("marshal boom")
		}
		return json.Marshal(v)
	}
	t.Cleanup(func() { marshalJSON = old })
	fn()
}

func assertDeniedFailClosed(t *testing.T, response admissionv1.AdmissionReview) {
	t.Helper()
	if response.Response == nil || response.Response.Allowed {
		t.Fatalf("response=%#v, want denied", response.Response)
	}
	if response.Response.Result == nil || response.Response.Result.Message == "" {
		t.Fatalf("missing denial message: %#v", response.Response)
	}
}

var _ = http.MethodPost
var _ = httptest.NewRecorder
