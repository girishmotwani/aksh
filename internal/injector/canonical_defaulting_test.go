package injector

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

// applyAPIServerVolumeDefaults mimics the cosmetic defaulting the Kubernetes API
// server applies to volume sources AFTER a mutating webhook returns its patch:
// hostPath.type nil -> "" and configMap/projected/emptyDir defaultMode -> 0644.
// This is exactly what breaks a naive reflect.DeepEqual comparison between the
// mutating webhook's output and the object the validating webhook then sees.
func applyAPIServerVolumeDefaults(pod *corev1.Pod) {
	mode := ptr.To[int32](0644)
	for i := range pod.Spec.Volumes {
		v := &pod.Spec.Volumes[i]
		switch {
		case v.HostPath != nil:
			if v.HostPath.Type == nil {
				v.HostPath.Type = ptr.To(corev1.HostPathType(""))
			}
		case v.ConfigMap != nil:
			if v.ConfigMap.DefaultMode == nil {
				v.ConfigMap.DefaultMode = mode
			}
		case v.Projected != nil:
			if v.Projected.DefaultMode == nil {
				v.Projected.DefaultMode = mode
			}
		case v.EmptyDir != nil:
			// emptyDir has no defaulted fields that affect equality.
		}
	}
}

// TestValidate_APIServerDefaultedVolumes_Allowed proves the validating webhook
// accepts a pod the mutating webhook produced once the API server has defaulted
// its volume sources (hostPath.type "", configMap/projected defaultMode 0644).
// Regression: on a real cluster this defaulting made validate.pods.aksh.dev
// reject every injected pod ("spec.volumes[name=hostcgroup]: source drift").
func TestValidate_APIServerDefaultedVolumes_Allowed(t *testing.T) {
	inj := testInjectorForPatch(t)
	pod := goldenPod(t)
	applyAPIServerVolumeDefaults(pod)

	if err := inj.Validate(pod); err != nil {
		t.Fatalf("Validate rejected an API-defaulted injected pod: %v", err)
	}
	if !isCanonicalAkshPod(pod, testOptions()) {
		t.Fatal("isCanonicalAkshPod = false for an API-defaulted injected pod; Patch would not be idempotent")
	}
}

// TestValidate_DriftedVolumeSource_StillDenied proves the defaulting tolerance
// does not weaken INV-10: a security-relevant change to an aksh volume source
// (swapping the upstream-ca configMap for a different name) is still denied.
func TestValidate_DriftedVolumeSource_StillDenied(t *testing.T) {
	inj := testInjectorForPatch(t)
	pod := goldenPod(t)
	applyAPIServerVolumeDefaults(pod)
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].ConfigMap != nil && pod.Spec.Volumes[i].Name == "upstream-ca" {
			pod.Spec.Volumes[i].ConfigMap.Name = "attacker-ca"
		}
	}

	if err := inj.Validate(pod); err == nil {
		t.Fatal("Validate allowed a pod whose upstream-ca configMap source was swapped")
	}
}
