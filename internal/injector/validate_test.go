package injector

import (
	"reflect"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

// e2eInjector configures a SidecarInjector aligned to the shipped e2e golden
// manifest proxy image so Validate accepts test/e2e/manifests/50-aksh-pod.yaml.
func e2eInjector(t *testing.T) *SidecarInjector {
	t.Helper()
	opts := testOptions()
	opts.ProxyImage = "aksh-proxy:e2e"
	inj, err := NewSidecarInjector(opts)
	if err != nil {
		t.Fatalf("NewSidecarInjector: %v", err)
	}
	return inj
}

// validateGolden validates a canonical golden pod after an optional mutation.
func validateGolden(t *testing.T, mutate func(*corev1.Pod)) error {
	t.Helper()
	pod := goldenPod(t)
	if mutate != nil {
		mutate(pod)
	}
	return testInjectorForPatch(t).Validate(pod)
}

func nonAkshContainer(t *testing.T, pod *corev1.Pod) *corev1.Container {
	t.Helper()
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name != "aksh" {
			return &pod.Spec.Containers[i]
		}
	}
	t.Fatal("non-aksh container not found")
	return nil
}

func TestValidate_PodZeroValue_ReturnsPodRequiredError(t *testing.T) {
	err := testInjectorForPatch(t).Validate(nil)
	assertAdmissionError(t, err, "pod", "required")
}

func TestValidate_ContainersZeroValue_ReturnsSpecContainersRequiredError(t *testing.T) {
	err := testInjectorForPatch(t).Validate(&corev1.Pod{})
	assertAdmissionError(t, err, "spec.containers", "required")
}

func TestValidate_PostWrapperGoldenPod_ReturnsNil(t *testing.T) {
	if err := e2eInjector(t).Validate(goldenManifestPod(t)); err != nil {
		t.Fatalf("Validate golden manifest = %v, want nil", err)
	}
}

func TestValidate_PatchedCanonicalPod_ReturnsNil(t *testing.T) {
	if err := validateGolden(t, nil); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
}

func TestValidate_PodWithoutOptInLabelButCanonicalShape_ReturnsNil(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		delete(pod.Labels, "aksh.dev/inject")
	})
	if err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
}

func TestValidate_HostPIDTrueWithCanonicalAkshShape_ReturnsNil(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) { pod.Spec.HostPID = true })
	if err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
}

func TestValidate_NonCanonicalAkshShape_ReturnsAkshContainerDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) { akshContainer(t, pod).Image = "other" })
	assertAdmissionError(t, err, "spec.containers[name=aksh]", reasonAkshShape)
}

func TestValidate_HostPIDTrueWithNonCanonicalShape_ReturnsAkshContainerDenied(t *testing.T) {
	pod := workloadPod()
	pod.Spec.HostPID = true
	err := testInjectorForPatch(t).Validate(pod)
	assertAdmissionError(t, err, "spec.containers[name=aksh]", reasonAkshShape)
}

func TestValidate_HostNetworkTrue_ReturnsHostNetworkDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) { pod.Spec.HostNetwork = true })
	assertAdmissionError(t, err, "spec.hostNetwork", reasonHostNetwork)
}

func TestValidate_ShareProcessNamespaceTrue_ReturnsShareProcessNamespaceDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) { pod.Spec.ShareProcessNamespace = ptr.To(true) })
	assertAdmissionError(t, err, "spec.shareProcessNamespace", reasonShareProcessNS)
}

func TestValidate_AppContainerReservedUID1774_ReturnsRunAsUserDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		nonAkshContainer(t, pod).SecurityContext = &corev1.SecurityContext{RunAsUser: ptr.To[int64](1774)}
	})
	assertAdmissionError(t, err, "spec.containers[name=workload].securityContext.runAsUser", reasonReservedUID)
}

func TestValidate_InitContainerReservedUID1774_ReturnsRunAsUserDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		pod.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: "busybox", SecurityContext: &corev1.SecurityContext{RunAsUser: ptr.To[int64](1774)}}}
	})
	assertAdmissionError(t, err, "spec.initContainers[name=setup].securityContext.runAsUser", reasonReservedUID)
}

func TestValidate_EphemeralContainerReservedUID1774_ReturnsRunAsUserDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "busybox", SecurityContext: &corev1.SecurityContext{RunAsUser: ptr.To[int64](1774)}}}}
	})
	assertAdmissionError(t, err, "spec.ephemeralContainers[name=debug].securityContext.runAsUser", reasonReservedUID)
}

func assertAppCapabilityDenied(t *testing.T, cap corev1.Capability) {
	t.Helper()
	err := validateGolden(t, func(pod *corev1.Pod) {
		nonAkshContainer(t, pod).SecurityContext = &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{cap}}}
	})
	assertAdmissionError(t, err, "spec.containers[name=workload].securityContext.capabilities.add", reasonCapabilities)
}

func TestValidate_AppContainerAddsBPF_ReturnsCapabilitiesDenied(t *testing.T) {
	assertAppCapabilityDenied(t, "BPF")
}
func TestValidate_AppContainerAddsNETADMIN_ReturnsCapabilitiesDenied(t *testing.T) {
	assertAppCapabilityDenied(t, "NET_ADMIN")
}
func TestValidate_AppContainerAddsNETRAW_ReturnsCapabilitiesDenied(t *testing.T) {
	assertAppCapabilityDenied(t, "NET_RAW")
}
func TestValidate_AppContainerAddsSYSADMIN_ReturnsCapabilitiesDenied(t *testing.T) {
	assertAppCapabilityDenied(t, "SYS_ADMIN")
}
func TestValidate_AppContainerAddsSYSRESOURCE_ReturnsCapabilitiesDenied(t *testing.T) {
	assertAppCapabilityDenied(t, "SYS_RESOURCE")
}
func TestValidate_AppContainerAddsPERFMON_ReturnsCapabilitiesDenied(t *testing.T) {
	assertAppCapabilityDenied(t, "PERFMON")
}
func TestValidate_AppContainerAddsSETUID_ReturnsCapabilitiesDenied(t *testing.T) {
	assertAppCapabilityDenied(t, "SETUID")
}
func TestValidate_AppContainerAddsSETGID_ReturnsCapabilitiesDenied(t *testing.T) {
	assertAppCapabilityDenied(t, "SETGID")
}
func TestValidate_AppContainerAddsSETPCAP_ReturnsCapabilitiesDenied(t *testing.T) {
	assertAppCapabilityDenied(t, "SETPCAP")
}
func TestValidate_AppContainerAddsSYSPTRACE_ReturnsCapabilitiesDenied(t *testing.T) {
	assertAppCapabilityDenied(t, "SYS_PTRACE")
}

func TestValidate_AppContainerAllowPrivilegeEscalationTrue_ReturnsPrivilegeEscalationDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		nonAkshContainer(t, pod).SecurityContext = &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(true)}
	})
	assertAdmissionError(t, err, "spec.containers[name=workload].securityContext.allowPrivilegeEscalation", reasonPrivEscalation)
}

func TestValidate_AppContainerPrivilegedTrue_ReturnsPrivilegedDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		nonAkshContainer(t, pod).SecurityContext = &corev1.SecurityContext{Privileged: ptr.To(true)}
	})
	assertAdmissionError(t, err, "spec.containers[name=workload].securityContext.privileged", reasonPrivileged)
}

func TestValidate_AppContainerRunAsNonRootFalse_ReturnsRunAsNonRootDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		nonAkshContainer(t, pod).SecurityContext = &corev1.SecurityContext{RunAsNonRoot: ptr.To(false)}
	})
	assertAdmissionError(t, err, "spec.containers[name=workload].securityContext.runAsNonRoot", reasonRunAsNonRoot)
}

func TestValidate_AppContainerMountsEntraToken_ReturnsTokenLeakageDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		c := nonAkshContainer(t, pod)
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "entra-token", MountPath: "/leak"})
	})
	assertAdmissionError(t, err, "spec.containers[name=workload].volumeMounts", reasonTokenLeakage)
}

func TestValidate_AppContainerMountsAkshProjectedServiceAccountToken_ReturnsTokenLeakageDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: "sneaky-token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", Audience: "api://AzureADTokenExchange", ExpirationSeconds: ptr.To[int64](3600)}}}}}})
		c := nonAkshContainer(t, pod)
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "sneaky-token", MountPath: "/leak"})
	})
	assertAdmissionError(t, err, "spec.containers[name=workload].volumeMounts", reasonTokenLeakage)
}

func TestValidate_AppContainerMountsCaPriv_ReturnsCAPrivateLeakageDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		c := nonAkshContainer(t, pod)
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "ca-priv", MountPath: "/leak"})
	})
	assertAdmissionError(t, err, "spec.containers[name=workload].volumeMounts", reasonCAPrivLeakage)
}

// Regression (Slice-3 review, High): init and ephemeral containers can also mount
// volumes and must not be an exfiltration path for aksh credentials/host volumes.
func TestValidate_InitContainerMountsCaPriv_ReturnsCAPrivateLeakageDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		pod.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: "busybox", VolumeMounts: []corev1.VolumeMount{{Name: "ca-priv", MountPath: "/leak"}}}}
	})
	assertAdmissionError(t, err, "spec.initContainers[name=setup].volumeMounts", reasonCAPrivLeakage)
}

func TestValidate_EphemeralContainerMountsEntraToken_ReturnsTokenLeakageDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "busybox", VolumeMounts: []corev1.VolumeMount{{Name: "entra-token", MountPath: "/leak"}}}}}
	})
	assertAdmissionError(t, err, "spec.ephemeralContainers[name=debug].volumeMounts", reasonTokenLeakage)
}

func TestValidate_AppContainerMountsCaPubReadWrite_ReturnsCAPublicMutabilityDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		c := nonAkshContainer(t, pod)
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "ca-pub", MountPath: "/leak", ReadOnly: false})
	})
	assertAdmissionError(t, err, "spec.containers[name=workload].volumeMounts[name=ca-pub].readOnly", reasonCAPubMutability)
}

func TestValidate_AppContainerMountsHostCgroup_ReturnsHostCgroupLeakageDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		c := nonAkshContainer(t, pod)
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "hostcgroup", MountPath: "/leak"})
	})
	assertAdmissionError(t, err, "spec.containers[name=workload].volumeMounts", reasonHostCgroupLeakage)
}

func TestValidate_AppContainerMountsUpstreamCA_ReturnsAkshCredentialVolumeDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		c := nonAkshContainer(t, pod)
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "upstream-ca", MountPath: "/leak"})
	})
	assertAdmissionError(t, err, "spec.containers[name=workload].volumeMounts", reasonAkshCredVolume)
}

func assertVolumeSourceDrift(t *testing.T, name string, drift corev1.VolumeSource) {
	t.Helper()
	err := validateGolden(t, func(pod *corev1.Pod) {
		for i := range pod.Spec.Volumes {
			if pod.Spec.Volumes[i].Name == name {
				pod.Spec.Volumes[i].VolumeSource = drift
			}
		}
	})
	assertAdmissionError(t, err, "spec.volumes[name="+name+"]", reasonVolumeSource)
}

func TestValidate_HostCgroupVolumeSourceDrift_ReturnsVolumeSourceDenied(t *testing.T) {
	assertVolumeSourceDrift(t, "hostcgroup", corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/other"}})
}
func TestValidate_CaPrivVolumeSourceDrift_ReturnsVolumeSourceDenied(t *testing.T) {
	assertVolumeSourceDrift(t, "ca-priv", corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/other"}})
}
func TestValidate_CaPubVolumeSourceDrift_ReturnsVolumeSourceDenied(t *testing.T) {
	assertVolumeSourceDrift(t, "ca-pub", corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/other"}})
}
func TestValidate_EntraTokenVolumeSourceDrift_ReturnsVolumeSourceDenied(t *testing.T) {
	assertVolumeSourceDrift(t, "entra-token", corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}})
}
func TestValidate_UpstreamCAVolumeSourceDrift_ReturnsVolumeSourceDenied(t *testing.T) {
	assertVolumeSourceDrift(t, "upstream-ca", corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "other"}}})
}

// Regression (Slice-3 review): a protected pod missing an aksh-owned volume is
// denied (canonical shape requires all five volumes present with golden sources).
func TestValidate_MissingCanonicalVolume_ReturnsVolumeMissingDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		kept := pod.Spec.Volumes[:0]
		for _, v := range pod.Spec.Volumes {
			if v.Name != "ca-pub" {
				kept = append(kept, v)
			}
		}
		pod.Spec.Volumes = kept
	})
	assertAdmissionError(t, err, "spec.volumes[name=ca-pub]", reasonVolumeMissing)
}

// Regression (Slice-3 review, High): init and ephemeral containers must be denied
// prohibited capabilities, not only reserved UID (design Limitations #4).
func TestValidate_InitContainerAddsNETADMIN_ReturnsCapabilitiesDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		pod.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: "busybox", SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}}}}}
	})
	assertAdmissionError(t, err, "spec.initContainers[name=setup].securityContext.capabilities.add", reasonCapabilities)
}

func TestValidate_EphemeralContainerAddsBPF_ReturnsCapabilitiesDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "busybox", SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"BPF"}}}}}}
	})
	assertAdmissionError(t, err, "spec.ephemeralContainers[name=debug].securityContext.capabilities.add", reasonCapabilities)
}

func TestValidate_IstioStatusAnnotationPresent_ReturnsIstioCoexistenceDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		pod.Annotations["sidecar.istio.io/status"] = "{}"
	})
	assertAdmissionError(t, err, "metadata.annotations[sidecar.istio.io/status]", reasonIstio)
}

func TestValidate_IstioProxyContainerPresent_ReturnsIstioCoexistenceDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "istio-proxy", Image: "istio"})
	})
	assertAdmissionError(t, err, "spec.containers[name=istio-proxy]", reasonIstio)
}

func TestValidate_AutomountServiceAccountTokenTrue_ReturnsAutomountDenied(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) { pod.Spec.AutomountServiceAccountToken = ptr.To(true) })
	assertAdmissionError(t, err, "spec.automountServiceAccountToken", reasonAutomount)
}

func TestValidate_GoldenWorkloadOmittedDropAllAndRunAsUser_ReturnsNil(t *testing.T) {
	// The golden workload container runs as image default/root with no
	// securityContext (no drop:[ALL], no runAsUser); omitted fields are allowed.
	if err := validateGolden(t, nil); err != nil {
		t.Fatalf("Validate golden workload = %v, want nil", err)
	}
	if nonAkshContainer(t, goldenPod(t)).SecurityContext != nil {
		t.Fatal("golden workload unexpectedly has a securityContext")
	}
}

func TestValidate_MultipleViolations_ReturnsFirstDeterministicAdmissionError(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		pod.Spec.HostNetwork = true
		c := nonAkshContainer(t, pod)
		c.SecurityContext = &corev1.SecurityContext{RunAsUser: ptr.To[int64](1774), Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"BPF"}}}
	})
	assertAdmissionError(t, err, "spec.hostNetwork", reasonHostNetwork)
}

func TestValidate_NonAkshContainerReservedGID1774_ReturnsNil(t *testing.T) {
	err := validateGolden(t, func(pod *corev1.Pod) {
		nonAkshContainer(t, pod).SecurityContext = &corev1.SecurityContext{RunAsGroup: ptr.To[int64](1774)}
	})
	if err != nil {
		t.Fatalf("Validate = %v, want nil (reserved GID is allowed on non-aksh containers)", err)
	}
}

func TestValidate_ConcurrentRequests_DoesNotMutateSharedInjectorOptionsOrPods(t *testing.T) {
	inj := testInjectorForPatch(t)
	snapshot := *inj
	const n = 60
	pods := make([]*corev1.Pod, n)
	befores := make([]*corev1.Pod, n)
	wantErr := make([]bool, n)
	for i := range pods {
		pod := goldenPod(t)
		pod.Name = "app" + string(rune('a'+i%26))
		if i%2 == 0 {
			pod.Spec.HostNetwork = true
			wantErr[i] = true
		}
		pods[i] = pod
		befores[i] = pod.DeepCopy()
	}
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range pods {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := inj.Validate(pods[i])
			if (err != nil) != wantErr[i] {
				errs <- AdmissionError{Field: "result", Reason: "nondeterministic"}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if *inj != snapshot {
		t.Fatal("injector mutated")
	}
	for i := range pods {
		if !reflect.DeepEqual(pods[i], befores[i]) {
			t.Fatalf("pod %d mutated by Validate", i)
		}
	}
}
