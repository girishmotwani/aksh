package injector

import (
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/yaml"
)

// goldenManifestPod loads the e2e golden oracle (test/e2e/manifests/50-aksh-pod.yaml)
// as the canonical post-wrapper shape. Anchoring test 43 to this external manifest
// (rather than to Patch output) makes it a true drift detector between canonical.go,
// sidecar_injector.go, and the shipped golden pod.
func goldenManifestPod(t *testing.T) *corev1.Pod {
	t.Helper()
	path := filepath.Join("..", "..", "test", "e2e", "manifests", "50-aksh-pod.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden manifest: %v", err)
	}
	var pod corev1.Pod
	if err := yaml.Unmarshal(raw, &pod); err != nil {
		t.Fatalf("unmarshal golden manifest: %v", err)
	}
	return &pod
}

func TestIsCanonicalAkshPod_PostWrapperGoldenShape_ReturnsTrue(t *testing.T) {
	pod := goldenManifestPod(t)
	opts := testOptions()
	// The e2e golden overlay uses a side-loaded image tag (design §environment
	// overlay note); align the expected proxy image with the shipped manifest.
	opts.ProxyImage = "aksh-proxy:e2e"
	if !isCanonicalAkshPod(pod, opts) {
		t.Fatal("golden manifest pod not canonical")
	}
}
func TestIsCanonicalAkshPod_PodZeroValue_ReturnsFalse(t *testing.T) {
	if isCanonicalAkshPod(nil, testOptions()) {
		t.Fatal("nil pod canonical")
	}
}
func TestIsCanonicalAkshPod_MissingInjectionAnnotation_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	delete(pod.Annotations, "aksh.dev/injected")
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_InjectionAnnotationZeroValue_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	pod.Annotations["aksh.dev/injected"] = ""
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_InjectionVersionInvalidValue_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	pod.Annotations["aksh.dev/injected"] = "v2"
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_MissingFsGroup_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	pod.Spec.SecurityContext.FSGroup = nil
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_FsGroupInvalidValue_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	pod.Spec.SecurityContext.FSGroup = ptr.To[int64](1337)
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_MissingAkshContainer_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	pod.Spec.Containers = pod.Spec.Containers[1:]
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_DuplicateAkshContainers_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	pod.Spec.Containers = append(pod.Spec.Containers, pod.Spec.Containers[0])
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_ProxyImageInvalidValue_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	akshContainer(t, pod).Image = "other"
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_ShellWrapperCommand_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	akshContainer(t, pod).Command = []string{"/bin/sh", "-c", "exec /usr/local/bin/aksh-proxy"}
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_ArgsInvalidValue_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	akshContainer(t, pod).Args = []string{"x"}
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_AkshRunAsUserInvalidValue_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	akshContainer(t, pod).SecurityContext.RunAsUser = ptr.To[int64](1)
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_AkshRunAsGroupInvalidValue_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	akshContainer(t, pod).SecurityContext.RunAsGroup = ptr.To[int64](1)
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_MissingCanonicalCapability_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	c := akshContainer(t, pod)
	c.SecurityContext.Capabilities.Add = c.SecurityContext.Capabilities.Add[1:]
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_ExtraCapability_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	c := akshContainer(t, pod)
	c.SecurityContext.Capabilities.Add = append(c.SecurityContext.Capabilities.Add, corev1.Capability("SYS_PTRACE"))
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_MissingRequiredEnvironment_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	c := akshContainer(t, pod)
	c.Env = c.Env[1:]
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_ForbiddenCapturePodPathOrSSLCertFileEnvironment_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	c := akshContainer(t, pod)
	c.Env = append(c.Env, corev1.EnvVar{Name: "AKSH_CAPTURE_POD_PATH", Value: "/x"})
	assertNotCanonical(t, pod)
	pod = goldenPod(t)
	c = akshContainer(t, pod)
	c.Env = append(c.Env, corev1.EnvVar{Name: "SSL_CERT_FILE", Value: "/x"})
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_MissingOrDriftedCanonicalVolume_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	pod.Spec.Volumes = pod.Spec.Volumes[1:]
	assertNotCanonical(t, pod)
	pod = goldenPod(t)
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == "hostcgroup" {
			pod.Spec.Volumes[i].HostPath = &corev1.HostPathVolumeSource{Path: "/other"}
		}
	}
	assertNotCanonical(t, pod)
}
func TestIsCanonicalAkshPod_MissingOrDriftedCanonicalMount_ReturnsFalse(t *testing.T) {
	pod := goldenPod(t)
	c := akshContainer(t, pod)
	c.VolumeMounts = c.VolumeMounts[1:]
	assertNotCanonical(t, pod)
	pod = goldenPod(t)
	c = akshContainer(t, pod)
	c.VolumeMounts[0].MountPath = "/other"
	assertNotCanonical(t, pod)
}

func assertNotCanonical(t *testing.T, pod *corev1.Pod) {
	t.Helper()
	if isCanonicalAkshPod(pod, testOptions()) {
		t.Fatalf("pod unexpectedly canonical: %#v", pod)
	}
}
