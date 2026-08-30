package injector

import (
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testOptions() InjectorOptions {
	return InjectorOptions{ProxyImage: "aksh-proxy:test", ReservedUID: 1774, ReservedGID: 1774, OptInLabelKey: "aksh.dev/inject", OptInLabelValue: "enabled", InjectionVersion: "v1"}
}

func testInjectorForPatch(t *testing.T) *SidecarInjector {
	t.Helper()
	inj, err := NewSidecarInjector(testOptions())
	if err != nil {
		t.Fatalf("NewSidecarInjector: %v", err)
	}
	return inj
}

func workloadPod() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "app-ns", Labels: map[string]string{"app": "demo"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "workload", Image: "busybox"}}}}
}

func goldenPod(t *testing.T) *corev1.Pod {
	t.Helper()
	pod, err := testInjectorForPatch(t).Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch golden: %v", err)
	}
	return pod
}

func akshContainer(t *testing.T, pod *corev1.Pod) *corev1.Container {
	t.Helper()
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == "aksh" {
			return &pod.Spec.Containers[i]
		}
	}
	t.Fatal("aksh container not found")
	return nil
}

func volumeNamed(t *testing.T, pod *corev1.Pod, name string) corev1.Volume {
	t.Helper()
	for _, v := range pod.Spec.Volumes {
		if v.Name == name {
			return v
		}
	}
	t.Fatalf("volume %s not found", name)
	return corev1.Volume{}
}

func envMap(c *corev1.Container) map[string]corev1.EnvVar {
	out := map[string]corev1.EnvVar{}
	for _, e := range c.Env {
		out[e.Name] = e
	}
	return out
}

func countNamedContainers(pod *corev1.Pod, name string) int {
	n := 0
	for _, c := range pod.Spec.Containers {
		if c.Name == name {
			n++
		}
	}
	return n
}
func countNamedVolumes(pod *corev1.Pod, name string) int {
	n := 0
	for _, v := range pod.Spec.Volumes {
		if v.Name == name {
			n++
		}
	}
	return n
}
func countNamedMounts(c *corev1.Container, name string) int {
	n := 0
	for _, m := range c.VolumeMounts {
		if m.Name == name {
			n++
		}
	}
	return n
}

func assertAdmissionError(t *testing.T, err error, field, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error nil, want %s: %s", field, reason)
	}
	ae, ok := err.(AdmissionError)
	if !ok {
		t.Fatalf("error type %T, want AdmissionError", err)
	}
	if ae.Field != field || ae.Reason != reason {
		t.Fatalf("AdmissionError = %#v, want field=%q reason=%q", ae, field, reason)
	}
}

func mustJSON[T any](t *testing.T, v T) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestNewSidecarInjector_ValidOptions_ReturnsConfiguredInjector(t *testing.T) {
	opts := testOptions()
	inj, err := NewSidecarInjector(opts)
	if err != nil {
		t.Fatalf("NewSidecarInjector error = %v", err)
	}
	if inj.proxyImage != opts.ProxyImage || inj.reservedUID != opts.ReservedUID || inj.reservedGID != opts.ReservedGID || inj.optInLabelKey != opts.OptInLabelKey || inj.optInLabelValue != opts.OptInLabelValue || inj.injectionVersion != opts.InjectionVersion {
		t.Fatalf("injector not configured from options: %#v", inj)
	}
}

func TestNewSidecarInjector_ProxyImageZeroValue_ReturnsProxyImageRequiredError(t *testing.T) {
	opts := testOptions()
	opts.ProxyImage = ""
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "proxyImage", "required")
}
func TestNewSidecarInjector_ProxyImageInvalidValue_ReturnsProxyImageRequiredError(t *testing.T) {
	opts := testOptions()
	opts.ProxyImage = "   "
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "proxyImage", "required")
}
func TestNewSidecarInjector_OptInLabelKeyZeroValue_ReturnsOptInLabelRequiredError(t *testing.T) {
	opts := testOptions()
	opts.OptInLabelKey = ""
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "optInLabel", "required")
}
func TestNewSidecarInjector_OptInLabelKeyInvalidValue_ReturnsOptInLabelRequiredError(t *testing.T) {
	opts := testOptions()
	opts.OptInLabelKey = " \t"
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "optInLabel", "required")
}
func TestNewSidecarInjector_OptInLabelValueZeroValue_ReturnsOptInLabelRequiredError(t *testing.T) {
	opts := testOptions()
	opts.OptInLabelValue = ""
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "optInLabel", "required")
}
func TestNewSidecarInjector_OptInLabelValueInvalidValue_ReturnsOptInLabelRequiredError(t *testing.T) {
	opts := testOptions()
	opts.OptInLabelValue = "  "
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "optInLabel", "required")
}
func TestNewSidecarInjector_InjectionVersionZeroValue_ReturnsInjectionVersionRequiredError(t *testing.T) {
	opts := testOptions()
	opts.InjectionVersion = ""
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "injectionVersion", "required")
}
func TestNewSidecarInjector_InjectionVersionInvalidValue_ReturnsInjectionVersionRequiredError(t *testing.T) {
	opts := testOptions()
	opts.InjectionVersion = "  "
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "injectionVersion", "required")
}
func TestNewSidecarInjector_ReservedUIDZeroValue_ReturnsReservedUIDMustBe1774Error(t *testing.T) {
	opts := testOptions()
	opts.ReservedUID = 0
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "reservedUID", "must be 1774")
}
func TestNewSidecarInjector_ReservedUIDInvalidValue_ReturnsReservedUIDMustBe1774Error(t *testing.T) {
	opts := testOptions()
	opts.ReservedUID = 1337
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "reservedUID", "must be 1774")
}
func TestNewSidecarInjector_ReservedGIDZeroValue_ReturnsReservedGIDMustBe1774Error(t *testing.T) {
	opts := testOptions()
	opts.ReservedGID = 0
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "reservedGID", "must be 1774")
}
func TestNewSidecarInjector_ReservedGIDInvalidValue_ReturnsReservedGIDMustBe1774Error(t *testing.T) {
	opts := testOptions()
	opts.ReservedGID = 1337
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "reservedGID", "must be 1774")
}
func TestNewSidecarInjector_MultipleInvalidFields_ReturnsDeterministicFirstError(t *testing.T) {
	opts := testOptions()
	opts.ProxyImage = ""
	opts.OptInLabelKey = ""
	opts.ReservedUID = 0
	_, err := NewSidecarInjector(opts)
	assertAdmissionError(t, err, "proxyImage", "required")
}

func TestPatch_PodZeroValue_ReturnsPodRequiredError(t *testing.T) {
	_, err := testInjectorForPatch(t).Patch(nil)
	assertAdmissionError(t, err, "pod", "required")
}
func TestPatch_ContainersZeroValue_ReturnsSpecContainersRequiredError(t *testing.T) {
	_, err := testInjectorForPatch(t).Patch(&corev1.Pod{})
	assertAdmissionError(t, err, "spec.containers", "required")
}
func TestPatch_DeliveredPod_InjectsAkshContainerFirst(t *testing.T) {
	pod, _ := testInjectorForPatch(t).Patch(workloadPod())
	if pod.Spec.Containers[0].Name != "aksh" || pod.Spec.Containers[1].Name != "workload" {
		t.Fatalf("containers = %#v", pod.Spec.Containers)
	}
}
func TestPatch_DeliveredPod_DoesNotMutateCallerOwnedPod(t *testing.T) {
	in := workloadPod()
	before := in.DeepCopy()
	_, err := testInjectorForPatch(t).Patch(in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, before) {
		t.Fatalf("caller pod mutated\nbefore=%s\nafter=%s", mustJSON(t, before), mustJSON(t, in))
	}
}
func TestPatch_DeliveredPod_SetsProxyImageAndIfNotPresentPullPolicy(t *testing.T) {
	pod := goldenPod(t)
	c := akshContainer(t, pod)
	if c.Image != testOptions().ProxyImage || c.ImagePullPolicy != corev1.PullIfNotPresent {
		t.Fatalf("image/policy=%q/%q", c.Image, c.ImagePullPolicy)
	}
}
func TestPatch_DeliveredPod_SetsAkshUIDGID1774AndCanonicalCapabilities(t *testing.T) {
	c := akshContainer(t, goldenPod(t))
	if c.SecurityContext == nil || *c.SecurityContext.RunAsUser != 1774 || *c.SecurityContext.RunAsGroup != 1774 {
		t.Fatalf("securityContext=%#v", c.SecurityContext)
	}
	want := []corev1.Capability{"BPF", "NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_RESOURCE", "PERFMON", "SETGID", "SETUID", "SETPCAP"}
	if !reflect.DeepEqual(c.SecurityContext.Capabilities.Add, want) {
		t.Fatalf("caps=%v", c.SecurityContext.Capabilities.Add)
	}
}
func TestPatch_DeliveredPod_SetsAppArmorUnconfinedForBpffsSelfMount(t *testing.T) {
	c := akshContainer(t, goldenPod(t))
	if c.SecurityContext == nil || c.SecurityContext.AppArmorProfile == nil ||
		c.SecurityContext.AppArmorProfile.Type != corev1.AppArmorProfileTypeUnconfined {
		t.Fatalf("appArmorProfile=%#v want Unconfined", c.SecurityContext.AppArmorProfile)
	}
}
func TestPatch_DeliveredPod_SetsCommandToAkshProxyAndOmitsShellArgs(t *testing.T) {
	c := akshContainer(t, goldenPod(t))
	if !reflect.DeepEqual(c.Command, []string{"/usr/local/bin/aksh-proxy"}) || len(c.Args) != 0 || strings.Contains(strings.Join(c.Command, " "), "/bin/sh") {
		t.Fatalf("command=%v args=%v", c.Command, c.Args)
	}
}
func TestPatch_DeliveredPod_SetsCanonicalAkshEnvironment(t *testing.T) {
	env := envMap(akshContainer(t, goldenPod(t)))
	want := map[string]string{"AKSH_POLICY_NAMESPACE": "app-ns", "AKSH_SA_TOKEN_PATH": "/var/run/secrets/aksh/token", "AKSH_ENTRA_TENANT_ID": "", "AKSH_ENTRA_CLIENT_ID": "", "AKSH_ENTRA_AUTHORITY": "", "AKSH_AUDIT_SINK": "stdout", "AKSH_CA_PRIV_DIR": "/var/lib/aksh/ca-priv", "AKSH_CA_PUB_DIR": "/var/lib/aksh/ca-pub", "AKSH_CAPTURE_HOST_CGROUP_MOUNT": "/host/sys/fs/cgroup", "AKSH_CAPTURE_MOUNT_BPFFS": "true", "AKSH_CAPTURE_PROXY_UID": "1774", "AKSH_CAPTURE_PROXY_GID": "1774", "AKSH_CAPTURE_BLOCK_NON_TCP": "true", "AKSH_CAPTURE_RUN_PROBE": "true", "AKSH_POLICY_FIRST_SNAPSHOT_TIMEOUT": "300s"}
	if env["POD_IP"].ValueFrom == nil || env["POD_IP"].ValueFrom.FieldRef.FieldPath != "status.podIP" {
		t.Fatalf("POD_IP=%#v", env["POD_IP"])
	}
	for k, v := range want {
		if env[k].Value != v {
			t.Fatalf("env %s=%q want %q", k, env[k].Value, v)
		}
	}
}
func TestPatch_DeliveredPod_OmitsCapturePodPathAndSSLCertFileEnvironment(t *testing.T) {
	env := envMap(akshContainer(t, goldenPod(t)))
	if _, ok := env["AKSH_CAPTURE_POD_PATH"]; ok {
		t.Fatal("AKSH_CAPTURE_POD_PATH present")
	}
	if _, ok := env["SSL_CERT_FILE"]; ok {
		t.Fatal("SSL_CERT_FILE present")
	}
}
func TestPatch_DeliveredPod_AddsHostCgroupVolumeWithCanonicalSource(t *testing.T) {
	v := volumeNamed(t, goldenPod(t), "hostcgroup")
	if v.HostPath == nil || v.HostPath.Path != "/sys/fs/cgroup" {
		t.Fatalf("hostcgroup=%#v", v)
	}
}
func TestPatch_DeliveredPod_AddsCaPrivCaPubEntraTokenAndUpstreamCAVolumes(t *testing.T) {
	pod := goldenPod(t)
	if volumeNamed(t, pod, "ca-priv").EmptyDir == nil || volumeNamed(t, pod, "ca-pub").EmptyDir == nil {
		t.Fatal("missing emptyDir ca volumes")
	}
	entra := volumeNamed(t, pod, "entra-token")
	if entra.Projected == nil || len(entra.Projected.Sources) != 1 || entra.Projected.Sources[0].ServiceAccountToken == nil || entra.Projected.Sources[0].ServiceAccountToken.Path != "token" || entra.Projected.Sources[0].ServiceAccountToken.Audience != "api://AzureADTokenExchange" || *entra.Projected.Sources[0].ServiceAccountToken.ExpirationSeconds != 3600 {
		t.Fatalf("entra-token=%#v", entra)
	}
	up := volumeNamed(t, pod, "upstream-ca")
	if up.ConfigMap == nil || up.ConfigMap.Name != "upstream-ca" {
		t.Fatalf("upstream-ca=%#v", up)
	}
}

// #35: the proxy needs the pod's whole label map to evaluate AkshPolicy
// selectors, and only a downwardAPI volume can supply it.
func TestPatch_DeliveredPod_AddsPodInfoDownwardAPILabelsVolume(t *testing.T) {
	pod := goldenPod(t)
	v, ok := findVolume(pod, "podinfo")
	if !ok {
		t.Fatal("podinfo volume missing")
	}
	if v.DownwardAPI == nil {
		t.Fatalf("podinfo=%#v, want a downwardAPI source", v.VolumeSource)
	}
	if len(v.DownwardAPI.Items) != 1 {
		t.Fatalf("podinfo items=%#v, want exactly one", v.DownwardAPI.Items)
	}
	item := v.DownwardAPI.Items[0]
	if item.Path != "labels" || item.FieldRef == nil || item.FieldRef.FieldPath != "metadata.labels" {
		t.Fatalf("podinfo item=%#v, want labels -> metadata.labels", item)
	}
}
func TestPatch_DeliveredPod_AddsCanonicalVolumeMountsAndReadOnlyFlags(t *testing.T) {
	c := akshContainer(t, goldenPod(t))
	want := map[string]struct {
		path string
		ro   bool
	}{"hostcgroup": {"/host/sys/fs/cgroup", false}, "ca-priv": {"/var/lib/aksh/ca-priv", false}, "ca-pub": {"/var/lib/aksh/ca-pub", false}, "entra-token": {"/var/run/secrets/aksh", true}, "upstream-ca": {"/etc/aksh/upstream-ca", true}, "podinfo": {"/etc/aksh/podinfo", true}}
	for _, m := range c.VolumeMounts {
		if w, ok := want[m.Name]; ok {
			if m.MountPath != w.path || m.ReadOnly != w.ro {
				t.Fatalf("mount %s=%#v want %#v", m.Name, m, w)
			}
			delete(want, m.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing mounts %v", want)
	}
}
func TestPatch_DeliveredPod_SetsFsGroupHostPIDAndInjectionVersionAnnotation(t *testing.T) {
	pod := goldenPod(t)
	if !pod.Spec.HostPID || pod.Spec.SecurityContext == nil || *pod.Spec.SecurityContext.FSGroup != 1774 || pod.Annotations["aksh.dev/injected"] != "v1" {
		t.Fatalf("pod fields=%s", mustJSON(t, pod))
	}
}
func TestPatch_DeliveredPod_DoesNotSetHostNetworkOrShareProcessNamespace(t *testing.T) {
	pod := goldenPod(t)
	if pod.Spec.HostNetwork || pod.Spec.ShareProcessNamespace != nil {
		t.Fatalf("hostNetwork=%v shareProcessNamespace=%v", pod.Spec.HostNetwork, pod.Spec.ShareProcessNamespace)
	}
}
func TestPatch_ExistingCanonicalPod_ReturnsEquivalentPodWithoutDuplicates(t *testing.T) {
	pod := goldenPod(t)
	out, err := testInjectorForPatch(t).Patch(pod)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, pod) {
		t.Fatalf("out != pod")
	}
	if countNamedContainers(out, "aksh") != 1 {
		t.Fatal("duplicate aksh")
	}
}
func TestPatch_RepeatedCalls_DoNotDuplicateContainersVolumesEnvOrMounts(t *testing.T) {
	inj := testInjectorForPatch(t)
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatal(err)
	}
	pod, err = inj.Patch(pod)
	if err != nil {
		t.Fatal(err)
	}
	c := akshContainer(t, pod)
	if countNamedContainers(pod, "aksh") != 1 || countNamedVolumes(pod, "hostcgroup") != 1 || countNamedMounts(c, "hostcgroup") != 1 || len(envMap(c)) != 16 {
		t.Fatalf("duplicates detected")
	}
}
func TestPatch_MarkerAnnotationOnlyWithMissingAkshShape_ReInjectsCanonicalContainer(t *testing.T) {
	pod := workloadPod()
	pod.Annotations = map[string]string{"aksh.dev/injected": "v1"}
	out, err := testInjectorForPatch(t).Patch(pod)
	if err != nil {
		t.Fatal(err)
	}
	if out.Spec.Containers[0].Name != "aksh" || !isCanonicalAkshPod(out, testOptions()) {
		t.Fatalf("not reinjected canonical")
	}
}
func TestPatch_ExistingNonCanonicalAkshContainer_ReturnsAkshContainerConflict(t *testing.T) {
	pod := workloadPod()
	pod.Spec.Containers = append([]corev1.Container{{Name: "aksh", Image: "busybox"}}, pod.Spec.Containers...)
	_, err := testInjectorForPatch(t).Patch(pod)
	assertAdmissionError(t, err, "spec.containers[name=aksh]", "conflicts with required aksh sidecar")
}
func TestPatch_ExistingAkshContainerWithDifferentImage_ReturnsAkshContainerConflict(t *testing.T) {
	pod := goldenPod(t)
	akshContainer(t, pod).Image = "other"
	_, err := testInjectorForPatch(t).Patch(pod)
	assertAdmissionError(t, err, "spec.containers[name=aksh]", "conflicts with required aksh sidecar")
}
func TestPatch_ConflictingHostCgroupVolume_ReturnsVolumeConflict(t *testing.T) {
	assertVolumeConflict(t, "hostcgroup")
}
func TestPatch_ConflictingCaPrivVolume_ReturnsVolumeConflict(t *testing.T) {
	assertVolumeConflict(t, "ca-priv")
}
func TestPatch_ConflictingCaPubVolume_ReturnsVolumeConflict(t *testing.T) {
	assertVolumeConflict(t, "ca-pub")
}
func TestPatch_ConflictingEntraTokenVolume_ReturnsVolumeConflict(t *testing.T) {
	assertVolumeConflict(t, "entra-token")
}
func TestPatch_ConflictingUpstreamCAVolume_ReturnsVolumeConflict(t *testing.T) {
	assertVolumeConflict(t, "upstream-ca")
}
func assertVolumeConflict(t *testing.T, name string) {
	t.Helper()
	pod := workloadPod()
	pod.Spec.Volumes = []corev1.Volume{{Name: name, VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/conflict"}}}}
	_, err := testInjectorForPatch(t).Patch(pod)
	assertAdmissionError(t, err, "spec.volumes[name="+name+"]", "conflicts with required aksh volume")
}

func TestPatch_ConcurrentRequests_DoesNotMutateSharedInjectorOptionsOrCallerPods(t *testing.T) {
	inj := testInjectorForPatch(t)
	snapshot := *inj
	const n = 50
	inputs := make([]*corev1.Pod, n)
	befores := make([]*corev1.Pod, n)
	for i := range inputs {
		inputs[i] = workloadPod()
		inputs[i].Name = "app" + string(rune('a'+i%26))
		befores[i] = inputs[i].DeepCopy()
	}
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for _, p := range inputs {
		wg.Add(1)
		go func(p *corev1.Pod) {
			defer wg.Done()
			out, err := inj.Patch(p)
			if err != nil {
				errs <- err
				return
			}
			if !isCanonicalAkshPod(out, testOptions()) {
				errs <- AdmissionError{Field: "out", Reason: "not canonical"}
			}
		}(p)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if *inj != snapshot {
		t.Fatalf("injector mutated")
	}
	for i := range inputs {
		if !reflect.DeepEqual(inputs[i], befores[i]) {
			t.Fatalf("input %d mutated", i)
		}
	}
}
