package injector

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

// staticProfile returns a legacy profile augmented with a static bearer token
// Secret so the static-credential wiring is exercised in isolation.
func staticProfile() RuntimeProfile {
	return RuntimeProfile{StaticTokenSecretName: "aksh-model-credentials", StaticTokenSecretKey: "api-key"}
}

func staticProfiledPod(t *testing.T, p RuntimeProfile) *corev1.Pod {
	t.Helper()
	pod, err := profiledInjector(t, p).Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch(static profile): %v", err)
	}
	return pod
}

// --- constructor validation ------------------------------------------------

func TestNewSidecarInjector_StaticSecretWithoutKey_ReturnsError(t *testing.T) {
	p := RuntimeProfile{StaticTokenSecretName: "aksh-model-credentials"}
	_, err := NewSidecarInjector(profiledOptions(p))
	assertAdmissionError(t, err, "runtimeProfile.staticToken", "requires secretKey when secretName is set")
}

func TestNewSidecarInjector_StaticSecretWithKey_Succeeds(t *testing.T) {
	if _, err := NewSidecarInjector(profiledOptions(staticProfile())); err != nil {
		t.Fatalf("valid static profile rejected: %v", err)
	}
}

func TestNewSidecarInjector_StaticKeyWithoutSecretName_Succeeds(t *testing.T) {
	// A key name alone is harmless (ignored) when no Secret is configured.
	p := RuntimeProfile{StaticTokenSecretKey: "api-key"}
	if _, err := NewSidecarInjector(profiledOptions(p)); err != nil {
		t.Fatalf("static key without secret rejected: %v", err)
	}
}

// --- configured volume / mount / env ---------------------------------------

func TestPatch_ConfiguredStaticSecret_AddsReadOnlySecretVolume(t *testing.T) {
	pod := staticProfiledPod(t, staticProfile())
	v := volumeNamed(t, pod, staticTokenVolumeName)
	if v.Secret == nil || v.Secret.SecretName != "aksh-model-credentials" {
		t.Fatalf("static volume = %#v want secret aksh-model-credentials", v.VolumeSource)
	}
	want := []corev1.KeyToPath{{Key: "api-key", Path: staticTokenFileName}}
	if !reflect.DeepEqual(v.Secret.Items, want) {
		t.Fatalf("static volume items = %#v want %#v", v.Secret.Items, want)
	}
}

func TestPatch_ConfiguredStaticSecret_MountsReadOnlyIntoAkshContainerOnly(t *testing.T) {
	pod := staticProfiledPod(t, staticProfile())
	aksh := akshContainer(t, pod)
	var found bool
	for _, m := range aksh.VolumeMounts {
		if m.Name == staticTokenVolumeName {
			found = true
			if m.MountPath != staticTokenMountPath {
				t.Fatalf("static mount path = %q want %q", m.MountPath, staticTokenMountPath)
			}
			if !m.ReadOnly {
				t.Fatalf("static mount must be read-only")
			}
		}
	}
	if !found {
		t.Fatalf("aksh container missing static token mount")
	}
	// The workload container (index shifted after the sidecar is prepended) must
	// NOT mount the static credential.
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if c.Name == akshContainerName {
			continue
		}
		if countNamedMounts(c, staticTokenVolumeName) != 0 {
			t.Fatalf("app container %q must not mount the static token", c.Name)
		}
	}
}

func TestPatch_ConfiguredStaticSecret_StampsFixedTokenPathEnv(t *testing.T) {
	env := envMap(akshContainer(t, staticProfiledPod(t, staticProfile())))
	e, ok := env[staticTokenEnvVar]
	if !ok {
		t.Fatalf("%s not stamped", staticTokenEnvVar)
	}
	if e.Value != staticTokenMountPath+"/"+staticTokenFileName {
		t.Fatalf("%s = %q want %q", staticTokenEnvVar, e.Value, staticTokenMountPath+"/"+staticTokenFileName)
	}
}

func TestPatch_ConfiguredStaticSecret_UsesConfiguredKeyName(t *testing.T) {
	p := RuntimeProfile{StaticTokenSecretName: "creds", StaticTokenSecretKey: "OPENAI_API_KEY"}
	v := volumeNamed(t, staticProfiledPod(t, p), staticTokenVolumeName)
	if v.Secret.Items[0].Key != "OPENAI_API_KEY" {
		t.Fatalf("static key mapping = %q want OPENAI_API_KEY", v.Secret.Items[0].Key)
	}
}

// --- legacy (zero profile) preservation ------------------------------------

func TestPatch_LegacyProfile_OmitsStaticTokenVolumeAndEnv(t *testing.T) {
	pod := goldenPod(t)
	if countNamedVolumes(pod, staticTokenVolumeName) != 0 {
		t.Fatalf("legacy profile must not add the static token volume")
	}
	if _, ok := envMap(akshContainer(t, pod))[staticTokenEnvVar]; ok {
		t.Fatalf("legacy profile must not stamp %s", staticTokenEnvVar)
	}
	if countNamedMounts(akshContainer(t, pod), staticTokenVolumeName) != 0 {
		t.Fatalf("legacy profile must not mount the static token")
	}
}

// --- idempotency + validation ----------------------------------------------

func TestPatch_StaticProfile_IsIdempotent(t *testing.T) {
	inj := profiledInjector(t, staticProfile())
	once, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("first Patch: %v", err)
	}
	twice, err := inj.Patch(once)
	if err != nil {
		t.Fatalf("second Patch: %v", err)
	}
	if !reflect.DeepEqual(once, twice) {
		t.Fatal("static profile Patch not idempotent")
	}
	if !isCanonicalAkshPod(once, profiledOptions(staticProfile())) {
		t.Fatal("static Patch output not canonical")
	}
}

func TestPatch_StaticProfile_ValidatePasses(t *testing.T) {
	inj := profiledInjector(t, staticProfile())
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	pod.Spec.HostPID = true
	if err := inj.Validate(pod); err != nil {
		t.Fatalf("Validate(static canonical pod) = %v", err)
	}
}

// --- Secret API defaulting tolerance ---------------------------------------

func TestVolumeSourceEquivalent_StaticSecretDefaultModeTolerated(t *testing.T) {
	var want corev1.VolumeSource
	for _, v := range canonicalVolumes(staticProfile()) {
		if v.Name == staticTokenVolumeName {
			want = v.VolumeSource
		}
	}
	got := *want.DeepCopy()
	got.Secret.DefaultMode = ptr.To[int32](0o644)
	if !volumeSourceEquivalent(got, want) {
		t.Fatal("static Secret defaultMode defaulting not tolerated")
	}
}

// --- tamper / value-lock rejection -----------------------------------------

func TestValidate_TamperedStaticTokenPathEnv_Denied(t *testing.T) {
	inj := profiledInjector(t, staticProfile())
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	pod.Spec.HostPID = true
	c := akshContainer(t, pod)
	for i := range c.Env {
		if c.Env[i].Name == staticTokenEnvVar {
			c.Env[i].Value = "/attacker/path/token"
		}
	}
	if err := inj.Validate(pod); err == nil {
		t.Fatal("tampered static token path accepted")
	}
}

func TestValidate_TamperedStaticSecretName_Denied(t *testing.T) {
	inj := profiledInjector(t, staticProfile())
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	pod.Spec.HostPID = true
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == staticTokenVolumeName {
			pod.Spec.Volumes[i].Secret.SecretName = "attacker-secret"
		}
	}
	assertAdmissionError(t, inj.Validate(pod), "spec.volumes[name="+staticTokenVolumeName+"]", reasonVolumeSource)
}

func TestValidate_MissingStaticTokenVolume_Denied(t *testing.T) {
	inj := profiledInjector(t, staticProfile())
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	pod.Spec.HostPID = true
	volumes := pod.Spec.Volumes[:0:0]
	for _, v := range pod.Spec.Volumes {
		if v.Name != staticTokenVolumeName {
			volumes = append(volumes, v)
		}
	}
	pod.Spec.Volumes = volumes
	assertAdmissionError(t, inj.Validate(pod), "spec.volumes[name="+staticTokenVolumeName+"]", reasonVolumeMissing)
}

// --- app-container leakage rejection ---------------------------------------

func TestValidate_AppContainerMountsStaticToken_Denied(t *testing.T) {
	inj := profiledInjector(t, staticProfile())
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	pod.Spec.HostPID = true
	// The workload attempts to mount the aksh-only static credential.
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name != akshContainerName {
			pod.Spec.Containers[i].VolumeMounts = append(pod.Spec.Containers[i].VolumeMounts,
				corev1.VolumeMount{Name: staticTokenVolumeName, MountPath: "/steal", ReadOnly: true})
		}
	}
	err = inj.Validate(pod)
	if err == nil {
		t.Fatal("app container mounting the static token must be denied")
	}
	ae, ok := err.(AdmissionError)
	if !ok || ae.Reason != reasonStaticTokenLeakage {
		t.Fatalf("error = %#v, want reason %q", err, reasonStaticTokenLeakage)
	}
}
