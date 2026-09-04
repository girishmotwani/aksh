package injector

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// secretContainmentProfile protects both a CA Secret and a static-token Secret
// so every reference vector can be exercised against a known protected name.
func secretContainmentProfile() RuntimeProfile {
	p := fullProfile()
	p.StaticTokenSecretName = "aksh-model-credentials"
	p.StaticTokenSecretKey = "api-key"
	return p
}

const (
	protectedCASecret     = "aksh-pod-ca"            // == fullProfile().CASecretName
	protectedStaticSecret = "aksh-model-credentials" // == static secret name above
)

// injectedPod returns a validated-shape canonical pod for the given profile with
// hostPID repaired, ready for tamper mutations before Validate.
func injectedPod(t *testing.T, p RuntimeProfile) (*SidecarInjector, *corev1.Pod) {
	t.Helper()
	inj := profiledInjector(t, p)
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	pod.Spec.HostPID = true
	return inj, pod
}

// appContainer returns a pointer to the first non-aksh container so a test can
// attach an illicit reference to the workload.
func appContainer(t *testing.T, pod *corev1.Pod) *corev1.Container {
	t.Helper()
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name != akshContainerName {
			return &pod.Spec.Containers[i]
		}
	}
	t.Fatal("no app container found")
	return nil
}

// --- baseline: a clean injected pod passes -------------------------------

func TestValidate_CleanInjectedPod_PassesContainment(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	if err := inj.Validate(pod); err != nil {
		t.Fatalf("clean injected pod rejected: %v", err)
	}
}

// --- volume by arbitrary name --------------------------------------------

func TestValidate_AppSecretVolumeUnderArbitraryName_CADenied(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name:         "sneaky",
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: protectedCASecret}},
	})
	c := appContainer(t, pod)
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "sneaky", MountPath: "/steal", ReadOnly: true})
	assertReason(t, inj.Validate(pod), reasonProtectedSecretVol)
}

func TestValidate_AppSecretVolumeUnderArbitraryName_StaticDenied(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name:         "sneaky",
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: protectedStaticSecret}},
	})
	c := appContainer(t, pod)
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "sneaky", MountPath: "/steal", ReadOnly: true})
	assertReason(t, inj.Validate(pod), reasonProtectedSecretVol)
}

// A Secret volume that references the protected name but is NEVER mounted by an
// app container is inert and must not, by itself, break an otherwise clean pod
// (defense stays targeted at reachable exfiltration paths).
func TestValidate_UnmountedProtectedSecretVolume_Allowed(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name:         "declared-not-mounted",
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: protectedStaticSecret}},
	})
	if err := inj.Validate(pod); err != nil {
		t.Fatalf("unmounted protected secret volume must not fail validation: %v", err)
	}
}

// --- projected secret source ---------------------------------------------

func TestValidate_AppProjectedSecretSource_Denied(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: "mixed-projected",
		VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
			{DownwardAPI: &corev1.DownwardAPIProjection{Items: []corev1.DownwardAPIVolumeFile{{Path: "labels", FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.labels"}}}}},
			{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: protectedCASecret}}},
		}}},
	})
	c := appContainer(t, pod)
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "mixed-projected", MountPath: "/steal", ReadOnly: true})
	assertReason(t, inj.Validate(pod), reasonProtectedSecretVol)
}

// --- env.valueFrom.secretKeyRef ------------------------------------------

func TestValidate_AppSecretKeyRefEnv_Denied(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	c := appContainer(t, pod)
	c.Env = append(c.Env, corev1.EnvVar{
		Name:      "STOLEN",
		ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: protectedStaticSecret}, Key: "api-key"}},
	})
	assertReason(t, inj.Validate(pod), reasonProtectedSecretEnv)
}

// --- envFrom.secretRef ----------------------------------------------------

func TestValidate_AppEnvFromSecretRef_Denied(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	c := appContainer(t, pod)
	c.EnvFrom = append(c.EnvFrom, corev1.EnvFromSource{
		SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: protectedCASecret}},
	})
	assertReason(t, inj.Validate(pod), reasonProtectedSecretEnv)
}

// --- init containers ------------------------------------------------------

func TestValidate_InitContainerSecretKeyRef_Denied(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, corev1.Container{
		Name:  "init",
		Image: "busybox",
		Env: []corev1.EnvVar{{
			Name:      "K",
			ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: protectedStaticSecret}, Key: "api-key"}},
		}},
	})
	assertReason(t, inj.Validate(pod), reasonProtectedSecretEnv)
}

func TestValidate_InitContainerSecretVolume_Denied(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name:         "init-vol",
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: protectedCASecret}},
	})
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, corev1.Container{
		Name:         "init",
		Image:        "busybox",
		VolumeMounts: []corev1.VolumeMount{{Name: "init-vol", MountPath: "/steal"}},
	})
	assertReason(t, inj.Validate(pod), reasonProtectedSecretVol)
}

// --- ephemeral (debug) containers ----------------------------------------

func TestValidate_EphemeralContainerEnvFromSecret_Denied(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:    "debug",
			Image:   "busybox",
			EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: protectedStaticSecret}}}},
		},
	})
	assertReason(t, inj.Validate(pod), reasonProtectedSecretEnv)
}

func TestValidate_EphemeralContainerProjectedSecret_Denied(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: "eph-proj",
		VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
			{Secret: &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: protectedCASecret}}},
		}}},
	})
	pod.Spec.EphemeralContainers = append(pod.Spec.EphemeralContainers, corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:         "debug",
			Image:        "busybox",
			VolumeMounts: []corev1.VolumeMount{{Name: "eph-proj", MountPath: "/steal"}},
		},
	})
	assertReason(t, inj.Validate(pod), reasonProtectedSecretVol)
}

// --- legitimate references remain allowed ---------------------------------

// An app container referencing an UNRELATED Secret (not a protected name) is
// perfectly fine and must pass — the containment is name-scoped, not a blanket
// Secret ban.
func TestValidate_AppReferencesUnrelatedSecret_Allowed(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name:         "app-cfg",
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "some-app-secret"}},
	})
	c := appContainer(t, pod)
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "app-cfg", MountPath: "/cfg", ReadOnly: true})
	c.EnvFrom = append(c.EnvFrom, corev1.EnvFromSource{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "another-app-secret"}}})
	if err := inj.Validate(pod); err != nil {
		t.Fatalf("unrelated Secret reference wrongly denied: %v", err)
	}
}

// The aksh sidecar itself legitimately references the protected Secrets (ca-priv
// via CASecretName, aksh-static-token via StaticTokenSecretName); containment
// must skip it so a correctly-injected pod validates.
func TestValidate_AkshContainerReferencesProtected_Allowed(t *testing.T) {
	inj, pod := injectedPod(t, secretContainmentProfile())
	// The canonical ca-priv/ca-pub/aksh-static-token volumes reference the
	// protected Secrets by construction; a clean pod must still validate.
	if err := inj.Validate(pod); err != nil {
		t.Fatalf("aksh sidecar's own protected references denied: %v", err)
	}
}

// A legacy zero profile has no protected Secrets, so containment is a no-op and
// any app Secret reference is allowed (backward-compatible).
func TestValidate_ZeroProfile_NoProtectedSecrets(t *testing.T) {
	inj := testInjectorForPatch(t)
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	pod.Spec.HostPID = true
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name:         "whatever",
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "aksh-pod-ca"}},
	})
	c := appContainer(t, pod)
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "whatever", MountPath: "/x"})
	if err := inj.Validate(pod); err != nil {
		t.Fatalf("zero profile must not protect any Secret name: %v", err)
	}
}

// Static-only profile protects only the static Secret, not an arbitrary CA name.
func TestValidate_StaticOnlyProfile_ProtectsOnlyStaticName(t *testing.T) {
	p := RuntimeProfile{StaticTokenSecretName: protectedStaticSecret, StaticTokenSecretKey: "api-key"}
	inj, pod := injectedPod(t, p)
	// Referencing the static name is denied.
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name:         "s",
		VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: protectedStaticSecret}},
	})
	c := appContainer(t, pod)
	c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "s", MountPath: "/s"})
	assertReason(t, inj.Validate(pod), reasonProtectedSecretVol)
}

func TestProtectedSecretNames_ProfileMapping(t *testing.T) {
	got := protectedSecretNames(secretContainmentProfile())
	if !got[protectedCASecret] || !got[protectedStaticSecret] {
		t.Fatalf("protected names = %v, want both CA and static", got)
	}
	if len(protectedSecretNames(RuntimeProfile{})) != 0 {
		t.Fatal("zero profile must yield no protected names")
	}
}

// assertReason asserts an AdmissionError with the given reason (field varies by
// vector and is asserted loosely).
func assertReason(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected AdmissionError with reason %q, got nil", reason)
	}
	ae, ok := err.(AdmissionError)
	if !ok {
		t.Fatalf("error type %T, want AdmissionError", err)
	}
	if ae.Reason != reason {
		t.Fatalf("reason = %q, want %q (field=%q)", ae.Reason, reason, ae.Field)
	}
}
