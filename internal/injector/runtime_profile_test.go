package injector

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// fullProfile is a fully-populated runtime profile mirroring the production e2e
// oracle plus a Secret-backed CA and capture network shaping. It exercises every
// optional field so the configured-vs-legacy behavior is distinguishable.
func fullProfile() RuntimeProfile {
	return RuntimeProfile{
		EntraTenantID:    "11111111-1111-1111-1111-111111111111",
		EntraClientID:    "22222222-2222-2222-2222-222222222222",
		EntraAuthority:   "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111",
		HostCgroupMount:  "/host/sys/fs/cgroup/unified",
		LocalCgroupMount: "/host/sys/fs/cgroup/unified",
		DNSServer:        "10.96.0.10:53",
		BypassCIDRs:      "10.96.0.0/12,10.0.0.0/8",
		CASecretName:     "aksh-pod-ca",
		CACertKey:        "tls.crt",
		CAPrivateKeyKey:  "tls.key",
		CAPublicCertKey:  "tls.crt",
		PodAttribution:   true,
	}
}

func profiledOptions(p RuntimeProfile) InjectorOptions {
	o := testOptions()
	o.RuntimeProfile = p
	return o
}

func profiledInjector(t *testing.T, p RuntimeProfile) *SidecarInjector {
	t.Helper()
	inj, err := NewSidecarInjector(profiledOptions(p))
	if err != nil {
		t.Fatalf("NewSidecarInjector(profile): %v", err)
	}
	return inj
}

// --- constructor validation ------------------------------------------------

func TestNewSidecarInjector_ZeroRuntimeProfile_Succeeds(t *testing.T) {
	if _, err := NewSidecarInjector(profiledOptions(RuntimeProfile{})); err != nil {
		t.Fatalf("zero profile rejected: %v", err)
	}
}
func TestNewSidecarInjector_FullValidProfile_Succeeds(t *testing.T) {
	if _, err := NewSidecarInjector(profiledOptions(fullProfile())); err != nil {
		t.Fatalf("full valid profile rejected: %v", err)
	}
}
func TestNewSidecarInjector_InvalidDNSServer_ReturnsError(t *testing.T) {
	p := RuntimeProfile{DNSServer: "not-a-host-port"}
	_, err := NewSidecarInjector(profiledOptions(p))
	assertAdmissionError(t, err, "runtimeProfile.dnsServer", "must be a host:port address")
}
func TestNewSidecarInjector_DNSServerWithoutPort_ReturnsError(t *testing.T) {
	p := RuntimeProfile{DNSServer: "10.96.0.10"}
	_, err := NewSidecarInjector(profiledOptions(p))
	assertAdmissionError(t, err, "runtimeProfile.dnsServer", "must be a host:port address")
}
func TestNewSidecarInjector_InvalidBypassCIDR_ReturnsError(t *testing.T) {
	p := RuntimeProfile{BypassCIDRs: "10.0.0.0/8,notacidr"}
	_, err := NewSidecarInjector(profiledOptions(p))
	assertAdmissionError(t, err, "runtimeProfile.bypassCIDRs", `entry "notacidr" is not a CIDR prefix`)
}
func TestNewSidecarInjector_BypassCIDRsTrailingComma_Succeeds(t *testing.T) {
	p := RuntimeProfile{BypassCIDRs: "10.96.0.0/12,"}
	if _, err := NewSidecarInjector(profiledOptions(p)); err != nil {
		t.Fatalf("trailing-comma bypass rejected: %v", err)
	}
}
func TestNewSidecarInjector_CASecretNameWithoutKeys_ReturnsError(t *testing.T) {
	p := RuntimeProfile{CASecretName: "aksh-pod-ca"}
	_, err := NewSidecarInjector(profiledOptions(p))
	assertAdmissionError(t, err, "runtimeProfile.caSecret", "requires certKey, privateKeyKey and publicCertKey")
}
func TestNewSidecarInjector_CASecretNameMissingOneKey_ReturnsError(t *testing.T) {
	p := RuntimeProfile{CASecretName: "aksh-pod-ca", CACertKey: "tls.crt", CAPrivateKeyKey: "tls.key"}
	_, err := NewSidecarInjector(profiledOptions(p))
	assertAdmissionError(t, err, "runtimeProfile.caSecret", "requires certKey, privateKeyKey and publicCertKey")
}
func TestNewSidecarInjector_CAKeysWithoutSecretName_Succeeds(t *testing.T) {
	// Key names are harmless (ignored) when no Secret backs the CA volumes.
	p := RuntimeProfile{CACertKey: "tls.crt", CAPrivateKeyKey: "tls.key", CAPublicCertKey: "tls.crt"}
	if _, err := NewSidecarInjector(profiledOptions(p)); err != nil {
		t.Fatalf("CA keys without secret rejected: %v", err)
	}
}

// --- configured env / mounts ----------------------------------------------

func profiledGoldenPod(t *testing.T, p RuntimeProfile) *corev1.Pod {
	t.Helper()
	pod, err := profiledInjector(t, p).Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch(profile): %v", err)
	}
	return pod
}

func TestPatch_ConfiguredEntra_StampsExactValues(t *testing.T) {
	p := fullProfile()
	env := envMap(akshContainer(t, profiledGoldenPod(t, p)))
	if env["AKSH_ENTRA_TENANT_ID"].Value != p.EntraTenantID ||
		env["AKSH_ENTRA_CLIENT_ID"].Value != p.EntraClientID ||
		env["AKSH_ENTRA_AUTHORITY"].Value != p.EntraAuthority {
		t.Fatalf("entra env = %#v", env["AKSH_ENTRA_TENANT_ID"])
	}
}
func TestPatch_ConfiguredCgroupMounts_StampExactValues(t *testing.T) {
	p := fullProfile()
	env := envMap(akshContainer(t, profiledGoldenPod(t, p)))
	if env["AKSH_CAPTURE_HOST_CGROUP_MOUNT"].Value != "/host/sys/fs/cgroup/unified" {
		t.Fatalf("host cgroup mount = %q", env["AKSH_CAPTURE_HOST_CGROUP_MOUNT"].Value)
	}
	if env["AKSH_CAPTURE_LOCAL_CGROUP_MOUNT"].Value != "/host/sys/fs/cgroup/unified" {
		t.Fatalf("local cgroup mount = %q", env["AKSH_CAPTURE_LOCAL_CGROUP_MOUNT"].Value)
	}
}
func TestPatch_ConfiguredDNSAndBypass_StampExactValues(t *testing.T) {
	p := fullProfile()
	env := envMap(akshContainer(t, profiledGoldenPod(t, p)))
	if env["AKSH_CAPTURE_DNS_SERVER"].Value != "10.96.0.10:53" {
		t.Fatalf("dns server = %q", env["AKSH_CAPTURE_DNS_SERVER"].Value)
	}
	if env["AKSH_CAPTURE_BYPASS_CIDRS"].Value != "10.96.0.0/12,10.0.0.0/8" {
		t.Fatalf("bypass cidrs = %q", env["AKSH_CAPTURE_BYPASS_CIDRS"].Value)
	}
}
func TestPatch_PodAttributionEnabled_AddsDownwardAPIEnv(t *testing.T) {
	env := envMap(akshContainer(t, profiledGoldenPod(t, fullProfile())))
	want := map[string]string{
		"AKSH_POD_NAMESPACE":         "metadata.namespace",
		"AKSH_POD_NAME":              "metadata.name",
		"AKSH_POD_UID":               "metadata.uid",
		"AKSH_AGENT_SERVICE_ACCOUNT": "spec.serviceAccountName",
	}
	for name, path := range want {
		e, ok := env[name]
		if !ok || e.ValueFrom == nil || e.ValueFrom.FieldRef == nil || e.ValueFrom.FieldRef.FieldPath != path {
			t.Fatalf("attribution env %s = %#v want fieldRef %s", name, e, path)
		}
	}
}
func TestPatch_PodAttributionDisabled_OmitsDownwardAPIEnv(t *testing.T) {
	env := envMap(akshContainer(t, goldenPod(t)))
	for _, name := range []string{"AKSH_POD_NAMESPACE", "AKSH_POD_NAME", "AKSH_POD_UID", "AKSH_AGENT_SERVICE_ACCOUNT"} {
		if _, ok := env[name]; ok {
			t.Fatalf("attribution env %s present in legacy profile", name)
		}
	}
}
func TestPatch_LegacyProfile_OmitsOptionalCaptureEnv(t *testing.T) {
	env := envMap(akshContainer(t, goldenPod(t)))
	for _, name := range []string{"AKSH_CAPTURE_LOCAL_CGROUP_MOUNT", "AKSH_CAPTURE_DNS_SERVER", "AKSH_CAPTURE_BYPASS_CIDRS"} {
		if _, ok := env[name]; ok {
			t.Fatalf("optional env %s present in legacy profile", name)
		}
	}
}
func TestPatch_LegacyProfile_EnvCountUnchanged(t *testing.T) {
	if got := len(envMap(akshContainer(t, goldenPod(t)))); got != 16 {
		t.Fatalf("legacy env count = %d, want 16", got)
	}
}

// --- configured CA volumes -------------------------------------------------

func TestPatch_ConfiguredCASecret_BacksCaPrivWithCertAndKey(t *testing.T) {
	pod := profiledGoldenPod(t, fullProfile())
	v := volumeNamed(t, pod, "ca-priv")
	if v.Secret == nil || v.Secret.SecretName != "aksh-pod-ca" {
		t.Fatalf("ca-priv = %#v want secret aksh-pod-ca", v.VolumeSource)
	}
	want := []corev1.KeyToPath{{Key: "tls.crt", Path: "ca-cert.pem"}, {Key: "tls.key", Path: "ca-key.pem"}}
	if !reflect.DeepEqual(v.Secret.Items, want) {
		t.Fatalf("ca-priv items = %#v want %#v", v.Secret.Items, want)
	}
}
func TestPatch_ConfiguredCASecret_BacksCaPubWithPublicCertOnly(t *testing.T) {
	pod := profiledGoldenPod(t, fullProfile())
	v := volumeNamed(t, pod, "ca-pub")
	if v.Secret == nil || v.Secret.SecretName != "aksh-pod-ca" {
		t.Fatalf("ca-pub = %#v want secret aksh-pod-ca", v.VolumeSource)
	}
	want := []corev1.KeyToPath{{Key: "tls.crt", Path: "ca-cert.pem"}}
	if !reflect.DeepEqual(v.Secret.Items, want) {
		t.Fatalf("ca-pub items = %#v want %#v", v.Secret.Items, want)
	}
}
func TestPatch_ConfiguredCASecret_UsesDistinctKeyNames(t *testing.T) {
	p := fullProfile()
	p.CACertKey = "ca.crt"
	p.CAPrivateKeyKey = "ca.key"
	p.CAPublicCertKey = "public.crt"
	pod := profiledGoldenPod(t, p)
	priv := volumeNamed(t, pod, "ca-priv")
	pub := volumeNamed(t, pod, "ca-pub")
	if priv.Secret.Items[0].Key != "ca.crt" || priv.Secret.Items[1].Key != "ca.key" || pub.Secret.Items[0].Key != "public.crt" {
		t.Fatalf("key mapping wrong: priv=%#v pub=%#v", priv.Secret.Items, pub.Secret.Items)
	}
}
func TestPatch_LegacyProfile_KeepsEmptyDirCAVolumes(t *testing.T) {
	pod := goldenPod(t)
	if volumeNamed(t, pod, "ca-priv").EmptyDir == nil || volumeNamed(t, pod, "ca-pub").EmptyDir == nil {
		t.Fatal("legacy CA volumes not emptyDir")
	}
}
func TestPatch_ConfiguredCASecret_LeavesMountsUnchanged(t *testing.T) {
	c := akshContainer(t, profiledGoldenPod(t, fullProfile()))
	want := map[string]struct {
		path string
		ro   bool
	}{"ca-priv": {"/var/lib/aksh/ca-priv", false}, "ca-pub": {"/var/lib/aksh/ca-pub", false}}
	for _, m := range c.VolumeMounts {
		if w, ok := want[m.Name]; ok {
			if m.MountPath != w.path || m.ReadOnly != w.ro {
				t.Fatalf("mount %s = %#v want %#v", m.Name, m, w)
			}
		}
	}
}

// --- Secret default equivalence (API defaulting tolerance) -----------------

func TestVolumeSourceEquivalent_SecretDefaultModeTolerated(t *testing.T) {
	want := canonicalVolumes(fullProfile())
	var wantPriv corev1.VolumeSource
	for _, v := range want {
		if v.Name == "ca-priv" {
			wantPriv = v.VolumeSource
		}
	}
	// Simulate API-server defaulting: defaultMode populated after the webhook
	// returns. The equivalence must still hold.
	got := *wantPriv.DeepCopy()
	got.Secret.DefaultMode = ptr.To[int32](0o644)
	if !volumeSourceEquivalent(got, wantPriv) {
		t.Fatal("Secret defaultMode defaulting not tolerated")
	}
}
func TestVolumeSourceEquivalent_SecretNameDriftRejected(t *testing.T) {
	want := canonicalVolumes(fullProfile())
	var wantPriv corev1.VolumeSource
	for _, v := range want {
		if v.Name == "ca-priv" {
			wantPriv = v.VolumeSource
		}
	}
	got := *wantPriv.DeepCopy()
	got.Secret.SecretName = "attacker-secret"
	if volumeSourceEquivalent(got, wantPriv) {
		t.Fatal("Secret name drift accepted")
	}
}
func TestVolumeSourceEquivalent_SecretItemsDriftRejected(t *testing.T) {
	want := canonicalVolumes(fullProfile())
	var wantPriv corev1.VolumeSource
	for _, v := range want {
		if v.Name == "ca-priv" {
			wantPriv = v.VolumeSource
		}
	}
	got := *wantPriv.DeepCopy()
	got.Secret.Items[0].Key = "attacker.crt"
	if volumeSourceEquivalent(got, wantPriv) {
		t.Fatal("Secret items drift accepted")
	}
}

// --- mutation idempotency with a configured profile ------------------------

func TestPatch_ConfiguredProfile_IsIdempotent(t *testing.T) {
	inj := profiledInjector(t, fullProfile())
	once, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("first Patch: %v", err)
	}
	twice, err := inj.Patch(once)
	if err != nil {
		t.Fatalf("second Patch: %v", err)
	}
	if !reflect.DeepEqual(once, twice) {
		t.Fatal("configured profile Patch not idempotent")
	}
	if !isCanonicalAkshPod(once, profiledOptions(fullProfile())) {
		t.Fatal("configured Patch output not canonical")
	}
}
func TestPatch_ConfiguredProfile_ValidatePasses(t *testing.T) {
	inj := profiledInjector(t, fullProfile())
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	pod.Spec.HostPID = true
	if err := inj.Validate(pod); err != nil {
		t.Fatalf("Validate(configured canonical pod) = %v", err)
	}
}

// --- tamper rejection against the configured profile -----------------------

func TestValidate_TamperedEntraValue_Denied(t *testing.T) {
	inj := profiledInjector(t, fullProfile())
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	c := akshContainer(t, pod)
	for i := range c.Env {
		if c.Env[i].Name == "AKSH_ENTRA_TENANT_ID" {
			c.Env[i].Value = "99999999-9999-9999-9999-999999999999"
		}
	}
	if err := inj.Validate(pod); err == nil {
		t.Fatal("tampered Entra tenant accepted")
	}
}
func TestValidate_TamperedHostCgroupMount_Denied(t *testing.T) {
	inj := profiledInjector(t, fullProfile())
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	c := akshContainer(t, pod)
	for i := range c.Env {
		if c.Env[i].Name == "AKSH_CAPTURE_HOST_CGROUP_MOUNT" {
			c.Env[i].Value = "/attacker/path"
		}
	}
	if err := inj.Validate(pod); err == nil {
		t.Fatal("tampered host cgroup mount accepted")
	}
}
func TestValidate_TamperedBypassCIDRs_Denied(t *testing.T) {
	inj := profiledInjector(t, fullProfile())
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	c := akshContainer(t, pod)
	for i := range c.Env {
		if c.Env[i].Name == "AKSH_CAPTURE_BYPASS_CIDRS" {
			c.Env[i].Value = "0.0.0.0/0"
		}
	}
	if err := inj.Validate(pod); err == nil {
		t.Fatal("tampered bypass CIDRs accepted")
	}
}
func TestValidate_TamperedCASecretName_Denied(t *testing.T) {
	inj := profiledInjector(t, fullProfile())
	pod, err := inj.Patch(workloadPod())
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	pod.Spec.HostPID = true
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == "ca-priv" {
			pod.Spec.Volumes[i].Secret.SecretName = "attacker-secret"
		}
	}
	err = inj.Validate(pod)
	assertAdmissionError(t, err, "spec.volumes[name=ca-priv]", reasonVolumeSource)
}

// --- legacy canonical predicate unaffected by unset profile ----------------

func TestCanonicalEnvPresent_LegacyEntraPlaceholderIsPresenceOnly(t *testing.T) {
	// A legacy-injected pod carrying REAL Entra values (as the e2e oracle does)
	// is still canonical under the zero profile: unset Entra fields are
	// presence-only.
	pod := goldenPod(t)
	c := akshContainer(t, pod)
	for i := range c.Env {
		if c.Env[i].Name == "AKSH_ENTRA_TENANT_ID" {
			c.Env[i].Value = "real-tenant-from-cluster"
		}
	}
	if !isCanonicalAkshPod(pod, testOptions()) {
		t.Fatal("legacy pod with real Entra value not canonical")
	}
}

// --- real kagent pod fields remain admissible ------------------------------

// automountServiceAccountToken:false is a common controller default and must
// stay admissible after injection; only the true (leak) case is denied.
func TestValidate_AutomountServiceAccountTokenFalse_Admissible(t *testing.T) {
	inj := profiledInjector(t, fullProfile())
	base := workloadPod()
	base.Spec.AutomountServiceAccountToken = ptr.To(false)
	base.Spec.ServiceAccountName = "kagent"
	pod, err := inj.Patch(base)
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	pod.Spec.HostPID = true
	if err := inj.Validate(pod); err != nil {
		t.Fatalf("Validate(automount=false) = %v", err)
	}
}
func TestValidate_AutomountServiceAccountTokenTrue_Denied(t *testing.T) {
	inj := profiledInjector(t, fullProfile())
	base := workloadPod()
	pod, err := inj.Patch(base)
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	pod.Spec.HostPID = true
	pod.Spec.AutomountServiceAccountToken = ptr.To(true)
	assertAdmissionError(t, inj.Validate(pod), "spec.automountServiceAccountToken", reasonAutomount)
}

// A kagent workload container declaring its own unrelated volumes/labels is
// admissible: injection adds the aksh sidecar and leaves the workload intact.
func TestPatch_KagentStyleWorkload_ProducesCanonicalPod(t *testing.T) {
	inj := profiledInjector(t, fullProfile())
	base := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kagent-x",
			Namespace: "kagent-ns",
			Labels:    map[string]string{"app": "kagent", "kagent.dev/agent": "x"},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName:           "kagent",
			AutomountServiceAccountToken: ptr.To(false),
			Containers: []corev1.Container{{
				Name:  "kagent",
				Image: "kagent:latest",
				VolumeMounts: []corev1.VolumeMount{
					{Name: "config", MountPath: "/config"},
				},
			}},
			Volumes: []corev1.Volume{{Name: "config", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
		},
	}
	pod, err := inj.Patch(base)
	if err != nil {
		t.Fatalf("Patch(kagent pod): %v", err)
	}
	if !isCanonicalAkshPod(pod, profiledOptions(fullProfile())) {
		t.Fatal("injected kagent pod not canonical")
	}
	pod.Spec.HostPID = true
	if err := inj.Validate(pod); err != nil {
		t.Fatalf("Validate(injected kagent pod) = %v", err)
	}
}
