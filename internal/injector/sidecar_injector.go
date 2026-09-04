package injector

import (
	"fmt"
	"net/netip"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

const (
	reservedID          = int64(1774)
	akshContainerName   = "aksh"
	injectionAnnotation = "aksh.dev/injected"
)

var canonicalCapabilities = []corev1.Capability{"BPF", "NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_RESOURCE", "PERFMON", "SETGID", "SETUID", "SETPCAP"}

type SidecarInjector struct {
	proxyImage       string
	reservedUID      int64
	reservedGID      int64
	optInLabelKey    string
	optInLabelValue  string
	injectionVersion string
	profile          RuntimeProfile
}

func NewSidecarInjector(opts InjectorOptions) (*SidecarInjector, error) {
	if strings.TrimSpace(opts.ProxyImage) == "" {
		return nil, AdmissionError{Field: "proxyImage", Reason: "required"}
	}
	if strings.TrimSpace(opts.OptInLabelKey) == "" || strings.TrimSpace(opts.OptInLabelValue) == "" {
		return nil, AdmissionError{Field: "optInLabel", Reason: "required"}
	}
	if strings.TrimSpace(opts.InjectionVersion) == "" {
		return nil, AdmissionError{Field: "injectionVersion", Reason: "required"}
	}
	if opts.ReservedUID != reservedID {
		return nil, AdmissionError{Field: "reservedUID", Reason: "must be 1774"}
	}
	if opts.ReservedGID != reservedID {
		return nil, AdmissionError{Field: "reservedGID", Reason: "must be 1774"}
	}
	if err := validateRuntimeProfile(opts.RuntimeProfile); err != nil {
		return nil, err
	}
	return &SidecarInjector{proxyImage: opts.ProxyImage, reservedUID: opts.ReservedUID, reservedGID: opts.ReservedGID, optInLabelKey: opts.OptInLabelKey, optInLabelValue: opts.OptInLabelValue, injectionVersion: opts.InjectionVersion, profile: opts.RuntimeProfile}, nil
}

// Bypass/DNS invariant bounds mirror the capture layer's LPM-trie and
// aksh_config constraints (internal/dataplane/capture: minBypassPrefixBits,
// maxBypassCIDRs, and Options.Validate's DNSServer check). They are duplicated
// here — not imported — because the capture package keeps its validators
// unexported and the injector deliberately avoids importing the dataplane; a
// malformed profile must fail at admission rather than produce a pod the proxy
// rejects at startup. Keep these in lockstep with capture.
const (
	injectorMinBypassPrefixBits = 8
	injectorMaxBypassCIDRs      = 64
)

// validateRuntimeProfile fail-closes on a profile that would stamp a
// non-functional or ambiguous sidecar. Only set fields are checked, so the zero
// profile always passes. Bypass/DNS validation is only ADDED here, never
// weakened: a malformed value is rejected at construction rather than silently
// producing a pod the proxy rejects at startup.
func validateRuntimeProfile(p RuntimeProfile) error {
	if err := validateProfileDNSServer(p.DNSServer); err != nil {
		return err
	}
	if err := validateBypassCIDRs(p.BypassCIDRs); err != nil {
		return err
	}
	if strings.TrimSpace(p.CASecretName) != "" {
		if strings.TrimSpace(p.CACertKey) == "" || strings.TrimSpace(p.CAPrivateKeyKey) == "" || strings.TrimSpace(p.CAPublicCertKey) == "" {
			return AdmissionError{Field: "runtimeProfile.caSecret", Reason: "requires certKey, privateKeyKey and publicCertKey"}
		}
	}
	if strings.TrimSpace(p.StaticTokenSecretName) != "" && strings.TrimSpace(p.StaticTokenSecretKey) == "" {
		return AdmissionError{Field: "runtimeProfile.staticToken", Reason: "requires secretKey when secretName is set"}
	}
	return nil
}

// validateProfileDNSServer enforces the capture layer's DNSServer invariant: the
// DEV-01 DNS exception is written into a 32-bit IPv4 field of aksh_config, so a
// set value must be an IPv4 (unmapped) address with a non-zero port. An IPv6
// value or a zero port would reach netip.Addr.As4() and panic at proxy startup.
func validateProfileDNSServer(dnsServer string) error {
	s := strings.TrimSpace(dnsServer)
	if s == "" {
		return nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return AdmissionError{Field: "runtimeProfile.dnsServer", Reason: "must be a host:port address"}
	}
	if !ap.Addr().Unmap().Is4() || ap.Port() == 0 {
		return AdmissionError{Field: "runtimeProfile.dnsServer", Reason: "must be an IPv4 address with a non-zero port"}
	}
	return nil
}

// validateBypassCIDRs enforces the capture layer's actual bypass invariants
// (internal/dataplane/capture.canonicalBypassPrefix + validateBypassCIDRs):
// every non-empty comma-separated entry must be an IPv4 prefix of /8 or longer
// with no host bits set, and there may be at most 64 entries. Empty entries from
// trailing/doubled commas are tolerated so the value round-trips exactly.
func validateBypassCIDRs(list string) error {
	count := 0
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return AdmissionError{Field: "runtimeProfile.bypassCIDRs", Reason: fmt.Sprintf("entry %q is not a CIDR prefix", f)}
		}
		if err := validateBypassPrefix(p); err != nil {
			return err
		}
		count++
	}
	if count > injectorMaxBypassCIDRs {
		return AdmissionError{Field: "runtimeProfile.bypassCIDRs", Reason: fmt.Sprintf("has %d entries, more than the %d the kernel map holds", count, injectorMaxBypassCIDRs)}
	}
	return nil
}

// validateBypassPrefix mirrors capture.canonicalBypassPrefix: it unmaps the
// address first (so ::ffff:10.0.0.0 is treated as the IPv4 prefix the kernel
// key must contain), then rejects non-IPv4 prefixes, prefixes shorter than /8
// (which would leave arbitrary destinations unpoliced, including /0), and
// prefixes with host bits set (a likely typo for a single host).
func validateBypassPrefix(p netip.Prefix) error {
	const field = "runtimeProfile.bypassCIDRs"
	addr := p.Addr().Unmap()
	if !addr.Is4() {
		return AdmissionError{Field: field, Reason: fmt.Sprintf("entry %v is not IPv4 (capture is IPv4 only)", p)}
	}
	canon := netip.PrefixFrom(addr, p.Bits())
	if !canon.IsValid() {
		return AdmissionError{Field: field, Reason: fmt.Sprintf("entry %v has a prefix length not valid for IPv4", p)}
	}
	if canon.Bits() < injectorMinBypassPrefixBits {
		return AdmissionError{Field: field, Reason: fmt.Sprintf("entry %v is shorter than /%d", canon, injectorMinBypassPrefixBits)}
	}
	if canon.Masked() != canon {
		return AdmissionError{Field: field, Reason: fmt.Sprintf("entry %v has host bits set", canon)}
	}
	return nil
}

func (s *SidecarInjector) Patch(pod *corev1.Pod) (*corev1.Pod, error) {
	if pod == nil {
		return nil, AdmissionError{Field: "pod", Reason: "required"}
	}
	if len(pod.Spec.Containers) == 0 {
		return nil, AdmissionError{Field: "spec.containers", Reason: "required"}
	}
	out := pod.DeepCopy()
	opts := s.options()
	if isCanonicalAkshPod(out, opts) {
		// isCanonicalAkshPod deliberately excludes spec.hostPID (design contract,
		// to avoid circularity with the Validate hostPID gate). Repair hostPID to
		// the required value here so an already-canonical pod is returned
		// idempotently rather than falling through to a spurious conflict.
		out.Spec.HostPID = true
		return out, nil
	}
	if hasContainerNamed(out, akshContainerName) {
		return nil, AdmissionError{Field: "spec.containers[name=aksh]", Reason: "conflicts with required aksh sidecar"}
	}
	for _, volume := range canonicalVolumes(s.profile) {
		if existing, ok := findVolume(out, volume.Name); ok {
			if !volumeSourceEquivalent(existing.VolumeSource, volume.VolumeSource) {
				return nil, AdmissionError{Field: "spec.volumes[name=" + volume.Name + "]", Reason: "conflicts with required aksh volume"}
			}
			continue
		}
		out.Spec.Volumes = append(out.Spec.Volumes, volume)
	}
	out.Spec.HostPID = true
	if out.Spec.SecurityContext == nil {
		out.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	out.Spec.SecurityContext.FSGroup = ptr.To(reservedID)
	if out.Annotations == nil {
		out.Annotations = map[string]string{}
	}
	out.Annotations[injectionAnnotation] = s.injectionVersion
	out.Spec.Containers = append([]corev1.Container{s.canonicalContainer(out.Namespace)}, out.Spec.Containers...)
	return out, nil
}

func (s *SidecarInjector) options() InjectorOptions {
	return InjectorOptions{ProxyImage: s.proxyImage, ReservedUID: s.reservedUID, ReservedGID: s.reservedGID, OptInLabelKey: s.optInLabelKey, OptInLabelValue: s.optInLabelValue, InjectionVersion: s.injectionVersion, RuntimeProfile: s.profile}
}

func (s *SidecarInjector) canonicalContainer(namespace string) corev1.Container {
	return corev1.Container{
		Name: akshContainerName, Image: s.proxyImage, ImagePullPolicy: corev1.PullIfNotPresent,
		SecurityContext: &corev1.SecurityContext{RunAsUser: ptr.To(reservedID), RunAsGroup: ptr.To(reservedID), Capabilities: &corev1.Capabilities{Add: append([]corev1.Capability(nil), canonicalCapabilities...)}, AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}},
		Command:         []string{"/usr/local/bin/aksh-proxy"}, Env: canonicalEnv(namespace, s.profile), VolumeMounts: canonicalMounts(s.profile),
	}
}

// hostCgroupMount is the in-container path the proxy is told the host cgroup2
// root is bind-mounted at. It varies by node topology, so the profile may
// override the pure-cgroup-v2 default.
func hostCgroupMount(p RuntimeProfile) string {
	if v := strings.TrimSpace(p.HostCgroupMount); v != "" {
		return v
	}
	return "/host/sys/fs/cgroup"
}

func fieldRefEnv(name, fieldPath string) corev1.EnvVar {
	return corev1.EnvVar{Name: name, ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: fieldPath}}}
}

func canonicalEnv(namespace string, p RuntimeProfile) []corev1.EnvVar {
	env := []corev1.EnvVar{
		{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}},
	}
	// Pod attribution (downward API) for the audit record's pod/agent blocks so
	// replicas sharing a ServiceAccount stay distinguishable (ADR-S0-06). Ordered
	// immediately after POD_IP to match the production e2e oracle.
	if p.PodAttribution {
		env = append(env,
			fieldRefEnv("AKSH_POD_NAMESPACE", "metadata.namespace"),
			fieldRefEnv("AKSH_POD_NAME", "metadata.name"),
			fieldRefEnv("AKSH_POD_UID", "metadata.uid"),
			fieldRefEnv("AKSH_AGENT_SERVICE_ACCOUNT", "spec.serviceAccountName"),
		)
	}
	env = append(env,
		corev1.EnvVar{Name: "AKSH_POLICY_NAMESPACE", Value: namespace},
		corev1.EnvVar{Name: "AKSH_SA_TOKEN_PATH", Value: "/var/run/secrets/aksh/token"},
		corev1.EnvVar{Name: "AKSH_ENTRA_TENANT_ID", Value: p.EntraTenantID},
		corev1.EnvVar{Name: "AKSH_ENTRA_CLIENT_ID", Value: p.EntraClientID},
		corev1.EnvVar{Name: "AKSH_ENTRA_AUTHORITY", Value: p.EntraAuthority},
		corev1.EnvVar{Name: "AKSH_AUDIT_SINK", Value: "stdout"},
		corev1.EnvVar{Name: "AKSH_CA_PRIV_DIR", Value: "/var/lib/aksh/ca-priv"},
		corev1.EnvVar{Name: "AKSH_CA_PUB_DIR", Value: "/var/lib/aksh/ca-pub"},
		corev1.EnvVar{Name: "AKSH_CAPTURE_HOST_CGROUP_MOUNT", Value: hostCgroupMount(p)},
		corev1.EnvVar{Name: "AKSH_CAPTURE_MOUNT_BPFFS", Value: "true"},
		corev1.EnvVar{Name: "AKSH_CAPTURE_PROXY_UID", Value: "1774"},
		corev1.EnvVar{Name: "AKSH_CAPTURE_PROXY_GID", Value: "1774"},
		corev1.EnvVar{Name: "AKSH_CAPTURE_BLOCK_NON_TCP", Value: "true"},
		corev1.EnvVar{Name: "AKSH_CAPTURE_RUN_PROBE", Value: "true"},
		corev1.EnvVar{Name: "AKSH_POLICY_FIRST_SNAPSHOT_TIMEOUT", Value: "300s"},
	)
	// Optional, value-locked capture env: emitted only when configured so the
	// legacy profile's env set is byte-for-byte unchanged.
	if v := strings.TrimSpace(p.LocalCgroupMount); v != "" {
		env = append(env, corev1.EnvVar{Name: "AKSH_CAPTURE_LOCAL_CGROUP_MOUNT", Value: v})
	}
	if v := strings.TrimSpace(p.DNSServer); v != "" {
		env = append(env, corev1.EnvVar{Name: "AKSH_CAPTURE_DNS_SERVER", Value: v})
	}
	if v := strings.TrimSpace(p.BypassCIDRs); v != "" {
		env = append(env, corev1.EnvVar{Name: "AKSH_CAPTURE_BYPASS_CIDRS", Value: p.BypassCIDRs})
	}
	// Static bearer credential path: emitted only when a static token Secret is
	// configured. The value is a fixed, injector-owned path (not user-supplied),
	// so it is value-locked exactly by the canonical predicate.
	if strings.TrimSpace(p.StaticTokenSecretName) != "" {
		env = append(env, corev1.EnvVar{Name: staticTokenEnvVar, Value: staticTokenMountPath + "/" + staticTokenFileName})
	}
	return env
}

func canonicalVolumes(p RuntimeProfile) []corev1.Volume {
	caPriv := corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}
	caPub := corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}
	if name := strings.TrimSpace(p.CASecretName); name != "" {
		// A pre-provisioned per-pod CA: ca-priv projects the certificate and the
		// signing key (the two files the proxy reads from AKSH_CA_PRIV_DIR),
		// ca-pub only the public certificate. Paths match the proxy's expected
		// on-disk names (internal/pki caCertFile/privKeyFile).
		caPriv = corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: name, Items: []corev1.KeyToPath{
			{Key: p.CACertKey, Path: caCertFileName},
			{Key: p.CAPrivateKeyKey, Path: caKeyFileName},
		}}}
		caPub = corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: name, Items: []corev1.KeyToPath{
			{Key: p.CAPublicCertKey, Path: caCertFileName},
		}}}
	}
	volumes := []corev1.Volume{
		{Name: "hostcgroup", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/cgroup"}}},
		{Name: "ca-priv", VolumeSource: caPriv},
		{Name: "ca-pub", VolumeSource: caPub},
		{Name: "entra-token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", Audience: "api://AzureADTokenExchange", ExpirationSeconds: ptr.To[int64](3600)}}}}}},
		{Name: "upstream-ca", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "upstream-ca"}}}},
		// The pod's whole label map is obtainable only through a downwardAPI
		// volume (the env fieldRef form takes one named key at a time), and the
		// proxy needs it to evaluate AkshPolicy selectors (#35). The kubelet
		// rewrites this file when the pod's labels change.
		{Name: "podinfo", VolumeSource: corev1.VolumeSource{DownwardAPI: &corev1.DownwardAPIVolumeSource{Items: []corev1.DownwardAPIVolumeFile{
			{Path: "labels", FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.labels"}},
		}}}},
	}
	if name := strings.TrimSpace(p.StaticTokenSecretName); name != "" {
		// A pre-provisioned static bearer credential, projected read-only into
		// the aksh container only. The single Item maps the configured Secret key
		// to the fixed on-disk filename the proxy reads via AKSH_STATIC_TOKEN_PATH.
		volumes = append(volumes, corev1.Volume{Name: staticTokenVolumeName, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName: name,
			Items:      []corev1.KeyToPath{{Key: strings.TrimSpace(p.StaticTokenSecretKey), Path: staticTokenFileName}},
		}}})
	}
	return volumes
}

func canonicalMounts(p RuntimeProfile) []corev1.VolumeMount {
	mounts := []corev1.VolumeMount{{Name: "hostcgroup", MountPath: "/host/sys/fs/cgroup"}, {Name: "ca-priv", MountPath: "/var/lib/aksh/ca-priv"}, {Name: "ca-pub", MountPath: "/var/lib/aksh/ca-pub"}, {Name: "entra-token", MountPath: "/var/run/secrets/aksh", ReadOnly: true}, {Name: "upstream-ca", MountPath: "/etc/aksh/upstream-ca", ReadOnly: true}, {Name: "podinfo", MountPath: "/etc/aksh/podinfo", ReadOnly: true}}
	if strings.TrimSpace(p.StaticTokenSecretName) != "" {
		// Read-only, aksh-container-only. Never added to any app container mount
		// set, so the static bearer credential stays outside the workload.
		mounts = append(mounts, corev1.VolumeMount{Name: staticTokenVolumeName, MountPath: staticTokenMountPath, ReadOnly: true})
	}
	return mounts
}

func hasContainerNamed(pod *corev1.Pod, name string) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name == name {
			return true
		}
	}
	return false
}
func findVolume(pod *corev1.Pod, name string) (corev1.Volume, bool) {
	for _, v := range pod.Spec.Volumes {
		if v.Name == name {
			return v, true
		}
	}
	return corev1.Volume{}, false
}
