package injector

import (
	"reflect"
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
	return &SidecarInjector{proxyImage: opts.ProxyImage, reservedUID: opts.ReservedUID, reservedGID: opts.ReservedGID, optInLabelKey: opts.OptInLabelKey, optInLabelValue: opts.OptInLabelValue, injectionVersion: opts.InjectionVersion}, nil
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
	for _, volume := range canonicalVolumes() {
		if existing, ok := findVolume(out, volume.Name); ok {
			if !reflect.DeepEqual(existing.VolumeSource, volume.VolumeSource) {
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
	return InjectorOptions{ProxyImage: s.proxyImage, ReservedUID: s.reservedUID, ReservedGID: s.reservedGID, OptInLabelKey: s.optInLabelKey, OptInLabelValue: s.optInLabelValue, InjectionVersion: s.injectionVersion}
}

func (s *SidecarInjector) canonicalContainer(namespace string) corev1.Container {
	return corev1.Container{
		Name: akshContainerName, Image: s.proxyImage, ImagePullPolicy: corev1.PullIfNotPresent,
		SecurityContext: &corev1.SecurityContext{RunAsUser: ptr.To(reservedID), RunAsGroup: ptr.To(reservedID), Capabilities: &corev1.Capabilities{Add: append([]corev1.Capability(nil), canonicalCapabilities...)}, AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined}},
		Command:         []string{"/usr/local/bin/aksh-proxy"}, Env: canonicalEnv(namespace), VolumeMounts: canonicalMounts(),
	}
}

func canonicalEnv(namespace string) []corev1.EnvVar {
	return []corev1.EnvVar{
		{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"}}},
		{Name: "AKSH_POLICY_NAMESPACE", Value: namespace},
		{Name: "AKSH_SA_TOKEN_PATH", Value: "/var/run/secrets/aksh/token"},
		{Name: "AKSH_ENTRA_TENANT_ID", Value: ""},
		{Name: "AKSH_ENTRA_CLIENT_ID", Value: ""},
		{Name: "AKSH_ENTRA_AUTHORITY", Value: ""},
		{Name: "AKSH_AUDIT_SINK", Value: "stdout"},
		{Name: "AKSH_CA_PRIV_DIR", Value: "/var/lib/aksh/ca-priv"},
		{Name: "AKSH_CA_PUB_DIR", Value: "/var/lib/aksh/ca-pub"},
		{Name: "AKSH_CAPTURE_HOST_CGROUP_MOUNT", Value: "/host/sys/fs/cgroup"},
		{Name: "AKSH_CAPTURE_MOUNT_BPFFS", Value: "true"},
		{Name: "AKSH_CAPTURE_PROXY_UID", Value: "1774"},
		{Name: "AKSH_CAPTURE_PROXY_GID", Value: "1774"},
		{Name: "AKSH_CAPTURE_BLOCK_NON_TCP", Value: "true"},
		{Name: "AKSH_CAPTURE_RUN_PROBE", Value: "true"},
		{Name: "AKSH_POLICY_FIRST_SNAPSHOT_TIMEOUT", Value: "300s"},
	}
}

func canonicalVolumes() []corev1.Volume {
	return []corev1.Volume{
		{Name: "hostcgroup", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/cgroup"}}},
		{Name: "ca-priv", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "ca-pub", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
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
}

func canonicalMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{{Name: "hostcgroup", MountPath: "/host/sys/fs/cgroup"}, {Name: "ca-priv", MountPath: "/var/lib/aksh/ca-priv"}, {Name: "ca-pub", MountPath: "/var/lib/aksh/ca-pub"}, {Name: "entra-token", MountPath: "/var/run/secrets/aksh", ReadOnly: true}, {Name: "upstream-ca", MountPath: "/etc/aksh/upstream-ca", ReadOnly: true}, {Name: "podinfo", MountPath: "/etc/aksh/podinfo", ReadOnly: true}}
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
