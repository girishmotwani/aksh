package injector

import (
	"reflect"

	corev1 "k8s.io/api/core/v1"
)

func isCanonicalAkshPod(pod *corev1.Pod, opts InjectorOptions) bool {
	return isCanonicalAkshShape(pod, opts) && canonicalVolumeSourcesPresent(pod, opts.RuntimeProfile)
}

// isCanonicalAkshShape is the canonical contract for everything except the
// aksh-owned volume sources (marker, pod fsGroup, aksh container cardinality/
// image/command/identity/capabilities/env, and aksh mount shape). It
// deliberately excludes spec.hostPID and the volume sources so Validate can gate
// on sidecar shape first and still report volume-source drift as its own
// distinct denial rather than a generic shape rejection.
func isCanonicalAkshShape(pod *corev1.Pod, opts InjectorOptions) bool {
	if pod == nil || pod.Annotations[injectionAnnotation] == "" || pod.Annotations[injectionAnnotation] != opts.InjectionVersion {
		return false
	}
	if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.FSGroup == nil || *pod.Spec.SecurityContext.FSGroup != reservedID {
		return false
	}
	var aksh *corev1.Container
	if len(pod.Spec.Containers) == 0 || pod.Spec.Containers[0].Name != akshContainerName {
		return false
	}
	aksh = &pod.Spec.Containers[0]
	for i := 1; i < len(pod.Spec.Containers); i++ {
		if pod.Spec.Containers[i].Name == akshContainerName {
			return false
		}
	}
	if aksh.Image != opts.ProxyImage || !reflect.DeepEqual(aksh.Command, []string{"/usr/local/bin/aksh-proxy"}) || len(aksh.Args) != 0 {
		return false
	}
	if aksh.SecurityContext == nil || aksh.SecurityContext.RunAsUser == nil || *aksh.SecurityContext.RunAsUser != reservedID || aksh.SecurityContext.RunAsGroup == nil || *aksh.SecurityContext.RunAsGroup != reservedID {
		return false
	}
	if aksh.SecurityContext.Capabilities == nil || !capabilitySetEqual(aksh.SecurityContext.Capabilities.Add, canonicalCapabilities) {
		return false
	}
	if !canonicalEnvPresent(aksh.Env, pod.Namespace, opts.RuntimeProfile) {
		return false
	}
	return canonicalMountsPresent(aksh.VolumeMounts, opts.RuntimeProfile)
}

// canonicalVolumeSourcesPresent reports whether every aksh-owned volume exists
// with its golden source.
func canonicalVolumeSourcesPresent(pod *corev1.Pod, profile RuntimeProfile) bool {
	for _, want := range canonicalVolumes(profile) {
		got, ok := findVolume(pod, want.Name)
		if !ok || !volumeSourceEquivalent(got.VolumeSource, want.VolumeSource) {
			return false
		}
	}
	return true
}

// volumeSourceEquivalent compares an actual volume source against a canonical
// aksh volume source while tolerating the cosmetic fields the Kubernetes API
// server defaults AFTER the mutating webhook returns its patch -- specifically
// hostPath.type (nil is defaulted to the empty HostPathType "") and the
// configMap/projected/emptyDir defaultMode. Every security-relevant field
// (hostPath.Path, configMap.Name/Items/Optional, the projected sources,
// emptyDir.Medium) is still compared exactly, so a workload cannot swap an
// aksh volume for a different source. Without this tolerance a plain
// reflect.DeepEqual makes the validating webhook reject every pod the mutating
// webhook just produced (nil vs "" hostPath.type), which is invisible to the
// in-memory unit tests but denies all injection on a real cluster.
func volumeSourceEquivalent(got, want corev1.VolumeSource) bool {
	switch {
	case want.HostPath != nil:
		if got.HostPath == nil || got.HostPath.Path != want.HostPath.Path {
			return false
		}
		return hostPathTypeEquivalent(got.HostPath.Type, want.HostPath.Type)
	case want.EmptyDir != nil:
		return got.EmptyDir != nil && got.EmptyDir.Medium == want.EmptyDir.Medium &&
			reflect.DeepEqual(got.EmptyDir.SizeLimit, want.EmptyDir.SizeLimit)
	case want.ConfigMap != nil:
		if got.ConfigMap == nil || got.ConfigMap.Name != want.ConfigMap.Name {
			return false
		}
		return reflect.DeepEqual(got.ConfigMap.Items, want.ConfigMap.Items) &&
			reflect.DeepEqual(got.ConfigMap.Optional, want.ConfigMap.Optional)
	case want.Secret != nil:
		// SecretName and Items (which Secret keys map to which files) carry the
		// security-relevant content and are compared exactly. defaultMode is
		// defaulted by the API server to 0644 AFTER the mutating webhook returns,
		// so it must not be compared -- otherwise the validating webhook would
		// reject every Secret-backed CA pod the mutating webhook just produced.
		// Optional is not API-defaulted and is compared exactly.
		if got.Secret == nil || got.Secret.SecretName != want.Secret.SecretName {
			return false
		}
		return reflect.DeepEqual(got.Secret.Items, want.Secret.Items) &&
			reflect.DeepEqual(got.Secret.Optional, want.Secret.Optional)
	case want.Projected != nil:
		return got.Projected != nil && reflect.DeepEqual(got.Projected.Sources, want.Projected.Sources)
	case want.DownwardAPI != nil:
		// Items carry the security-relevant content (which pod fields are
		// exposed and at what path); defaultMode is defaulted by the API server
		// after the mutating webhook returns and must not be compared.
		return got.DownwardAPI != nil && reflect.DeepEqual(got.DownwardAPI.Items, want.DownwardAPI.Items)
	default:
		return reflect.DeepEqual(got, want)
	}
}

// hostPathTypeEquivalent treats a nil *HostPathType and a pointer to the empty
// HostPathType ("") as equal: the API server defaults an unset hostPath.type to
// "" (HostPathUnset), so the injected nil and the persisted "" denote the same
// "no type check" semantics.
func hostPathTypeEquivalent(got, want *corev1.HostPathType) bool {
	norm := func(t *corev1.HostPathType) corev1.HostPathType {
		if t == nil {
			return ""
		}
		return *t
	}
	return norm(got) == norm(want)
}

func capabilitySetEqual(got, want []corev1.Capability) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[corev1.Capability]bool{}
	for _, c := range got {
		seen[c] = true
	}
	for _, c := range want {
		if !seen[c] {
			return false
		}
	}
	return true
}

// configSourcedEnv names carry deployment/config- or node-topology-sourced
// values. In the LEGACY (unset-profile) case the canonical predicate checks
// presence only, not value:
//   - AKSH_ENTRA_* come "from injector/config source" (design §Patch flow); the
//     e2e golden oracle (test/e2e/manifests/50-aksh-pod.yaml) carries real Entra
//     values while a legacy injector emits placeholders. Both are canonical in
//     shape.
//   - AKSH_CAPTURE_HOST_CGROUP_MOUNT names where the host cgroup2 root is bind-
//     mounted, which is a per-node topology detail: pure cgroup-v2 nodes (AKS,
//     production) use "/host/sys/fs/cgroup" while a hybrid-cgroup kind node uses
//     the "/unified" subtree. The host-path volume ("hostcgroup" -> /sys/fs/cgroup)
//     stays value-locked; only the in-mount subpath varies by node.
//
// When the runtime profile SETS the corresponding field, the value stops being
// config-sourced and is compared exactly (value-locked) by presenceOnlyEnv, so
// a tampered Entra/cgroup value is rejected. Value-comparing an UNSET field
// would spuriously reject correctly-injected pods across environments and break
// idempotency.
var configSourcedEnv = map[string]bool{
	"AKSH_ENTRA_TENANT_ID":           true,
	"AKSH_ENTRA_CLIENT_ID":           true,
	"AKSH_ENTRA_AUTHORITY":           true,
	"AKSH_CAPTURE_HOST_CGROUP_MOUNT": true,
}

// presenceOnlyEnv reports whether a config-sourced env var is checked for
// presence only for the given profile. A config-sourced name is presence-only
// exactly when the profile leaves its field unset (the legacy placeholder);
// once the operator configures it, the canonical predicate value-locks it.
func presenceOnlyEnv(name string, p RuntimeProfile) bool {
	if !configSourcedEnv[name] {
		return false
	}
	switch name {
	case "AKSH_ENTRA_TENANT_ID":
		return p.EntraTenantID == ""
	case "AKSH_ENTRA_CLIENT_ID":
		return p.EntraClientID == ""
	case "AKSH_ENTRA_AUTHORITY":
		return p.EntraAuthority == ""
	case "AKSH_CAPTURE_HOST_CGROUP_MOUNT":
		return p.HostCgroupMount == ""
	}
	return true
}

func canonicalEnvPresent(got []corev1.EnvVar, namespace string, profile RuntimeProfile) bool {
	env := map[string]corev1.EnvVar{}
	for _, e := range got {
		env[e.Name] = e
	}
	if _, ok := env["AKSH_CAPTURE_POD_PATH"]; ok {
		return false
	}
	if _, ok := env["SSL_CERT_FILE"]; ok {
		return false
	}
	for _, want := range canonicalEnv(namespace, profile) {
		got, ok := env[want.Name]
		if !ok {
			return false
		}
		if presenceOnlyEnv(want.Name, profile) {
			continue
		}
		if want.ValueFrom != nil {
			if got.ValueFrom == nil || got.ValueFrom.FieldRef == nil || want.ValueFrom.FieldRef == nil || got.ValueFrom.FieldRef.FieldPath != want.ValueFrom.FieldRef.FieldPath {
				return false
			}
			continue
		}
		if got.Value != want.Value {
			return false
		}
	}
	return true
}

func canonicalMountsPresent(got []corev1.VolumeMount, profile RuntimeProfile) bool {
	mounts := map[string]corev1.VolumeMount{}
	for _, m := range got {
		mounts[m.Name] = m
	}
	for _, want := range canonicalMounts(profile) {
		got, ok := mounts[want.Name]
		if !ok || got.MountPath != want.MountPath || got.ReadOnly != want.ReadOnly {
			return false
		}
	}
	return true
}
