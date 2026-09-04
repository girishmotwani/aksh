package injector

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Validate deterministic INV-10 rejection reasons. Each distinct denial pairs a
// field-specific bounded reason so the admission response names the offending
// field. Reasons are intentionally short and free of request-derived content.
const (
	reasonAkshShape          = "must match canonical aksh sidecar shape"
	reasonHostNetwork        = "denied"
	reasonShareProcessNS     = "denied"
	reasonAutomount          = "denied"
	reasonIstio              = "istio coexistence denied"
	reasonReservedUID        = "must not use reserved uid 1774"
	reasonCapabilities       = "must not add privileged capabilities"
	reasonPrivEscalation     = "must not be true"
	reasonPrivileged         = "must not be true"
	reasonRunAsNonRoot       = "must not be false"
	reasonTokenLeakage       = "must not mount aksh service-account token"
	reasonCAPrivLeakage      = "must not mount ca-priv"
	reasonCAPubMutability    = "must be read-only"
	reasonHostCgroupLeakage  = "must not mount hostcgroup"
	reasonAkshCredVolume     = "must not mount upstream-ca"
	reasonStaticTokenLeakage = "must not mount aksh static bearer credential"
	reasonProtectedSecretVol = "must not reference an aksh-protected Secret via a volume"
	reasonProtectedSecretEnv = "must not reference an aksh-protected Secret via env"
	reasonVolumeSource       = "source drift from required aksh volume"
	reasonVolumeMissing      = "required aksh volume missing"
)

const (
	istioStatusAnnotation = "sidecar.istio.io/status"
	istioProxyContainer   = "istio-proxy"
	entraTokenAudience    = "api://AzureADTokenExchange"
)

// deniedNonAkshCapabilities are Linux capabilities that a non-aksh container may
// not add: the canonical aksh set plus SYS_PTRACE. Adding any of them lets a
// workload regain the interception/capture powers reserved for the sidecar.
var deniedNonAkshCapabilities = map[corev1.Capability]bool{
	"BPF": true, "NET_ADMIN": true, "NET_RAW": true, "SYS_ADMIN": true,
	"SYS_RESOURCE": true, "PERFMON": true, "SETUID": true, "SETGID": true,
	"SETPCAP": true, "SYS_PTRACE": true,
}

// Validate asserts INV-10 on the final admitted pod and returns the first
// deterministic AdmissionError. The traversal order is fixed: input sanity,
// canonical aksh shape (excluding hostPID and volume sources), pod-level
// host/namespace/automount, Istio coexistence, per-container reserved
// identity/capability/security rules, aksh credential mount leakage, and
// aksh-owned volume-source drift. Validate is read-only and never mutates pod.
func (s *SidecarInjector) Validate(pod *corev1.Pod) error {
	if pod == nil {
		return AdmissionError{Field: "pod", Reason: "required"}
	}
	if len(pod.Spec.Containers) == 0 {
		return AdmissionError{Field: "spec.containers", Reason: "required"}
	}
	opts := s.options()

	if !isCanonicalAkshShape(pod, opts) {
		return AdmissionError{Field: "spec.containers[name=aksh]", Reason: reasonAkshShape}
	}
	// HostPID note: the design INV-10 table lists a "Host PID abuse" rule
	// (hostPID:true on a non-canonical pod). The canonical-shape gate above
	// already denies every non-canonical pod first, so that case surfaces as
	// AkshContainerDenied (UT case 70), and a canonical pod with hostPID:true is
	// intentionally allowed (UT case 68). No separate hostPID branch is needed.

	if err := validatePodLevel(pod); err != nil {
		return err
	}
	if err := validateIstioCoexistence(pod); err != nil {
		return err
	}
	if err := validateContainerSecurity(pod); err != nil {
		return err
	}
	if err := validateMountLeakage(pod); err != nil {
		return err
	}
	if err := validateProtectedSecretContainment(pod, opts.RuntimeProfile); err != nil {
		return err
	}
	return validateVolumeSources(pod, opts.RuntimeProfile)
}

func validatePodLevel(pod *corev1.Pod) error {
	if pod.Spec.HostNetwork {
		return AdmissionError{Field: "spec.hostNetwork", Reason: reasonHostNetwork}
	}
	if pod.Spec.ShareProcessNamespace != nil && *pod.Spec.ShareProcessNamespace {
		return AdmissionError{Field: "spec.shareProcessNamespace", Reason: reasonShareProcessNS}
	}
	if pod.Spec.AutomountServiceAccountToken != nil && *pod.Spec.AutomountServiceAccountToken {
		return AdmissionError{Field: "spec.automountServiceAccountToken", Reason: reasonAutomount}
	}
	return nil
}

func validateIstioCoexistence(pod *corev1.Pod) error {
	if _, ok := pod.Annotations[istioStatusAnnotation]; ok {
		return AdmissionError{Field: "metadata.annotations[" + istioStatusAnnotation + "]", Reason: reasonIstio}
	}
	for _, c := range pod.Spec.Containers {
		if c.Name == istioProxyContainer {
			return AdmissionError{Field: "spec.containers[name=" + istioProxyContainer + "]", Reason: reasonIstio}
		}
	}
	return nil
}

// validateContainerSecurity enforces reserved-identity, capability, and
// hardening rules. runAsUser 1774 AND prohibited capabilities are denied on
// every non-aksh app, init, and ephemeral (debug) container -- init/ephemeral
// containers share the pod namespaces and are a capture-bypass surface, and the
// design Limitations #4 requires ephemeral UPDATE to deny UID 1774 or prohibited
// capabilities. The privilege/privileged/runAsNonRoot hardening rules apply to
// app containers per the design rejection table.
func validateContainerSecurity(pod *corev1.Pod) error {
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if c.Name == akshContainerName {
			continue
		}
		if err := validateAppContainerSecurity("spec.containers[name="+c.Name+"]", c.SecurityContext); err != nil {
			return err
		}
	}
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		if err := validateReservedIdentityAndCapabilities("spec.initContainers[name="+c.Name+"]", c.SecurityContext); err != nil {
			return err
		}
	}
	for i := range pod.Spec.EphemeralContainers {
		c := &pod.Spec.EphemeralContainers[i]
		if err := validateReservedIdentityAndCapabilities("spec.ephemeralContainers[name="+c.Name+"]", c.SecurityContext); err != nil {
			return err
		}
	}
	return nil
}

func validateReservedUID(field string, sc *corev1.SecurityContext) error {
	if sc != nil && sc.RunAsUser != nil && *sc.RunAsUser == reservedID {
		return AdmissionError{Field: field + ".securityContext.runAsUser", Reason: reasonReservedUID}
	}
	return nil
}

func validateDeniedCapabilities(field string, sc *corev1.SecurityContext) error {
	if sc == nil || sc.Capabilities == nil {
		return nil
	}
	for _, add := range sc.Capabilities.Add {
		if deniedNonAkshCapabilities[add] {
			return AdmissionError{Field: field + ".securityContext.capabilities.add", Reason: reasonCapabilities}
		}
	}
	return nil
}

func validateReservedIdentityAndCapabilities(field string, sc *corev1.SecurityContext) error {
	if err := validateReservedUID(field, sc); err != nil {
		return err
	}
	return validateDeniedCapabilities(field, sc)
}

func validateAppContainerSecurity(field string, sc *corev1.SecurityContext) error {
	if err := validateReservedUID(field, sc); err != nil {
		return err
	}
	if err := validateDeniedCapabilities(field, sc); err != nil {
		return err
	}
	if sc == nil {
		return nil
	}
	if sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
		return AdmissionError{Field: field + ".securityContext.allowPrivilegeEscalation", Reason: reasonPrivEscalation}
	}
	if sc.Privileged != nil && *sc.Privileged {
		return AdmissionError{Field: field + ".securityContext.privileged", Reason: reasonPrivileged}
	}
	if sc.RunAsNonRoot != nil && !*sc.RunAsNonRoot {
		return AdmissionError{Field: field + ".securityContext.runAsNonRoot", Reason: reasonRunAsNonRoot}
	}
	return nil
}

// validateMountLeakage denies non-aksh containers that mount aksh credential or
// host volumes: the entra token (or any aksh projected SA token), ca-priv,
// ca-pub read-write, hostcgroup, and upstream-ca. All three container lists are
// checked -- an init or ephemeral (debug) container can mount volumes too and
// must not be an exfiltration path for aksh credentials.
func validateMountLeakage(pod *corev1.Pod) error {
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if c.Name == akshContainerName {
			continue
		}
		if err := checkContainerMountLeakage(pod, "spec.containers[name="+c.Name+"]", c.VolumeMounts); err != nil {
			return err
		}
	}
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		if err := checkContainerMountLeakage(pod, "spec.initContainers[name="+c.Name+"]", c.VolumeMounts); err != nil {
			return err
		}
	}
	for i := range pod.Spec.EphemeralContainers {
		c := &pod.Spec.EphemeralContainers[i]
		if err := checkContainerMountLeakage(pod, "spec.ephemeralContainers[name="+c.Name+"]", c.VolumeMounts); err != nil {
			return err
		}
	}
	return nil
}

func checkContainerMountLeakage(pod *corev1.Pod, base string, mounts []corev1.VolumeMount) error {
	field := base + ".volumeMounts"
	for _, m := range mounts {
		switch {
		case m.Name == "entra-token" || isAkshProjectedToken(pod, m.Name):
			return AdmissionError{Field: field, Reason: reasonTokenLeakage}
		case m.Name == "ca-priv":
			return AdmissionError{Field: field, Reason: reasonCAPrivLeakage}
		case m.Name == "ca-pub" && !m.ReadOnly:
			return AdmissionError{Field: field + "[name=ca-pub].readOnly", Reason: reasonCAPubMutability}
		case m.Name == "hostcgroup":
			return AdmissionError{Field: field, Reason: reasonHostCgroupLeakage}
		case m.Name == "upstream-ca":
			return AdmissionError{Field: field, Reason: reasonAkshCredVolume}
		case m.Name == staticTokenVolumeName:
			return AdmissionError{Field: field, Reason: reasonStaticTokenLeakage}
		}
	}
	return nil
}

func isAkshProjectedToken(pod *corev1.Pod, volumeName string) bool {
	v, ok := findVolume(pod, volumeName)
	if !ok || v.Projected == nil {
		return false
	}
	for _, src := range v.Projected.Sources {
		if src.ServiceAccountToken != nil && src.ServiceAccountToken.Audience == entraTokenAudience {
			return true
		}
	}
	return false
}

// protectedSecretNames is the set of Secret names Aksh mounts into the sidecar
// and that must never be reachable by an application/init/ephemeral container:
// the per-pod CA Secret (private key + certificate) and the static bearer
// credential Secret. Both come from the operator-controlled RuntimeProfile; when
// a field is unset the corresponding Secret does not exist and is not protected.
func protectedSecretNames(profile RuntimeProfile) map[string]bool {
	names := map[string]bool{}
	if n := strings.TrimSpace(profile.CASecretName); n != "" {
		names[n] = true
	}
	if n := strings.TrimSpace(profile.StaticTokenSecretName); n != "" {
		names[n] = true
	}
	return names
}

// validateProtectedSecretContainment denies any non-aksh container that reaches
// a protected Secret by ANY mechanism other than the sanctioned canonical aksh
// volumes: an arbitrarily named Secret volume, a projected Secret source, an
// env.valueFrom.secretKeyRef, or an envFrom.secretRef. The canonical aksh
// volumes themselves (ca-priv/ca-pub/aksh-static-token) legitimately reference
// these Secrets and are governed separately by validateMountLeakage (mount
// rules) and validateVolumeSources (exact golden source), so they are skipped
// here by name. This closes the gap where the name-based mount-leakage check
// alone could be bypassed by referencing the Secret under a different volume
// name or through env, exfiltrating the CA private key or the bearer token.
func validateProtectedSecretContainment(pod *corev1.Pod, profile RuntimeProfile) error {
	protected := protectedSecretNames(profile)
	if len(protected) == 0 {
		return nil
	}
	// Canonical aksh volume names are locked to their golden Secret sources and
	// governed by the mount-leakage rules; exclude them so a legitimate
	// read-only ca-pub mount is not misread as an illicit reference.
	canonical := map[string]bool{}
	for _, v := range canonicalVolumes(profile) {
		canonical[v.Name] = true
	}

	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if c.Name == akshContainerName {
			continue
		}
		if err := checkContainerSecretContainment(pod, "spec.containers[name="+c.Name+"]", protected, canonical, c.VolumeMounts, c.Env, c.EnvFrom); err != nil {
			return err
		}
	}
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		if err := checkContainerSecretContainment(pod, "spec.initContainers[name="+c.Name+"]", protected, canonical, c.VolumeMounts, c.Env, c.EnvFrom); err != nil {
			return err
		}
	}
	for i := range pod.Spec.EphemeralContainers {
		c := &pod.Spec.EphemeralContainers[i]
		if err := checkContainerSecretContainment(pod, "spec.ephemeralContainers[name="+c.Name+"]", protected, canonical, c.VolumeMounts, c.Env, c.EnvFrom); err != nil {
			return err
		}
	}
	return nil
}

func checkContainerSecretContainment(pod *corev1.Pod, base string, protected, canonical map[string]bool, mounts []corev1.VolumeMount, env []corev1.EnvVar, envFrom []corev1.EnvFromSource) error {
	for _, e := range env {
		if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil && protected[e.ValueFrom.SecretKeyRef.Name] {
			return AdmissionError{Field: base + ".env[" + e.Name + "].valueFrom.secretKeyRef", Reason: reasonProtectedSecretEnv}
		}
	}
	for _, ef := range envFrom {
		if ef.SecretRef != nil && protected[ef.SecretRef.Name] {
			return AdmissionError{Field: base + ".envFrom.secretRef", Reason: reasonProtectedSecretEnv}
		}
	}
	for _, m := range mounts {
		if canonical[m.Name] {
			// Governed by validateMountLeakage + validateVolumeSources.
			continue
		}
		v, ok := findVolume(pod, m.Name)
		if !ok {
			continue
		}
		if volumeReferencesProtectedSecret(v, protected) {
			return AdmissionError{Field: base + ".volumeMounts[name=" + m.Name + "]", Reason: reasonProtectedSecretVol}
		}
	}
	return nil
}

// volumeReferencesProtectedSecret reports whether a volume's source reaches a
// protected Secret, either directly (secret volume) or via any projected Secret
// source. Projected sources are the subtle vector: a volume can look innocuous
// while smuggling a protected Secret in as one of several projections.
func volumeReferencesProtectedSecret(v corev1.Volume, protected map[string]bool) bool {
	if v.Secret != nil && protected[v.Secret.SecretName] {
		return true
	}
	if v.Projected != nil {
		for _, src := range v.Projected.Sources {
			if src.Secret != nil && protected[src.Secret.Name] {
				return true
			}
		}
	}
	return false
}

// validateVolumeSources denies an aksh-owned volume that is missing or whose
// source drifted from its golden definition. A protected final pod must carry
// every canonical aksh volume with its exact golden source.
func validateVolumeSources(pod *corev1.Pod, profile RuntimeProfile) error {
	for _, want := range canonicalVolumes(profile) {
		got, ok := findVolume(pod, want.Name)
		if !ok {
			return AdmissionError{Field: "spec.volumes[name=" + want.Name + "]", Reason: reasonVolumeMissing}
		}
		if !volumeSourceEquivalent(got.VolumeSource, want.VolumeSource) {
			return AdmissionError{Field: "spec.volumes[name=" + want.Name + "]", Reason: reasonVolumeSource}
		}
	}
	return nil
}
