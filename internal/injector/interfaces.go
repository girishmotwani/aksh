// Package injector defines the S5 admission webhook interface
// for sidecar injection and pod validation.
package injector

import corev1 "k8s.io/api/core/v1"

// Injector serves two admission webhook operations:
//   - Patch: mutating webhook — adds aksh-proxy, volumes, CA trust
//   - Validate: validating webhook — asserts INV-10 on the final admitted pod
//
// Two operations because the pod the validator judges is not the pod
// the mutator produced — other webhooks run in between.
type Injector interface {
	Patch(pod *corev1.Pod) (*corev1.Pod, error)
	Validate(pod *corev1.Pod) error
}
