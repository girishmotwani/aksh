package watch

import (
	"errors"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestNewDynamicAkshPolicyClient_EmptyNamespace_ReturnsError proves the
// fail-closed guard: a dynamic client must never be constructed with an empty
// namespace (which would read akshpolicies cluster-wide). The guard rejects
// before touching the dynamic client, so a nil client exercises the error path.
func TestNewDynamicAkshPolicyClient_EmptyNamespace_ReturnsError(t *testing.T) {
	if _, err := NewDynamicAkshPolicyClient(nil, ""); !errors.Is(err, ErrEmptyNamespace) {
		t.Fatalf("NewDynamicAkshPolicyClient(nil, \"\") err = %v, want ErrEmptyNamespace", err)
	}
}

// TestNewDynamicAkshPolicyClient_NilClient_ReturnsError proves the constructor
// rejects a nil dynamic client instead of returning an adapter that panics on
// first use. The namespace guard runs first (so (nil, "") is ErrEmptyNamespace);
// a valid namespace with a nil client must surface ErrNilClient.
func TestNewDynamicAkshPolicyClient_NilClient_ReturnsError(t *testing.T) {
	if _, err := NewDynamicAkshPolicyClient(nil, "aksh-system"); !errors.Is(err, ErrNilClient) {
		t.Fatalf("NewDynamicAkshPolicyClient(nil, ns) err = %v, want ErrNilClient", err)
	}
}

// TestUnstructuredToPolicy_ConvertsSpecFields verifies the dynamic-client
// adapter's conversion preserves namespace, name, and egress rule fields.
func TestUnstructuredToPolicy_ConvertsSpecFields(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aksh.dev/v1alpha1",
		"kind":       "AkshPolicy",
		"metadata": map[string]any{
			"name":      "p1",
			"namespace": "app-ns",
		},
		"spec": map[string]any{
			"egress": map[string]any{
				"rules": []any{
					map[string]any{
						"name": "r1",
						"to":   map[string]any{"host": "example.com"},
					},
				},
			},
		},
	}}

	p, err := unstructuredToPolicy(u)
	if err != nil {
		t.Fatalf("unstructuredToPolicy: %v", err)
	}
	if p.Name != "p1" || p.Namespace != "app-ns" {
		t.Fatalf("metadata = %q/%q, want app-ns/p1", p.Namespace, p.Name)
	}
	if len(p.Spec.Egress.Rules) != 1 || p.Spec.Egress.Rules[0].To.Host != "example.com" {
		t.Fatalf("egress rules = %+v, want one rule to example.com", p.Spec.Egress.Rules)
	}
}
