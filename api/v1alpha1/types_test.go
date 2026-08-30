package v1alpha1_test

import (
	"reflect"
	"testing"

	v1alpha1 "github.com/girishmotwani/aksh/api/v1alpha1"
)

// TestAkshPolicy_SpecHasEgressEnvelope verifies that the Spec struct
// contains an Egress field. S0 makes this a normative requirement:
// without it, adding spec.ingress later forces a breaking migration.
func TestAkshPolicy_SpecHasEgressEnvelope(t *testing.T) {
	specType := reflect.TypeOf(v1alpha1.AkshPolicySpec{})
	field, ok := specType.FieldByName("Egress")
	if !ok {
		t.Fatal("AkshPolicySpec has no Egress field — v1 forward-compat requires spec.egress envelope")
	}
	if field.Type.Kind() != reflect.Struct {
		t.Fatalf("Egress field kind = %v, want struct", field.Type.Kind())
	}
}

// TestAkshPolicy_HasRequiredMetadata verifies that AkshPolicy carries
// the standard Kubernetes TypeMeta and ObjectMeta fields.
func TestAkshPolicy_HasRequiredMetadata(t *testing.T) {
	policyType := reflect.TypeOf(v1alpha1.AkshPolicy{})
	for _, name := range []string{"TypeMeta", "ObjectMeta"} {
		if _, ok := policyType.FieldByName(name); !ok {
			t.Errorf("AkshPolicy missing embedded %s", name)
		}
	}
}

// --- Phase 2: Full CRD schema tests ---

// TestEgressRule_HasAllFields verifies the full EgressRule schema per S2 §2.
func TestEgressRule_HasAllFields(t *testing.T) {
	typ := reflect.TypeOf(v1alpha1.EgressRule{})
	for _, name := range []string{"Name", "To", "Match", "AllowPlaintext", "Credential", "Constraints"} {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("EgressRule missing field %s", name)
		}
	}
}

// TestPathMatcher_HasTypeAndValue verifies the PathMatcher structure.
func TestPathMatcher_HasTypeAndValue(t *testing.T) {
	typ := reflect.TypeOf(v1alpha1.PathMatcher{})
	for _, name := range []string{"Type", "Value"} {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("PathMatcher missing field %s", name)
		}
	}
}

// TestCredentialSelector_HasFields verifies CredentialSelector per ADR-S2-06.
func TestCredentialSelector_HasFields(t *testing.T) {
	typ := reflect.TypeOf(v1alpha1.CredentialSelector{})
	for _, name := range []string{"Provider", "Resource", "Scopes"} {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("CredentialSelector missing field %s", name)
		}
	}
}

// TestEgressRule_ConstraintsFieldExists verifies the constraints placeholder
// exists as a slice (§4 discrimination — maxItems:0 guard).
func TestEgressRule_ConstraintsFieldExists(t *testing.T) {
	typ := reflect.TypeOf(v1alpha1.EgressRule{})
	f, ok := typ.FieldByName("Constraints")
	if !ok {
		t.Fatal("EgressRule missing Constraints field — §4 forward-compat requires it")
	}
	if f.Type.Kind() != reflect.Slice {
		t.Errorf("Constraints kind = %v, want slice", f.Type.Kind())
	}
}

// TestEgressRule_EffectFieldExists verifies the effect discriminator placeholder
// exists (§4.1 — prevents silent pruning of future deny verb).
func TestEgressRule_EffectFieldExists(t *testing.T) {
	typ := reflect.TypeOf(v1alpha1.EgressRule{})
	if _, ok := typ.FieldByName("Effect"); !ok {
		t.Fatal("EgressRule missing Effect field — §4.1 forward-compat requires it")
	}
}

// TestAkshPolicySpec_SelectorRequired verifies Selector is a pointer (optional
// in Go) but its presence is enforced by CEL at apply time. Here we just
// confirm the field exists.
func TestAkshPolicySpec_SelectorRequired(t *testing.T) {
	typ := reflect.TypeOf(v1alpha1.AkshPolicySpec{})
	f, ok := typ.FieldByName("Selector")
	if !ok {
		t.Fatal("AkshPolicySpec missing Selector field")
	}
	if f.Type.Kind() != reflect.Pointer {
		t.Errorf("Selector should be a pointer (for k8s LabelSelector); got %v", f.Type.Kind())
	}
}
