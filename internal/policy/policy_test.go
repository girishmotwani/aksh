package policy_test

import (
	"reflect"
	"testing"

	"github.com/girishmotwani/aksh/internal/policy"
)

// TestInterfaces_Exist verifies that the S2 interfaces are defined.
func TestInterfaces_Exist(t *testing.T) {
	tests := []struct {
		name    string
		iface   reflect.Type
		methods []string
	}{
		{
			name:    "PolicyStore",
			iface:   reflect.TypeOf((*policy.PolicyStore)(nil)).Elem(),
			methods: []string{"Current"},
		},
		{
			name:    "PolicySnapshot",
			iface:   reflect.TypeOf((*policy.PolicySnapshot)(nil)).Elem(),
			methods: []string{"Version", "Rules"},
		},
		{
			name:    "Matcher",
			iface:   reflect.TypeOf((*policy.Matcher)(nil)).Elem(),
			methods: []string{"Match"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.iface.Kind() != reflect.Interface {
				t.Fatalf("%s is not an interface", tt.name)
			}
			for _, m := range tt.methods {
				if _, ok := tt.iface.MethodByName(m); !ok {
					t.Errorf("%s missing method %s", tt.name, m)
				}
			}
		})
	}
}

// TestRequestFacts_HasRequiredFields verifies the canonical request view.
func TestRequestFacts_HasRequiredFields(t *testing.T) {
	typ := reflect.TypeOf(policy.RequestFacts{})
	for _, name := range []string{"Identity", "Method", "Path", "Port", "Transport"} {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("RequestFacts missing field %s", name)
		}
	}
}

// TestMatchResult_HasRequiredFields verifies the policy match output.
func TestMatchResult_HasRequiredFields(t *testing.T) {
	typ := reflect.TypeOf(policy.MatchResult{})
	for _, name := range []string{"Matched", "PolicyRef", "Version", "Credential", "Ambiguous"} {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("MatchResult missing field %s", name)
		}
	}
}
