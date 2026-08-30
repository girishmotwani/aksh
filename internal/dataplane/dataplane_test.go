package dataplane_test

import (
	"reflect"
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane"
)

// TestInterfaces_Exist verifies that the S1 interfaces are defined
// and have the expected methods.
func TestInterfaces_Exist(t *testing.T) {
	tests := []struct {
		name    string
		iface   reflect.Type
		methods []string
	}{
		{
			name:    "DestinationResolver",
			iface:   reflect.TypeOf((*dataplane.DestinationResolver)(nil)).Elem(),
			methods: []string{"Resolve"},
		},
		{
			name:    "LeafSource",
			iface:   reflect.TypeOf((*dataplane.LeafSource)(nil)).Elem(),
			methods: []string{"CertificateFor"},
		},
		{
			name:    "UpstreamDialer",
			iface:   reflect.TypeOf((*dataplane.UpstreamDialer)(nil)).Elem(),
			methods: []string{"DialUpstream"},
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
