package injector_test

import (
	"reflect"
	"testing"

	"github.com/girishmotwani/aksh/internal/injector"
)

// TestInjector_InterfaceExists verifies the S5 injector interface.
func TestInjector_InterfaceExists(t *testing.T) {
	iface := reflect.TypeOf((*injector.Injector)(nil)).Elem()
	if iface.Kind() != reflect.Interface {
		t.Fatal("Injector is not an interface")
	}
	for _, m := range []string{"Patch", "Validate"} {
		if _, ok := iface.MethodByName(m); !ok {
			t.Errorf("Injector missing %s method", m)
		}
	}
}
