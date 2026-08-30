package pki_test

import (
	"reflect"
	"testing"

	"github.com/girishmotwani/aksh/internal/pki"
)

// TestCAProvider_InterfaceExists verifies the S8 reconciled CA provider interface.
func TestCAProvider_InterfaceExists(t *testing.T) {
	iface := reflect.TypeOf((*pki.CAProvider)(nil)).Elem()
	if iface.Kind() != reflect.Interface {
		t.Fatal("CAProvider is not an interface")
	}
	for _, m := range []string{"Signer", "Generation", "PublicPEM"} {
		if _, ok := iface.MethodByName(m); !ok {
			t.Errorf("CAProvider missing %s method", m)
		}
	}
}
