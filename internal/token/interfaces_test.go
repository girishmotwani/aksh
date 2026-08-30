package token_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/girishmotwani/aksh/internal/token"
)

// TestTokenProvider_InterfaceExists verifies the S3 provider interface.
func TestTokenProvider_InterfaceExists(t *testing.T) {
	iface := reflect.TypeOf((*token.TokenProvider)(nil)).Elem()
	if iface.Kind() != reflect.Interface {
		t.Fatal("TokenProvider is not an interface")
	}
	if _, ok := iface.MethodByName("Acquire"); !ok {
		t.Error("TokenProvider missing Acquire method")
	}
}

// TestTokenCache_InterfaceExists verifies the S3 cache interface.
func TestTokenCache_InterfaceExists(t *testing.T) {
	iface := reflect.TypeOf((*token.TokenCache)(nil)).Elem()
	if iface.Kind() != reflect.Interface {
		t.Fatal("TokenCache is not an interface")
	}
	for _, m := range []string{"Get", "Put"} {
		if _, ok := iface.MethodByName(m); !ok {
			t.Errorf("TokenCache missing %s method", m)
		}
	}
}

// TestAcquireErrorClass_AllValuesHaveNames verifies the classification enum.
func TestAcquireErrorClass_AllValuesHaveNames(t *testing.T) {
	classes := []token.AcquireErrorClass{
		token.AcquireErrorTransient,
		token.AcquireErrorPermanent,
		token.AcquireErrorLocal,
	}
	for _, c := range classes {
		if c.String() == "" {
			t.Errorf("AcquireErrorClass(%d).String() is empty", int(c))
		}
	}
}

// TestAcquireError_ErrorDoesNotRenderCause verifies that Error() never
// concatenates the wrapped Cause's text, since Cause may carry secret
// or request material from the IdP HTTP layer (INV-5). Cause must
// remain reachable only via Unwrap() for errors.Is/errors.As.
func TestAcquireError_ErrorDoesNotRenderCause(t *testing.T) {
	secretCause := errors.New("token=SUPER-SECRET-ABC123")
	err := &token.AcquireError{
		Class:   token.AcquireErrorTransient,
		Message: "idp request failed",
		Cause:   secretCause,
	}

	msg := err.Error()
	if strings.Contains(msg, "SUPER-SECRET-ABC123") {
		t.Errorf("Error() leaked the cause text: %s", msg)
	}
	if !errors.Is(err, secretCause) {
		t.Error("errors.Is(err, secretCause) = false, want true (Cause must remain reachable via Unwrap)")
	}
}
