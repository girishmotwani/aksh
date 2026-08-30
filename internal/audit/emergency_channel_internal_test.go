package audit

import (
	"os"
	"reflect"
	"testing"
)

// #28
func TestNewEmergencyChannel_NilStderr_DefaultsToOsStderr(t *testing.T) {
	ec := NewEmergencyChannel(nil, nil, nil)
	if ec.stderr != os.Stderr {
		t.Fatalf("stderr = %v, want os.Stderr", ec.stderr)
	}
}

// #38 (structural half): the EmergencyChannel owns no policy-snapshot or
// token-cache state, so Recover cannot discard either — the guarantee holds
// by construction rather than by a runtime assertion.
func TestEmergencyChannel_HasNoPolicyOrTokenState(t *testing.T) {
	typ := reflect.TypeOf(EmergencyChannel{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		switch name {
		case "stderr", "metrics", "readiness", "mu", "ready", "transitions":
			// expected minimal signalling state only
		default:
			t.Fatalf("unexpected EmergencyChannel field %q — Recover must not own snapshot/cache state", name)
		}
	}
}
