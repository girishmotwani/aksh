package pipeline_test

import (
	"reflect"
	"testing"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

// TestAuditEvent_HasNoTokenField verifies that AuditEvent does not carry
// a Token field. S4 §2: after injection the RequestContext holds the
// plaintext credential, so AuditEvent is built from a snapshot — passing
// the context to a sink would create a leak path.
func TestAuditEvent_HasNoTokenField(t *testing.T) {
	typ := reflect.TypeOf(pipeline.AuditEvent{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if name == "Token" || name == "token" || name == "Secret" || name == "secret" {
			t.Fatalf("AuditEvent must not have a %q field — leak path to audit sink", name)
		}
	}
}

// TestRequestContext_HasIdentityInput verifies the pipeline carries
// untrusted input separately from validated facts.
func TestRequestContext_HasIdentityInput(t *testing.T) {
	typ := reflect.TypeOf(pipeline.RequestContext{})
	if _, ok := typ.FieldByName("Identity"); !ok {
		t.Fatal("RequestContext missing Identity (IdentityInput) field")
	}
	if _, ok := typ.FieldByName("Facts"); !ok {
		t.Fatal("RequestContext missing Facts (RequestFacts) field")
	}
}

// TestFaultClass_AllValuesHaveNames verifies every FaultClass has a string.
func TestFaultClass_AllValuesHaveNames(t *testing.T) {
	classes := []pipeline.FaultClass{
		pipeline.FaultClassNone,
		pipeline.FaultClassTransient,
		pipeline.FaultClassPermanent,
		pipeline.FaultClassLocal,
	}
	for _, c := range classes {
		if c.String() == "" {
			t.Errorf("FaultClass(%d).String() is empty", int(c))
		}
	}
}
