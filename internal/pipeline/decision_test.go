package pipeline_test

import (
	"fmt"
	"testing"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

// TestDecision_ZeroValueIsInvalid verifies that a forgotten assignment
// cannot fail open — the zero value must be Invalid, not Allow.
func TestDecision_ZeroValueIsInvalid(t *testing.T) {
	var d pipeline.Decision
	if d.Disposition() != pipeline.DispositionInvalid {
		t.Fatalf("zero-value Decision disposition = %v, want Invalid", d.Disposition())
	}
}

// TestDecision_InvalidDenies verifies that an Invalid decision is not treated as Allow.
func TestDecision_InvalidDenies(t *testing.T) {
	var d pipeline.Decision
	if d.IsAllow() {
		t.Fatal("zero-value Decision.IsAllow() = true, want false")
	}
}

// TestDecision_AllValuesDistinct verifies the four dispositions are distinct.
func TestDecision_AllValuesDistinct(t *testing.T) {
	values := []pipeline.Disposition{
		pipeline.DispositionInvalid,
		pipeline.DispositionAllow,
		pipeline.DispositionDeny,
		pipeline.DispositionPending,
	}
	seen := make(map[pipeline.Disposition]bool)
	for _, v := range values {
		if seen[v] {
			t.Fatalf("duplicate disposition value: %v", v)
		}
		seen[v] = true
	}
	if len(seen) != 4 {
		t.Fatalf("expected 4 distinct dispositions, got %d", len(seen))
	}
}

// TestDecision_StringNotEmpty verifies that each disposition has a non-empty string representation.
func TestDecision_StringNotEmpty(t *testing.T) {
	for _, d := range []pipeline.Disposition{
		pipeline.DispositionInvalid,
		pipeline.DispositionAllow,
		pipeline.DispositionDeny,
		pipeline.DispositionPending,
	} {
		s := fmt.Sprintf("%v", d)
		if s == "" || s == fmt.Sprintf("%d", int(d)) {
			t.Errorf("Disposition(%d).String() = %q, want a named string", int(d), s)
		}
	}
}
