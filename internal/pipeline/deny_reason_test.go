package pipeline_test

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/pipeline"
)

// TestDenyReason_AllValuesHaveNames verifies every DenyReason has a meaningful string.
func TestDenyReason_AllValuesHaveNames(t *testing.T) {
	reasons := []pipeline.DenyReason{
		pipeline.DenyReasonNoMatch,
		pipeline.DenyReasonPolicyCacheEmpty,
		pipeline.DenyReasonPolicyCacheStale,
		pipeline.DenyReasonTokenAcquisitionFailed,
		pipeline.DenyReasonAuditFailed,
		pipeline.DenyReasonIdentityMismatch,
		pipeline.DenyReasonUnsupportedProtocol,
		pipeline.DenyReasonNoSNI,
		pipeline.ReasonResourceLimit,
		pipeline.ReasonPodLocalDestination,
		pipeline.ReasonNoOriginalDst,
	}
	for _, r := range reasons {
		s := r.String()
		if s == "" {
			t.Errorf("DenyReason(%d).String() is empty", int(r))
		}
	}
}

func TestDenyReason_NewReasonsHaveExpectedStrings(t *testing.T) {
	if got := pipeline.ReasonResourceLimit.String(); got != "resource_limit" {
		t.Fatalf("ReasonResourceLimit.String() = %q, want %q", got, "resource_limit")
	}
	if got := pipeline.ReasonPodLocalDestination.String(); got != "destination_pod_local" {
		t.Fatalf("ReasonPodLocalDestination.String() = %q, want %q", got, "destination_pod_local")
	}
}

// Test #110: pipeline.ReasonNoOriginalDst.String() returns the bounded
// closed-enum label "no_original_dst" (never a free string).
func TestReasonNoOriginalDst_String_ReturnsNoOriginalDst(t *testing.T) {
	if got := pipeline.ReasonNoOriginalDst.String(); got != "no_original_dst" {
		t.Fatalf("ReasonNoOriginalDst.String() = %q, want %q", got, "no_original_dst")
	}
}

// Test #111: ReasonNoOriginalDst is ordinal-appended immediately after
// ReasonMissingClientHello (the previous last real value); existing ordinals
// are unshifted (ordinal-stability).
func TestReasonNoOriginalDst_Ordinal_AppendedWithoutShiftingExisting(t *testing.T) {
	if got, want := pipeline.ReasonNoOriginalDst, pipeline.ReasonMissingClientHello+1; got != want {
		t.Fatalf("ReasonNoOriginalDst ordinal = %d, want %d (appended after ReasonMissingClientHello)", int(got), int(want))
	}
	// Ordinal-stability: a pre-existing value must keep its ordinal.
	if int(pipeline.ReasonMissingClientHello) != int(pipeline.ReasonLoopGuard)+1 {
		t.Fatalf("ReasonMissingClientHello ordinal shifted: got %d, want %d", int(pipeline.ReasonMissingClientHello), int(pipeline.ReasonLoopGuard)+1)
	}
}
