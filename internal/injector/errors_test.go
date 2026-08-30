package injector

import "testing"

func TestError_FieldAndReason_ReturnsBoundedFieldColonReasonMessage(t *testing.T) {
	if got := (AdmissionError{Field: "spec.containers", Reason: "required"}).Error(); got != "spec.containers: required" {
		t.Fatalf("Error()=%q", got)
	}
}

func TestError_FieldOrReasonZeroValue_ReturnsDeterministicMessage(t *testing.T) {
	if got := (AdmissionError{Field: "", Reason: "required"}).Error(); got != ": required" {
		t.Fatalf("Error()=%q", got)
	}
	if got := (AdmissionError{Field: "pod", Reason: ""}).Error(); got != "pod: " {
		t.Fatalf("Error()=%q", got)
	}
}
