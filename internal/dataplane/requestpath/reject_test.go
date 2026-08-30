package requestpath_test

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/dataplane/requestpath"
	"github.com/girishmotwani/aksh/internal/pipeline"
)

func TestRejectClass_ConstantsExposeT1ThroughT9Literals(t *testing.T) {
	tests := []struct {
		name string
		got  requestpath.RejectClass
		want requestpath.RejectClass
	}{
		{name: "T1", got: requestpath.ClassT1, want: "no_original_dst"},
		{name: "T2", got: requestpath.ClassT2, want: "loop_guard"},
		{name: "T3", got: requestpath.ClassT3, want: "no_sni"},
		{name: "T4", got: requestpath.ClassT4, want: "handshake"},
		{name: "T5", got: requestpath.ClassT5, want: "unsupported_protocol"},
		{name: "T6", got: requestpath.ClassT6, want: "identity_mismatch"},
		{name: "T7", got: requestpath.ClassT7, want: "resource_limit"},
		{name: "T8", got: requestpath.ClassT8, want: "plaintext_unresolvable"},
		{name: "T9", got: requestpath.ClassT9, want: "plaintext_registry_unavailable"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("%s = %q, want %q", tc.name, tc.got, tc.want)
			}
		})
	}
}

func TestWireBehaviour_ConstantsExposeCloseAndStatusModes(t *testing.T) {
	if requestpath.WireCloseBare != 0 {
		t.Fatalf("WireCloseBare = %d, want 0", requestpath.WireCloseBare)
	}
	if requestpath.WireWrite400Close != 1 {
		t.Fatalf("WireWrite400Close = %d, want 1", requestpath.WireWrite400Close)
	}
	if requestpath.WireWrite431Close != 2 {
		t.Fatalf("WireWrite431Close = %d, want 2", requestpath.WireWrite431Close)
	}
}

func TestRejection_FieldAssignment_PreservesValues(t *testing.T) {
	rejection := requestpath.Rejection{
		Class:     requestpath.ClassT7,
		Reason:    pipeline.ReasonResourceLimit,
		Bound:     "max_inflight_requests",
		Wire:      requestpath.WireCloseBare,
		Status:    0,
		Fault:     true,
		RequestID: "req-1",
		ConnID:    "conn-1",
		Port:      443,
		Method:    "GET",
		Path:      "/v1/models",
	}

	if rejection.Class != requestpath.ClassT7 {
		t.Fatalf("Class = %q, want %q", rejection.Class, requestpath.ClassT7)
	}
	if rejection.Reason != pipeline.ReasonResourceLimit {
		t.Fatalf("Reason = %v, want %v", rejection.Reason, pipeline.ReasonResourceLimit)
	}
	if rejection.Bound != "max_inflight_requests" {
		t.Fatalf("Bound = %q, want %q", rejection.Bound, "max_inflight_requests")
	}
	if rejection.Wire != requestpath.WireCloseBare {
		t.Fatalf("Wire = %d, want %d", rejection.Wire, requestpath.WireCloseBare)
	}
	if !rejection.Fault {
		t.Fatal("Fault = false, want true")
	}
	if rejection.RequestID != "req-1" {
		t.Fatalf("RequestID = %q, want %q", rejection.RequestID, "req-1")
	}
	if rejection.ConnID != "conn-1" {
		t.Fatalf("ConnID = %q, want %q", rejection.ConnID, "conn-1")
	}
	if rejection.Port != 443 {
		t.Fatalf("Port = %d, want 443", rejection.Port)
	}
	if rejection.Method != "GET" {
		t.Fatalf("Method = %q, want %q", rejection.Method, "GET")
	}
	if rejection.Path != "/v1/models" {
		t.Fatalf("Path = %q, want %q", rejection.Path, "/v1/models")
	}
}
