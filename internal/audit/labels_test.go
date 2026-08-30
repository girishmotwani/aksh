package audit_test

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/audit"
)

// TestClosedEnumStrings verifies each closed metric-label enum maps its values
// to the exact §4 label strings and that unknown values fall back to a single
// bounded token (never leaking an out-of-range integer as a distinct series).
func TestClosedEnumStrings(t *testing.T) {
	t.Run("StageName", func(t *testing.T) {
		cases := map[audit.StageName]string{
			audit.StageUnknown:        "unknown",
			audit.StageSanitise:       "sanitise",
			audit.StageIdentity:       "identity",
			audit.StageMatch:          "match",
			audit.StageAcquire:        "acquire",
			audit.StageInject:         "inject",
			audit.StageAcceptDispatch: "accept_to_dispatch",
			audit.StageTLSConfigBuild: "tls_config_build",
			audit.StageLeafMint:       "leaf_mint",
			audit.StageUpstreamDial:   "upstream_dial",
			audit.StageResolve:        "resolve",
		}
		for v, want := range cases {
			if got := v.String(); got != want {
				t.Errorf("StageName(%d).String() = %q, want %q", int(v), got, want)
			}
		}
		if got := audit.StageName(9999).String(); got != "unknown" {
			t.Errorf("StageName out-of-range = %q, want %q", got, "unknown")
		}
	})

	t.Run("BoundName", func(t *testing.T) {
		cases := map[audit.BoundName]string{
			audit.BoundNone:                     "none",
			audit.BoundMaxInflightRequests:      "max_inflight_requests",
			audit.BoundPipelining:               "pipelining",
			audit.BoundMaxHeaderBytes:           "max_header_bytes",
			audit.BoundRequestHeaderReadTimeout: "request_header_read_timeout",
			audit.BoundHandover:                 "handover",
			audit.BoundMaxResponseBody:          "max_response_body",
			audit.BoundHandshakeRate:            "handshake_rate",
		}
		for v, want := range cases {
			if got := v.String(); got != want {
				t.Errorf("BoundName(%d).String() = %q, want %q", int(v), got, want)
			}
		}
		if got := audit.BoundName(9999).String(); got != "unknown" {
			t.Errorf("BoundName out-of-range = %q, want %q", got, "unknown")
		}
	})

	t.Run("TransportKind", func(t *testing.T) {
		cases := map[audit.TransportKind]string{
			audit.TransportTLS:       "tls",
			audit.TransportPlaintext: "plaintext",
		}
		seen := map[string]bool{}
		for v, want := range cases {
			got := v.String()
			if got != want {
				t.Errorf("TransportKind(%d).String() = %q, want %q", int(v), got, want)
			}
			seen[got] = true
		}
		if len(seen) != 2 {
			t.Errorf("TransportKind closed set size = %d, want 2", len(seen))
		}
	})

	t.Run("AuditRecordKind", func(t *testing.T) {
		cases := map[audit.AuditRecordKind]string{
			audit.AuditRecordDecision:   "decision",
			audit.AuditRecordCompletion: "completion",
		}
		for v, want := range cases {
			if got := v.String(); got != want {
				t.Errorf("AuditRecordKind(%d).String() = %q, want %q", int(v), got, want)
			}
		}
	})

	t.Run("RejectClass", func(t *testing.T) {
		cases := map[audit.RejectClass]string{
			audit.RejectClassNone:                     "none",
			audit.RejectClassNoOriginalDst:            "no_original_dst",
			audit.RejectClassLoopGuard:                "loop_guard",
			audit.RejectClassNoSNI:                    "no_sni",
			audit.RejectClassHandshake:                "handshake",
			audit.RejectClassUnsupportedProtocol:      "unsupported_protocol",
			audit.RejectClassIdentityMismatch:         "identity_mismatch",
			audit.RejectClassResourceLimit:            "resource_limit",
			audit.RejectClassPlaintextUnresolvable:    "plaintext_unresolvable",
			audit.RejectClassPlaintextRegistryUnavail: "plaintext_registry_unavailable",
		}
		for v, want := range cases {
			if got := v.String(); got != want {
				t.Errorf("RejectClass(%d).String() = %q, want %q", int(v), got, want)
			}
		}
		if got := audit.RejectClass(9999).String(); got != "unknown" {
			t.Errorf("RejectClass out-of-range = %q, want %q", got, "unknown")
		}
	})
}

// Test #112: audit.StageResolve.String() returns the bounded closed-enum label
// "resolve".
func TestStageResolve_String_ReturnsResolve(t *testing.T) {
	if got := audit.StageResolve.String(); got != "resolve" {
		t.Fatalf("StageResolve.String() = %q, want %q", got, "resolve")
	}
}

// Test #113: StageResolve is ordinal-appended immediately after
// StageUpstreamDial; existing ordinals are unshifted (ordinal-stability).
func TestStageResolve_Ordinal_AppendedAfterStageUpstreamDial(t *testing.T) {
	if got, want := audit.StageResolve, audit.StageUpstreamDial+1; got != want {
		t.Fatalf("StageResolve ordinal = %d, want %d (appended after StageUpstreamDial)", int(got), int(want))
	}
	if int(audit.StageUpstreamDial) != int(audit.StageLeafMint)+1 {
		t.Fatalf("StageUpstreamDial ordinal shifted: got %d, want %d", int(audit.StageUpstreamDial), int(audit.StageLeafMint)+1)
	}
}
