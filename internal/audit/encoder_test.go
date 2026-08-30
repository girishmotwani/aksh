package audit_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/girishmotwani/aksh/internal/policy"
)

// fullAuditEvent is a representative allow-with-credential decision event
// carrying every §2 field populated.
func fullAuditEvent() pipeline.AuditEvent {
	return pipeline.AuditEvent{
		Timestamp:           time.Date(2026, 7, 31, 20, 14, 3, 412_000_000, time.UTC),
		RequestID:           "01J8ZK3M4N5P6Q7R8S9T0V1W2X",
		Identity:            "graph.microsoft.com",
		Method:              "GET",
		Path:                "/v1.0/me",
		Port:                443,
		Disposition:         pipeline.DispositionAllow,
		DenyReason:          pipeline.ReasonNone,
		Fault:               false,
		FaultClass:          pipeline.FaultClassNone,
		PolicyVersion:       "sha256:9f2c0000",
		RuleName:            "agents/graph-readonly/graph-read",
		CredentialID:        "graph-read",
		CacheHit:            true,
		Ambiguous:           false,
		PodNamespace:        "agents",
		PodName:             "research-agent-7d9f-x2k4",
		PodUID:              "b3d2c1e0-1111-2222-3333-444455556666",
		AgentServiceAccount: "research-agent",
		Transport:           policy.TransportTLS,
		EvaluatorVersion:    "v0.1.0",
		CredentialProvider:  "azure",
		CredentialResource:  "https://graph.microsoft.com",
		CredentialScopes:    []string{"User.Read"},
		CredentialExpiresAt: time.Date(2026, 7, 31, 21, 14, 3, 0, time.UTC),
		Timings: pipeline.AuditTimings{
			Total:   1840 * time.Microsecond,
			Match:   210 * time.Microsecond,
			Acquire: 40 * time.Microsecond,
			Audit:   830 * time.Microsecond,
		},
	}
}

// decodeRecord encodes ev and decodes the single NDJSON line into a generic map.
func decodeRecord(t *testing.T, ev pipeline.AuditEvent) map[string]any {
	t.Helper()
	enc := audit.NewAuditRecordEncoder()
	out, err := enc.Encode(ev)
	if err != nil {
		t.Fatalf("Encode returned error: %v", err)
	}
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Fatalf("output not newline-terminated: %q", out)
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimRight(out, "\n"), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v (%q)", err, out)
	}
	return m
}

func Test_Encode_SchemaField_IsAkshDevAuditV1(t *testing.T) {
	m := decodeRecord(t, fullAuditEvent())
	if got := m["schema"]; got != "aksh.dev/audit/v1" {
		t.Fatalf("schema = %v, want aksh.dev/audit/v1", got)
	}
}

func Test_Encode_Timestamp_RFC3339MillisUTC(t *testing.T) {
	m := decodeRecord(t, fullAuditEvent())
	ts, ok := m["ts"].(string)
	if !ok {
		t.Fatalf("ts is not a string: %v", m["ts"])
	}
	if ts != "2026-07-31T20:14:03.412Z" {
		t.Fatalf("ts = %q, want 2026-07-31T20:14:03.412Z", ts)
	}
	// Must parse as RFC3339 and be UTC with millisecond precision.
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t.Fatalf("ts not RFC3339: %v", err)
	}
	if parsed.Location() != time.UTC && !strings.HasSuffix(ts, "Z") {
		t.Fatalf("ts not UTC: %q", ts)
	}
	if !strings.Contains(ts, ".") || len(strings.SplitN(ts, ".", 2)[1]) != 4 { // "412Z"
		t.Fatalf("ts not millisecond precision: %q", ts)
	}
}

func Test_Encode_Output_IsOneJSONObjectPerLine(t *testing.T) {
	enc := audit.NewAuditRecordEncoder()
	out, err := enc.Encode(fullAuditEvent())
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}
	if bytes.Count(out, []byte("\n")) != 1 {
		t.Fatalf("expected exactly one newline, got %d: %q", bytes.Count(out, []byte("\n")), out)
	}
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Fatalf("record not newline-terminated: %q", out)
	}
	// The single line must be a complete JSON object.
	line := bytes.TrimRight(out, "\n")
	if bytes.Contains(line, []byte("\n")) {
		t.Fatalf("record body contains embedded newline: %q", line)
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("line is not a JSON object: %v", err)
	}
}

func Test_Encode_RequestId_ULIDPresent(t *testing.T) {
	ev := fullAuditEvent()
	m := decodeRecord(t, ev)
	if got := m["requestId"]; got != ev.RequestID {
		t.Fatalf("requestId = %v, want %v", got, ev.RequestID)
	}
}
