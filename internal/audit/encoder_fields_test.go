package audit_test

import (
	"strings"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/girishmotwani/aksh/internal/policy"
)

// earlyDenialEvent models a denial reached before request validation: no
// validated identity, method, path, transport, or named credential.
func earlyDenialEvent() pipeline.AuditEvent {
	return pipeline.AuditEvent{
		Timestamp:        time.Date(2026, 7, 31, 20, 14, 3, 0, time.UTC),
		RequestID:        "01J8ZK3M4N5P6Q7R8S9T0V1W2X",
		Disposition:      pipeline.DispositionDeny,
		DenyReason:       pipeline.ReasonNoSNI,
		PodNamespace:     "agents",
		PodName:          "research-agent-7d9f-x2k4",
		PodUID:           "b3d2c1e0",
		EvaluatorVersion: "v0.1.0",
	}
}

// plaintextEvent models an allowed plaintext-transport request carrying the
// resolved serviceUID/serviceGeneration.
func plaintextEvent() pipeline.AuditEvent {
	ev := fullAuditEvent()
	ev.Transport = policy.TransportPlaintext
	ev.ServiceUID = "svc-uid-9988"
	ev.ServiceGeneration = 7
	return ev
}

// staleEvent models an evaluator-fault/stale-snapshot denial that must still
// carry the last-known policy block.
func staleEvent() pipeline.AuditEvent {
	ev := fullAuditEvent()
	ev.Disposition = pipeline.DispositionDeny
	ev.DenyReason = pipeline.ReasonSnapshotStale
	ev.Fault = true
	ev.FaultClass = pipeline.FaultClassTransient
	return ev
}

func Test_Encode_PodBlock_NamespaceNameUID(t *testing.T) {
	ev := fullAuditEvent()
	m := decodeRecord(t, ev)
	pod, ok := m["pod"].(map[string]any)
	if !ok {
		t.Fatalf("pod block missing: %v", m["pod"])
	}
	if pod["namespace"] != ev.PodNamespace || pod["name"] != ev.PodName || pod["uid"] != ev.PodUID {
		t.Fatalf("pod block = %v, want ns=%q name=%q uid=%q", pod, ev.PodNamespace, ev.PodName, ev.PodUID)
	}
}

func Test_Encode_AgentServiceAccount_Present(t *testing.T) {
	ev := fullAuditEvent()
	m := decodeRecord(t, ev)
	agent, ok := m["agent"].(map[string]any)
	if !ok {
		t.Fatalf("agent block missing: %v", m["agent"])
	}
	if agent["serviceAccount"] != ev.AgentServiceAccount {
		t.Fatalf("agent.serviceAccount = %v, want %q", agent["serviceAccount"], ev.AgentServiceAccount)
	}
}

func Test_Encode_DecisionBlock_DispositionReasonFault(t *testing.T) {
	ev := staleEvent()
	m := decodeRecord(t, ev)
	dec, ok := m["decision"].(map[string]any)
	if !ok {
		t.Fatalf("decision block missing: %v", m["decision"])
	}
	if dec["disposition"] != "deny" {
		t.Fatalf("disposition = %v, want deny", dec["disposition"])
	}
	if dec["reason"] != "policy_cache_stale" {
		t.Fatalf("reason = %v, want policy_cache_stale", dec["reason"])
	}
	if dec["fault"] != true {
		t.Fatalf("fault = %v, want true", dec["fault"])
	}
}

func Test_Encode_FaultClass_PresentOnlyWhenFault(t *testing.T) {
	// No fault -> faultClass absent.
	m := decodeRecord(t, fullAuditEvent())
	dec := m["decision"].(map[string]any)
	if _, present := dec["faultClass"]; present {
		t.Fatalf("faultClass present on non-fault decision: %v", dec)
	}
	// Fault -> faultClass present.
	m = decodeRecord(t, staleEvent())
	dec = m["decision"].(map[string]any)
	if _, present := dec["faultClass"]; !present {
		t.Fatalf("faultClass absent on fault decision: %v", dec)
	}
}

func Test_Encode_FaultClass_NeverErrorText(t *testing.T) {
	closed := map[string]bool{"none": true, "transient": true, "permanent": true, "local": true, "unknown": true}
	for _, fc := range []pipeline.FaultClass{
		pipeline.FaultClassTransient, pipeline.FaultClassPermanent, pipeline.FaultClassLocal,
	} {
		ev := fullAuditEvent()
		ev.Fault = true
		ev.FaultClass = fc
		m := decodeRecord(t, ev)
		dec := m["decision"].(map[string]any)
		val, _ := dec["faultClass"].(string)
		if !closed[val] {
			t.Fatalf("faultClass %q is not a closed enum literal", val)
		}
		if strings.ContainsAny(val, " :/") {
			t.Fatalf("faultClass %q looks like free-form error text", val)
		}
	}
}

func Test_Encode_EarlyDenial_RequestFieldsOmittedOrNone(t *testing.T) {
	m := decodeRecord(t, earlyDenialEvent())
	req, ok := m["request"].(map[string]any)
	if !ok {
		t.Fatalf("request block missing: %v", m["request"])
	}
	if req["identity"] != "none" {
		t.Fatalf("early-denial request.identity = %v, want none", req["identity"])
	}
	// Raw agent input must not be echoed: validated fields omitted.
	for _, k := range []string{"method", "path", "port", "serviceUID", "serviceGeneration"} {
		if _, present := req[k]; present {
			t.Fatalf("early-denial request unexpectedly carries %q: %v", k, req)
		}
	}
}

func Test_Encode_EarlyDenial_CredentialIdentityNone(t *testing.T) {
	m := decodeRecord(t, earlyDenialEvent())
	cred, ok := m["credential"].(map[string]any)
	if !ok {
		t.Fatalf("credential block missing: %v", m["credential"])
	}
	if cred["identity"] != "none" {
		t.Fatalf("credential.identity = %v, want none", cred["identity"])
	}
	if len(cred) != 1 {
		t.Fatalf("credential block should be identity-only, got %v", cred)
	}
}

func Test_Encode_TransportTLS_NoServiceUIDGeneration(t *testing.T) {
	m := decodeRecord(t, fullAuditEvent()) // TLS
	req := m["request"].(map[string]any)
	if req["transport"] != "tls" {
		t.Fatalf("transport = %v, want tls", req["transport"])
	}
	for _, k := range []string{"serviceUID", "serviceGeneration"} {
		if _, present := req[k]; present {
			t.Fatalf("TLS request unexpectedly carries %q: %v", k, req)
		}
	}
}

func Test_Encode_TransportPlaintext_IncludesServiceUIDGeneration(t *testing.T) {
	ev := plaintextEvent()
	m := decodeRecord(t, ev)
	req := m["request"].(map[string]any)
	if req["transport"] != "plaintext" {
		t.Fatalf("transport = %v, want plaintext", req["transport"])
	}
	if req["serviceUID"] != ev.ServiceUID {
		t.Fatalf("serviceUID = %v, want %q", req["serviceUID"], ev.ServiceUID)
	}
	gen, ok := req["serviceGeneration"].(float64)
	if !ok || int64(gen) != ev.ServiceGeneration {
		t.Fatalf("serviceGeneration = %v, want %d", req["serviceGeneration"], ev.ServiceGeneration)
	}
}

func Test_Encode_PolicyBlock_PresentEvenOnStaleOutcome(t *testing.T) {
	ev := staleEvent()
	m := decodeRecord(t, ev)
	pol, ok := m["policy"].(map[string]any)
	if !ok {
		t.Fatalf("policy block missing on stale outcome: %v", m["policy"])
	}
	if pol["ref"] != ev.RuleName || pol["version"] != ev.PolicyVersion {
		t.Fatalf("policy block = %v, want last-known ref/version", pol)
	}
}

func Test_Encode_EvaluatorVersion_AlwaysPresent(t *testing.T) {
	for name, ev := range map[string]pipeline.AuditEvent{
		"full":  fullAuditEvent(),
		"early": earlyDenialEvent(),
		"stale": staleEvent(),
	} {
		m := decodeRecord(t, ev)
		pol, ok := m["policy"].(map[string]any)
		if !ok {
			t.Fatalf("%s: policy block missing", name)
		}
		if _, present := pol["evaluatorVersion"]; !present {
			t.Fatalf("%s: evaluatorVersion absent: %v", name, pol)
		}
	}
}

func Test_Encode_AllowWithCredential_ResourceScopesPresent(t *testing.T) {
	ev := fullAuditEvent()
	m := decodeRecord(t, ev)
	cred := m["credential"].(map[string]any)
	if cred["identity"] != ev.CredentialID {
		t.Fatalf("credential.identity = %v, want %q", cred["identity"], ev.CredentialID)
	}
	if cred["resource"] != ev.CredentialResource {
		t.Fatalf("credential.resource = %v, want %q", cred["resource"], ev.CredentialResource)
	}
	scopes, ok := cred["scopes"].([]any)
	if !ok || len(scopes) != 1 || scopes[0] != "User.Read" {
		t.Fatalf("credential.scopes = %v, want [User.Read]", cred["scopes"])
	}
	if _, present := cred["cacheHit"]; !present {
		t.Fatalf("credential.cacheHit absent: %v", cred)
	}
	if _, present := cred["expiresAt"]; !present {
		t.Fatalf("credential.expiresAt absent: %v", cred)
	}
}

func Test_Encode_CredentialBlock_NeverContainsToken(t *testing.T) {
	for _, ev := range []pipeline.AuditEvent{fullAuditEvent(), earlyDenialEvent(), plaintextEvent(), staleEvent()} {
		m := decodeRecord(t, ev)
		cred, ok := m["credential"].(map[string]any)
		if !ok {
			continue
		}
		for k := range cred {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "token") || strings.Contains(lk, "secret") || strings.Contains(lk, "bearer") {
				t.Fatalf("credential block carries forbidden key %q", k)
			}
		}
	}
}

func Test_Encode_Timings_PerStageMicroseconds(t *testing.T) {
	ev := fullAuditEvent()
	m := decodeRecord(t, ev)
	tm, ok := m["timings"].(map[string]any)
	if !ok {
		t.Fatalf("timings block missing: %v", m["timings"])
	}
	want := map[string]int64{"total_us": 1840, "match_us": 210, "acquire_us": 40, "audit_us": 830}
	for k, w := range want {
		got, ok := tm[k].(float64)
		if !ok {
			t.Fatalf("timings.%s missing/not-number: %v", k, tm[k])
		}
		if int64(got) != w {
			t.Fatalf("timings.%s = %d, want %d", k, int64(got), w)
		}
	}
}

// ensure per-stage timings and closed-enum presence are asserted above.
