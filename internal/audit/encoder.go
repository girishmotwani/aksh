package audit

import (
	"encoding/json"

	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/girishmotwani/aksh/internal/policy"
)

// auditRecordSchema is the versioned schema key SIEM consumers parse.
// It is versioned from day one (design §2.1); F7 pins this design value,
// which diverges from the legacy StreamSink constant.
const auditRecordSchema = "aksh.dev/audit/v1"

// rfc3339Millis is RFC 3339, millisecond precision. Applied to a UTC time
// it renders the trailing "Z" the audit contract (§2.1) requires.
const rfc3339Millis = "2006-01-02T15:04:05.000Z07:00"

// identityNone is the sentinel used where no validated identity or named
// credential exists, so an early denial never echoes raw agent input (§2.1).
const identityNone = "none"

// AuditRecordEncoder serialises a pipeline.AuditEvent into the versioned
// aksh.dev/audit/v1 NDJSON record. It reads only the immutable AuditEvent,
// which by construction has no token field, so there is structurally no path
// from a credential to the record (INV-5, §2.3).
type AuditRecordEncoder struct{}

// NewAuditRecordEncoder constructs the audit record encoder.
func NewAuditRecordEncoder() *AuditRecordEncoder {
	return &AuditRecordEncoder{}
}

// Encode renders one JSON object terminated by a newline (NDJSON).
func (e *AuditRecordEncoder) Encode(ev pipeline.AuditEvent) ([]byte, error) {
	rec := buildAuditRecord(ev)
	body, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// completionRecord is the best-effort post-allow completion record (§2.2). It
// carries only correlation and outcome measurements — requestId, status, bytes
// and duration — never a token, preserving the structural INV-5 property.
type completionRecord struct {
	Schema     string          `json:"schema"`
	TS         string          `json:"ts"`
	RequestID  string          `json:"requestId"`
	Kind       string          `json:"kind"`
	Completion completionBlock `json:"completion"`
}

type completionBlock struct {
	Status     int   `json:"status"`
	Bytes      int64 `json:"bytes"`
	DurationUS int64 `json:"duration_us"`
}

// EncodeCompletion renders the completion-kind NDJSON record consumed by the
// Slice-4 BufferedSink write path.
func (e *AuditRecordEncoder) EncodeCompletion(ev pipeline.AuditEvent) ([]byte, error) {
	rec := completionRecord{
		Schema:    auditRecordSchema,
		TS:        ev.Timestamp.UTC().Format(rfc3339Millis),
		RequestID: ev.RequestID,
		Kind:      "completion",
		Completion: completionBlock{
			Status:     ev.CompletionStatus,
			Bytes:      ev.CompletionBytes,
			DurationUS: ev.CompletionDuration.Microseconds(),
		},
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// auditRecord is the nested, bounded field set of §2. Every field is a
// closed enum, a validated identifier, or a numeric measurement; there is
// deliberately no token field and no free-form text field (INV-5, §2.3).
type auditRecord struct {
	Schema     string          `json:"schema"`
	TS         string          `json:"ts"`
	RequestID  string          `json:"requestId"`
	Pod        podBlock        `json:"pod"`
	Agent      agentBlock      `json:"agent"`
	Decision   decisionBlock   `json:"decision"`
	Request    requestBlock    `json:"request"`
	Policy     policyBlock     `json:"policy"`
	Credential credentialBlock `json:"credential"`
	Timings    timingsBlock    `json:"timings"`
}

type podBlock struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

type agentBlock struct {
	ServiceAccount string `json:"serviceAccount"`
}

type decisionBlock struct {
	Disposition string `json:"disposition"`
	Reason      string `json:"reason"`
	Fault       bool   `json:"fault"`
	// FaultClass is present only when Fault is true and is always a closed
	// enum literal, never error text (§2.3, #85/#86).
	FaultClass *string `json:"faultClass,omitempty"`
}

type requestBlock struct {
	Identity string `json:"identity"`
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	// Transport is omitted for an early denial (before validation); for a
	// validated request it is the closed tls|plaintext enum.
	Transport string `json:"transport,omitempty"`
	// ServiceUID/ServiceGeneration are present only for plaintext transport
	// (§2.1, #89/#90).
	ServiceUID        string `json:"serviceUID,omitempty"`
	ServiceGeneration *int64 `json:"serviceGeneration,omitempty"`
}

type policyBlock struct {
	Ref     string `json:"ref"`
	Version string `json:"version"`
	// EvaluatorVersion is always present (§2.1, #92): the hash attests
	// inputs, not behaviour.
	EvaluatorVersion string `json:"evaluatorVersion"`
	Ambiguous        bool   `json:"ambiguous"`
}

type credentialBlock struct {
	// Identity is "none" when the rule names no credential; the rest of the
	// block is omitted then (§2.1). Never the token.
	Identity  string   `json:"identity"`
	Provider  string   `json:"provider,omitempty"`
	Resource  string   `json:"resource,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	CacheHit  *bool    `json:"cacheHit,omitempty"`
	ExpiresAt string   `json:"expiresAt,omitempty"`
}

type timingsBlock struct {
	TotalUS   int64 `json:"total_us"`
	MatchUS   int64 `json:"match_us"`
	AcquireUS int64 `json:"acquire_us"`
	AuditUS   int64 `json:"audit_us"`
}

// buildAuditRecord maps the immutable AuditEvent onto the nested record with
// correct per-outcome field presence.
func buildAuditRecord(ev pipeline.AuditEvent) auditRecord {
	return auditRecord{
		Schema:     auditRecordSchema,
		TS:         ev.Timestamp.UTC().Format(rfc3339Millis),
		RequestID:  ev.RequestID,
		Pod:        podBlock{Namespace: ev.PodNamespace, Name: ev.PodName, UID: ev.PodUID},
		Agent:      agentBlock{ServiceAccount: ev.AgentServiceAccount},
		Decision:   buildDecision(ev),
		Request:    buildRequest(ev),
		Policy:     buildPolicy(ev),
		Credential: buildCredential(ev),
		Timings:    buildTimings(ev),
	}
}

func buildDecision(ev pipeline.AuditEvent) decisionBlock {
	d := decisionBlock{
		Disposition: ev.Disposition.String(),
		Reason:      ev.DenyReason.String(),
		Fault:       ev.Fault,
	}
	if ev.Fault {
		fc := ev.FaultClass.String()
		d.FaultClass = &fc
	}
	return d
}

func buildRequest(ev pipeline.AuditEvent) requestBlock {
	// An early denial (before validation) carries no validated identity; the
	// record must not echo raw agent input, so identity becomes "none" and the
	// remaining validated fields are omitted.
	if ev.Identity == "" {
		return requestBlock{Identity: identityNone}
	}
	r := requestBlock{
		Identity:  ev.Identity,
		Method:    ev.Method,
		Path:      ev.Path,
		Port:      ev.Port,
		Transport: string(ev.Transport),
	}
	if ev.Transport == policy.TransportPlaintext {
		r.ServiceUID = ev.ServiceUID
		gen := ev.ServiceGeneration
		r.ServiceGeneration = &gen
	}
	return r
}

func buildPolicy(ev pipeline.AuditEvent) policyBlock {
	// Present even on stale/evaluator-fault outcomes, using the last known
	// version (§2.1, #91).
	return policyBlock{
		Ref:              ev.RuleName,
		Version:          ev.PolicyVersion,
		EvaluatorVersion: ev.EvaluatorVersion,
		Ambiguous:        ev.Ambiguous,
	}
}

func buildCredential(ev pipeline.AuditEvent) credentialBlock {
	if ev.CredentialID == "" {
		return credentialBlock{Identity: identityNone}
	}
	c := credentialBlock{
		Identity: ev.CredentialID,
		Provider: ev.CredentialProvider,
		Resource: ev.CredentialResource,
		Scopes:   ev.CredentialScopes,
	}
	cacheHit := ev.CacheHit
	c.CacheHit = &cacheHit
	if !ev.CredentialExpiresAt.IsZero() {
		c.ExpiresAt = ev.CredentialExpiresAt.UTC().Format(rfc3339Millis)
	}
	return c
}

func buildTimings(ev pipeline.AuditEvent) timingsBlock {
	return timingsBlock{
		TotalUS:   ev.Timings.Total.Microseconds(),
		MatchUS:   ev.Timings.Match.Microseconds(),
		AcquireUS: ev.Timings.Acquire.Microseconds(),
		AuditUS:   ev.Timings.Audit.Microseconds(),
	}
}
