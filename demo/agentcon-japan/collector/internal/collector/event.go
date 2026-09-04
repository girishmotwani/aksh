package collector

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Bounds applied to every ingested field. They exist so a single request can
// never inflate memory, smuggle unbounded data into the observer UI, or turn a
// stored event into an echo channel for attacker-controlled content. Values are
// deliberately generous for a demo yet strictly enforced.
const (
	// MaxBodyBytes caps the accepted request body. A larger body is rejected
	// with 413 before any parsing, bounding per-request memory.
	MaxBodyBytes = 64 * 1024

	maxRequestIDLen = 128
	maxNamespaceLen = 63  // DNS-1123 label
	maxPodLen       = 253 // DNS-1123 subdomain
	maxClusterIDLen = 128
	maxSummaryLen   = 256

	// maxStolenCredentialLen bounds the optional leaked-credential field. It is
	// the one field the demo deliberately retains and displays verbatim, so the
	// bound exists purely to keep a single request from inflating memory or the
	// observer UI. A longer value is truncated, never rejected: the field is
	// optional demo colour, not part of the required contract.
	maxStolenCredentialLen = 8192
)

// Event is the sanitized, bounded projection of an ingested diagnostic report.
// Only these fields are ever retained or surfaced; the raw request body is
// discarded after its size is measured, so no secret, header, or arbitrary
// field an agent supplied is echoed back through the observer UI or the
// internal harness endpoints.
type Event struct {
	Seq             int64  `json:"seq"`
	Timestamp       string `json:"timestamp"` // RFC3339, assigned by the collector
	RequestID       string `json:"request_id"`
	SourceNamespace string `json:"source_namespace"`
	SourcePod       string `json:"source_pod"`
	ClusterID       string `json:"cluster_id"`
	Summary         string `json:"summary"`
	PayloadSize     int    `json:"payload_size"` // bytes of the original request body

	// StolenCredential is the demo's leaked-credential payload: an optional,
	// bounded string the agent was coaxed into exfiltrating. It is retained and
	// surfaced verbatim ON PURPOSE — showing the leak is the entire point of the
	// demo — but only ever in the bounded in-memory store and the observer UI,
	// never a log or other sink. Empty when absent.
	StolenCredential string `json:"stolen_credential,omitempty"`

	// CredentialClaims holds non-secret claims decoded from StolenCredential
	// when it is a JWT, for DISPLAY ONLY. It is nil when the credential is
	// absent or is not a decodable JWT, in which case the raw value is shown as
	// received. The signature is never verified and nothing is ever executed.
	CredentialClaims *CredentialClaims `json:"credential_claims,omitempty"`
}

// CredentialClaims are the non-secret, display-only claims lifted from a leaked
// JWT so the dashboard can prove the token is a genuine Microsoft Entra access
// token. Only these fields are surfaced; the signature is neither decoded nor
// verified. Every field is omitempty so a token missing a claim simply omits it.
type CredentialClaims struct {
	Iss   string `json:"iss,omitempty"`
	Aud   string `json:"aud,omitempty"`
	Exp   string `json:"exp,omitempty"` // RFC3339, converted from the numeric exp
	Tid   string `json:"tid,omitempty"`
	AppID string `json:"appid,omitempty"`
}

// diagnosticReport is the accepted wire schema. Unknown fields are ignored (not
// rejected) so the demo agent may send a rich body, but only the recognized
// fields below are ever read out of it.
type diagnosticReport struct {
	ClusterID string `json:"cluster_id"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Summary   string `json:"summary"`
	RequestID string `json:"request_id"`
	// StolenCredential is an optional top-level string carrying the demo's
	// leaked-credential payload. It is not validated as required; its absence is
	// normal and never an error.
	StolenCredential string `json:"stolen_credential"`
}

// dns1123 matches a single DNS-1123 label; a subdomain is one or more labels
// joined by dots. Namespaces are labels, pod names are subdomains, which mirrors
// Kubernetes naming and keeps both fields to a safe, predictable character set.
var (
	dns1123Label     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	dns1123Subdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	// clusterIDPattern and requestIDPattern permit a compact, log-safe token.
	idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
)

// validationError describes why a report was rejected. The message is safe to
// return to the caller because it names only the offending field, never its
// value, so a malformed body cannot reflect attacker content into the response.
type validationError struct{ msg string }

func (e *validationError) Error() string { return e.msg }

func invalid(msg string) *validationError { return &validationError{msg: msg} }

// sanitize validates the recognized fields and normalizes them into an Event.
// It returns a *validationError for any bounded-input violation. Seq, Timestamp
// and PayloadSize are filled in by the caller/store, not here.
func sanitize(r diagnosticReport, headerRequestID string, payloadSize int) (Event, error) {
	clusterID := strings.TrimSpace(r.ClusterID)
	if clusterID == "" {
		return Event{}, invalid("cluster_id is required")
	}
	if len(clusterID) > maxClusterIDLen {
		return Event{}, invalid("cluster_id exceeds bound")
	}
	if !idPattern.MatchString(clusterID) {
		return Event{}, invalid("cluster_id has invalid characters")
	}

	namespace := strings.TrimSpace(r.Namespace)
	if namespace == "" {
		return Event{}, invalid("namespace is required")
	}
	if len(namespace) > maxNamespaceLen || !dns1123Label.MatchString(namespace) {
		return Event{}, invalid("namespace is not a valid DNS-1123 label")
	}

	pod := strings.TrimSpace(r.Pod)
	if pod == "" {
		return Event{}, invalid("pod is required")
	}
	if len(pod) > maxPodLen || !dns1123Subdomain.MatchString(pod) {
		return Event{}, invalid("pod is not a valid DNS-1123 subdomain")
	}

	// request_id is optional and least-trusted: prefer the validated body
	// value, fall back to a validated header, else mint a fresh opaque id.
	requestID := firstValidID(strings.TrimSpace(r.RequestID), strings.TrimSpace(headerRequestID))
	if requestID == "" {
		requestID = newRequestID()
	}

	// stolen_credential is optional demo colour. It is bounded and, when it
	// looks like a JWT, decoded for display only. Absence and malformed input
	// are both non-fatal: a bad value degrades to an empty/raw display.
	credential := boundCredential(r.StolenCredential)

	return Event{
		RequestID:        requestID,
		SourceNamespace:  namespace,
		SourcePod:        pod,
		ClusterID:        clusterID,
		Summary:          sanitizeSummary(r.Summary),
		PayloadSize:      payloadSize,
		StolenCredential: credential,
		CredentialClaims: decodeJWTClaims(credential),
	}, nil
}

// boundCredential trims and caps the leaked-credential string to
// maxStolenCredentialLen, returning valid UTF-8. It never rejects: an oversized
// value is truncated because the field is optional demo content, not a
// contract field. The value is otherwise preserved verbatim so the UI can show
// exactly what leaked.
func boundCredential(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > maxStolenCredentialLen {
		s = strings.ToValidUTF8(s[:maxStolenCredentialLen], "")
	}
	return s
}

// decodeJWTClaims returns the non-secret, display-only claims of a JWT-looking
// credential, or nil if it is absent or not a decodable JWT. "JWT-looking" means
// exactly three non-empty base64url segments whose header and payload are valid
// base64url-encoded JSON. The signature is validated as base64url only; it is
// never verified and no cryptography is performed. The whole function is
// panic-safe: any unexpected input falls back to nil so the caller shows the raw
// value instead. This is DISPLAY ONLY — nothing here is trusted or executed.
func decodeJWTClaims(raw string) (claims *CredentialClaims) {
	defer func() {
		if recover() != nil {
			claims = nil
		}
	}()
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}
	var hdr map[string]any
	if json.Unmarshal(header, &hdr) != nil {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return nil // signature must at least be base64url; still never verified
	}
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil {
		return nil
	}
	c := &CredentialClaims{
		Iss:   claimString(m["iss"]),
		Aud:   claimString(m["aud"]),
		Tid:   claimString(m["tid"]),
		AppID: claimString(m["appid"]),
	}
	if exp, ok := claimUnix(m["exp"]); ok {
		c.Exp = time.Unix(exp, 0).UTC().Format(time.RFC3339)
	}
	return c
}

// claimString coerces a JSON claim to a display string. A plain string is
// returned as-is; an array (e.g. a multi-valued aud) is joined; anything else
// yields the empty string so a non-string claim is simply not shown.
func claimString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return ""
	}
}

// claimUnix coerces a numeric-or-numeric-string exp claim to Unix seconds.
func claimUnix(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return n, true
		}
	case string:
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

// firstValidID returns the first candidate that is a non-empty, in-bounds,
// pattern-valid id. An invalid candidate is skipped rather than rejected so a
// bad client-supplied id degrades to a server-minted one instead of a 4xx.
func firstValidID(candidates ...string) string {
	for _, c := range candidates {
		if c == "" || len(c) > maxRequestIDLen {
			continue
		}
		if idPattern.MatchString(c) {
			return c
		}
	}
	return ""
}

// sanitizeSummary strips control characters and truncates to a hard bound so a
// free-text field cannot break the UI, inject terminal escapes into logs, or
// carry an unbounded payload.
func sanitizeSummary(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxSummaryLen {
		// Truncate on a rune boundary to avoid emitting invalid UTF-8.
		s = strings.ToValidUTF8(s[:maxSummaryLen], "")
	}
	return s
}

// newRequestID mints an opaque, collision-resistant fallback id. crypto/rand
// makes it unpredictable; the failure path still yields a usable non-empty id.
func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-unknown"
	}
	return "req-" + hex.EncodeToString(b[:])
}
