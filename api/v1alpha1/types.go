// Package v1alpha1 contains the AkshPolicy CRD Go types.
//
// This is the only public (non-internal) package — it is the
// compatibility surface per ADR-S0-09.
// +kubebuilder:object:generate=true
// +groupName=aksh.dev
package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// AkshPolicy is the user-facing policy resource.
// +kubebuilder:object:root=true
type AkshPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AkshPolicySpec `json:"spec"`
}

// AkshPolicySpec defines the desired state of an AkshPolicy.
// The Egress envelope is a normative S0 requirement: without it,
// adding spec.ingress later forces a breaking migration.
type AkshPolicySpec struct {
	// Selector determines which workloads this policy applies to.
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Egress holds the egress rules. v1 adds spec.ingress alongside.
	Egress EgressSpec `json:"egress"`
}

// EgressSpec contains egress policy rules.
type EgressSpec struct {
	Rules []EgressRule `json:"rules,omitempty"`
}

// HostMatch identifies the destination host a rule applies to.
type HostMatch struct {
	Host string `json:"host"`
}

// PathType discriminates exact vs prefix path matching.
type PathType string

const (
	PathTypeExact  PathType = "Exact"
	PathTypePrefix PathType = "Prefix"
)

// PathMatcher is a single path matching entry within a rule.
type PathMatcher struct {
	Type  PathType `json:"type"`
	Value string   `json:"value"`
}

// RuleMatch specifies which requests to a host are permitted.
// All dimensions are AND'd; paths within the list are OR'd.
type RuleMatch struct {
	Methods []string      `json:"methods,omitempty"`
	Paths   []PathMatcher `json:"paths,omitempty"`
}

// CredentialSelector describes the OAuth credential a rule wants injected.
//
// When present, the pipeline acquires a token matching these fields
// and injects it into the Authorization header. When nil on a matched
// rule, the request is forwarded without credentials.
//
// AllowPlaintext on the parent rule controls transport, NOT whether
// credentials are injected — a plaintext rule with a CredentialSelector
// still gets a token (the operator explicitly opted in to this risk).
type CredentialSelector struct {
	Provider string   `json:"provider,omitempty"`
	Resource string   `json:"resource,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
}

// Constraint is a placeholder for future narrowing dimensions (S2 section 4).
type Constraint struct {
	Type string `json:"type"`
}

// EgressRule is a single egress policy rule per S2.
//
// Key design decisions:
//   - AllowPlaintext is orthogonal to Credential — a rule can require
//     authentication over HTTP (plaintext + credential both set).
//   - Effect is a forward-compatibility guard: MVP only accepts "Allow"
//     or empty. A future version adds "Deny" for denylist rules.
//     Compile() rejects unknown effects so a deny rule can never
//     silently become an allow rule.
//   - Constraints is reserved (maxItems:0 in CRD schema) for future
//     narrowing dimensions like source-namespace or time-of-day.
type EgressRule struct {
	Name           string              `json:"name"`
	To             HostMatch           `json:"to"`
	Match          *RuleMatch          `json:"match,omitempty"`
	AllowPlaintext bool                `json:"allowPlaintext,omitempty"`
	Credential     *CredentialSelector `json:"credential,omitempty"`
	Constraints    []Constraint        `json:"constraints,omitempty"`
	Effect         string              `json:"effect,omitempty"`
}

// AkshPolicyList contains a list of AkshPolicy resources.
// +kubebuilder:object:root=true
type AkshPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AkshPolicy `json:"items"`
}
