package audit_test

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/audit"
)

// These tests pin the Slice-2 closed-enum label vocabulary (S6 §4). Each type
// is a closed set whose String() yields the bounded label value; an
// agent-controlled free string can never be assigned to one (§4.1).

func TestProviderID_String(t *testing.T) {
	cases := map[audit.ProviderID]string{
		audit.ProviderUnknown: "unknown",
		audit.ProviderEntra:   "entra",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("ProviderID(%d).String() = %q, want %q", in, got, want)
		}
	}
}

func TestResult_String(t *testing.T) {
	cases := map[audit.Result]string{
		audit.ResultUnknown: "unknown",
		audit.ResultSuccess: "success",
		audit.ResultFailure: "failure",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("Result(%d).String() = %q, want %q", in, got, want)
		}
	}
}

func TestAcquireErrorClass_String(t *testing.T) {
	cases := map[audit.AcquireErrorClass]string{
		audit.AcquireErrorNone:      "none",
		audit.AcquireErrorTransient: "transient",
		audit.AcquireErrorPermanent: "permanent",
		audit.AcquireErrorLocal:     "local",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("AcquireErrorClass(%d).String() = %q, want %q", in, got, want)
		}
	}
}

func TestAcquireErrorClassFromString_UnknownFallsBackToNone(t *testing.T) {
	if got := audit.AcquireErrorClassFromString("transient"); got != audit.AcquireErrorTransient {
		t.Errorf("FromString(transient) = %v, want transient", got)
	}
	if got := audit.AcquireErrorClassFromString("nonsense-agent-string"); got != audit.AcquireErrorNone {
		t.Errorf("FromString(unrecognised) = %v, want AcquireErrorNone", got)
	}
}

func TestUpstreamResult_String(t *testing.T) {
	cases := map[audit.UpstreamResult]string{
		audit.UpstreamResultUnknown: "unknown",
		audit.UpstreamResultSuccess: "success",
		audit.UpstreamResultFailure: "failure",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("UpstreamResult(%d).String() = %q, want %q", in, got, want)
		}
	}
}

func TestWebhookName_String(t *testing.T) {
	cases := map[audit.WebhookName]string{
		audit.WebhookUnknown:  "unknown",
		audit.WebhookMutate:   "mutate",
		audit.WebhookValidate: "validate",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("WebhookName(%d).String() = %q, want %q", in, got, want)
		}
	}
}

func TestAdmissionResult_String(t *testing.T) {
	cases := map[audit.AdmissionResult]string{
		audit.AdmissionResultUnknown: "unknown",
		audit.AdmissionResultAllowed: "allowed",
		audit.AdmissionResultDenied:  "denied",
		audit.AdmissionResultError:   "errored",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("AdmissionResult(%d).String() = %q, want %q", in, got, want)
		}
	}
}

func TestAdmissionRule_String(t *testing.T) {
	cases := map[audit.AdmissionRule]string{
		audit.AdmissionRuleUnknown:             "unknown",
		audit.AdmissionRuleRunAsUser:           "run_as_user",
		audit.AdmissionRuleContainerOrder:      "container_order",
		audit.AdmissionRuleCanonicalShape:      "canonical_shape",
		audit.AdmissionRuleCapabilities:        "capabilities",
		audit.AdmissionRuleProcessNamespace:    "process_namespace",
		audit.AdmissionRuleHostNetwork:         "host_network",
		audit.AdmissionRuleServiceAccountToken: "service_account_token",
		audit.AdmissionRuleCredentialMounts:    "credential_mounts",
		audit.AdmissionRuleHostUsers:           "host_users",
		audit.AdmissionRuleIstioSidecar:        "istio_sidecar",
		audit.AdmissionRuleCATrustReadOnly:     "ca_trust_read_only",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("AdmissionRule(%d).String() = %q, want %q", in, got, want)
		}
	}
}

func TestBreakerState_String(t *testing.T) {
	cases := map[audit.BreakerState]string{
		audit.BreakerClosed:   "closed",
		audit.BreakerOpen:     "open",
		audit.BreakerHalfOpen: "half_open",
	}
	for in, want := range cases {
		if got := in.String(); got != want {
			t.Errorf("BreakerState(%d).String() = %q, want %q", in, got, want)
		}
	}
}

func TestCredentialID_String_IsNamedType(t *testing.T) {
	c := audit.CredentialID("deadbeef")
	if c.String() != "deadbeef" {
		t.Errorf("CredentialID.String() = %q, want deadbeef", c.String())
	}
}
