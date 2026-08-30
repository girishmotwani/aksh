package audit

// This file extends the closed-enum label vocabulary with the Slice-6 injector
// observability labels: the webhook-configuration name patched by the caBundle
// reconciler and the coarse outcome of that patch attempt. Both are closed sets
// so an agent-controlled free string can never become a label value (§4.1).

// WebhookConfigName is the closed enum for the `configuration` label on
// aksh_webhook_cabundle_patch_total. There are exactly two admission webhook
// configurations (mutating, validating). Zero value WebhookConfigUnknown so an
// unset configuration never leaks a series.
type WebhookConfigName int

const (
	WebhookConfigUnknown WebhookConfigName = iota
	WebhookConfigMutating
	WebhookConfigValidating
)

// String returns the bounded configuration label value.
func (c WebhookConfigName) String() string {
	switch c {
	case WebhookConfigMutating:
		return "mutating"
	case WebhookConfigValidating:
		return "validating"
	default:
		return "unknown"
	}
}

// PatchResult is the closed enum for the `result` label on
// aksh_webhook_cabundle_patch_total. It records only the coarse outcome of a
// caBundle patch attempt. Zero value PatchResultUnknown.
type PatchResult int

const (
	PatchResultUnknown PatchResult = iota
	PatchResultSuccess
	PatchResultError
)

// String returns the bounded patch result label value.
func (r PatchResult) String() string {
	switch r {
	case PatchResultSuccess:
		return "success"
	case PatchResultError:
		return "error"
	default:
		return "unknown"
	}
}
