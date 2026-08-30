package injector

import "time"

// InjectorOptions configures the sidecar injector.
type InjectorOptions struct {
	ProxyImage       string
	ReservedUID      int64
	ReservedGID      int64
	OptInLabelKey    string
	OptInLabelValue  string
	InjectionVersion string
}

// WebhookServerOptions configures the webhook server, its serving material, the
// service identity encoded into the serving certificate, and caBundle
// reconciliation targets.
type WebhookServerOptions struct {
	Addr                           string
	CertDir                        string
	ServiceName                    string
	ServiceNamespace               string
	MutatingWebhookConfiguration   string
	ValidatingWebhookConfiguration string
	CABundlePatchInterval          time.Duration
}
