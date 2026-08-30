package injector

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WebhookConfigOptions parameterises the rendered admission webhook
// configurations: the configuration names, the serving service identity, and
// the CA bundle to install. The renderer produces the fail-closed, namespace
// opt-in registration asserted by the webhook-configuration correctness tests.
type WebhookConfigOptions struct {
	MutatingName     string
	ValidatingName   string
	ServiceName      string
	ServiceNamespace string
	MutatePath       string
	ValidatePath     string
	CABundle         []byte
}

const (
	// injectLabelKey/Value scope webhook registration to operator opt-in
	// namespaces. This is an operator-owned label, never a pod-author selector,
	// so admission cannot be opted out by workload authors (ADR-S5-07).
	injectLabelKey   = "aksh.dev/inject"
	injectLabelValue = "enabled"

	defaultMutatePath   = "/mutate"
	defaultValidatePath = "/validate"

	mutateWebhookName   = "mutate.pods.aksh.dev"
	validateWebhookName = "validate.pods.aksh.dev"
)

// withWebhookConfigDefaults fills unset option fields with the production
// defaults so callers may pass a partial options struct.
func withWebhookConfigDefaults(opts WebhookConfigOptions) WebhookConfigOptions {
	if opts.MutatingName == "" {
		opts.MutatingName = "aksh-injector-mutating"
	}
	if opts.ValidatingName == "" {
		opts.ValidatingName = "aksh-injector-validating"
	}
	if opts.ServiceName == "" {
		opts.ServiceName = "aksh-injector"
	}
	if opts.ServiceNamespace == "" {
		opts.ServiceNamespace = "aksh-system"
	}
	if opts.MutatePath == "" {
		opts.MutatePath = defaultMutatePath
	}
	if opts.ValidatePath == "" {
		opts.ValidatePath = defaultValidatePath
	}
	return opts
}

// namespaceSelector returns the operator opt-in namespace selector shared by
// both webhooks: matchLabels aksh.dev/inject=enabled and no pod-author opt-out
// matchExpressions.
func namespaceSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: map[string]string{injectLabelKey: injectLabelValue},
	}
}

func failPolicy() *admissionregistrationv1.FailurePolicyType {
	fail := admissionregistrationv1.Fail
	return &fail
}

func sideEffectsNone() *admissionregistrationv1.SideEffectClass {
	none := admissionregistrationv1.SideEffectClassNone
	return &none
}

// webhookTimeoutSeconds bounds the admission call so a slow or hung injector
// cannot stall pod admission beyond this window before failurePolicy applies.
// Kept in sync with deploy/40-mutatingwebhook.yaml and deploy/50-validatingwebhook.yaml.
func webhookTimeoutSeconds() *int32 {
	t := int32(5)
	return &t
}

func namespacedScope() *admissionregistrationv1.ScopeType {
	scope := admissionregistrationv1.NamespacedScope
	return &scope
}

func clientConfig(namespace, name, path string, caBundle []byte) admissionregistrationv1.WebhookClientConfig {
	p := path
	return admissionregistrationv1.WebhookClientConfig{
		Service: &admissionregistrationv1.ServiceReference{
			Namespace: namespace,
			Name:      name,
			Path:      &p,
		},
		CABundle: caBundle,
	}
}

// RenderMutatingWebhookConfiguration renders the MutatingWebhookConfiguration:
// namespace opt-in, failurePolicy Fail, and a single rule matching core v1 pods
// CREATE in Namespaced scope.
func RenderMutatingWebhookConfiguration(opts WebhookConfigOptions) *admissionregistrationv1.MutatingWebhookConfiguration {
	opts = withWebhookConfigDefaults(opts)
	return &admissionregistrationv1.MutatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "MutatingWebhookConfiguration",
		},
		ObjectMeta: metav1.ObjectMeta{Name: opts.MutatingName},
		Webhooks: []admissionregistrationv1.MutatingWebhook{
			{
				Name:                    mutateWebhookName,
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             sideEffectsNone(),
				FailurePolicy:           failPolicy(),
				TimeoutSeconds:          webhookTimeoutSeconds(),
				NamespaceSelector:       namespaceSelector(),
				ClientConfig:            clientConfig(opts.ServiceNamespace, opts.ServiceName, opts.MutatePath, opts.CABundle),
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
							Scope:       namespacedScope(),
						},
					},
				},
			},
		},
	}
}

// RenderValidatingWebhookConfiguration renders the
// ValidatingWebhookConfiguration: namespace opt-in, failurePolicy Fail, and
// rules matching core v1 pods CREATE and pods/ephemeralcontainers UPDATE in
// Namespaced scope.
func RenderValidatingWebhookConfiguration(opts WebhookConfigOptions) *admissionregistrationv1.ValidatingWebhookConfiguration {
	opts = withWebhookConfigDefaults(opts)
	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingWebhookConfiguration",
		},
		ObjectMeta: metav1.ObjectMeta{Name: opts.ValidatingName},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{
			{
				Name:                    validateWebhookName,
				AdmissionReviewVersions: []string{"v1"},
				SideEffects:             sideEffectsNone(),
				FailurePolicy:           failPolicy(),
				TimeoutSeconds:          webhookTimeoutSeconds(),
				NamespaceSelector:       namespaceSelector(),
				ClientConfig:            clientConfig(opts.ServiceNamespace, opts.ServiceName, opts.ValidatePath, opts.CABundle),
				Rules: []admissionregistrationv1.RuleWithOperations{
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
							Scope:       namespacedScope(),
						},
					},
					{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Update},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods/ephemeralcontainers"},
							Scope:       namespacedScope(),
						},
					},
				},
			},
		},
	}
}
