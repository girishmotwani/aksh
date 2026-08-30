package injector

import (
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func renderedConfigs() (*admissionregistrationv1.MutatingWebhookConfiguration, *admissionregistrationv1.ValidatingWebhookConfiguration) {
	opts := WebhookConfigOptions{
		MutatingName:     testMutatingName,
		ValidatingName:   testValidatingName,
		ServiceName:      testServiceName,
		ServiceNamespace: testServiceNamespace,
	}
	return RenderMutatingWebhookConfiguration(opts), RenderValidatingWebhookConfiguration(opts)
}

// assertRenderedNamespaceOptIn verifies every rendered webhook is scoped by the
// aksh.dev/inject=enabled namespaceSelector. Shared by binding tests 41 and 164
// (the UT spec mandates both IDs; both delegate here to avoid duplicated body).
func assertRenderedNamespaceOptIn(t *testing.T) {
	t.Helper()
	mutating, validating := renderedConfigs()
	if len(mutating.Webhooks) == 0 || len(validating.Webhooks) == 0 {
		t.Fatal("expected at least one webhook in each configuration")
	}
	for _, w := range mutating.Webhooks {
		assertInjectOptIn(t, "mutating", w.NamespaceSelector)
	}
	for _, w := range validating.Webhooks {
		assertInjectOptIn(t, "validating", w.NamespaceSelector)
	}
}

// assertRenderedFailurePolicyFail verifies every rendered webhook fails closed
// (failurePolicy Fail). Shared by binding tests 42 and 165 (the UT spec mandates
// both IDs; both delegate here to avoid duplicated body).
func assertRenderedFailurePolicyFail(t *testing.T) {
	t.Helper()
	mutating, validating := renderedConfigs()
	if len(mutating.Webhooks) == 0 || len(validating.Webhooks) == 0 {
		t.Fatal("expected at least one webhook in each configuration")
	}
	for _, w := range mutating.Webhooks {
		if w.FailurePolicy == nil || *w.FailurePolicy != admissionregistrationv1.Fail {
			t.Fatalf("mutating webhook %q failurePolicy = %v, want Fail", w.Name, w.FailurePolicy)
		}
	}
	for _, w := range validating.Webhooks {
		if w.FailurePolicy == nil || *w.FailurePolicy != admissionregistrationv1.Fail {
			t.Fatalf("validating webhook %q failurePolicy = %v, want Fail", w.Name, w.FailurePolicy)
		}
	}
}

// 41
func TestWebhookConfiguration_NamespaceSelectorMatchLabelsAkshInjectEnabled_ScopesWebhookRegistration(t *testing.T) {
	assertRenderedNamespaceOptIn(t)
}

// 42
func TestWebhookConfiguration_FailurePolicyFailForMutatingAndValidatingWebhooks_FailsClosed(t *testing.T) {
	assertRenderedFailurePolicyFail(t)
}

// 164
func TestWebhookConfiguration_RenderedNamespaceSelector_UsesMatchLabelsAkshInjectEnabled(t *testing.T) {
	assertRenderedNamespaceOptIn(t)
}

// 165
func TestWebhookConfiguration_RenderedFailurePolicyFail_FailsClosedForBothWebhooks(t *testing.T) {
	assertRenderedFailurePolicyFail(t)
}

// 166
func TestWebhookConfiguration_MutatingRules_PodsCreateOnly(t *testing.T) {
	mutating, _ := renderedConfigs()
	if len(mutating.Webhooks) != 1 {
		t.Fatalf("mutating webhooks = %d, want 1", len(mutating.Webhooks))
	}
	rules := mutating.Webhooks[0].Rules
	if len(rules) != 1 {
		t.Fatalf("mutating rules = %d, want 1", len(rules))
	}
	r := rules[0]
	if !stringsEqual(r.Operations, []admissionregistrationv1.OperationType{admissionregistrationv1.Create}) {
		t.Fatalf("operations = %v, want [CREATE]", r.Operations)
	}
	assertCoreV1PodsRule(t, r, "pods")
}

// 167
func TestWebhookConfiguration_ValidatingRules_PodsCreateAndEphemeralContainersUpdateOnly(t *testing.T) {
	_, validating := renderedConfigs()
	if len(validating.Webhooks) != 1 {
		t.Fatalf("validating webhooks = %d, want 1", len(validating.Webhooks))
	}
	rules := validating.Webhooks[0].Rules
	if len(rules) != 2 {
		t.Fatalf("validating rules = %d, want 2", len(rules))
	}

	create := rules[0]
	if !stringsEqual(create.Operations, []admissionregistrationv1.OperationType{admissionregistrationv1.Create}) {
		t.Fatalf("rule[0] operations = %v, want [CREATE]", create.Operations)
	}
	assertCoreV1PodsRule(t, create, "pods")

	update := rules[1]
	if !stringsEqual(update.Operations, []admissionregistrationv1.OperationType{admissionregistrationv1.Update}) {
		t.Fatalf("rule[1] operations = %v, want [UPDATE]", update.Operations)
	}
	assertCoreV1PodsRule(t, update, "pods/ephemeralcontainers")
}

func assertInjectOptIn(t *testing.T, which string, sel *metav1.LabelSelector) {
	t.Helper()
	if sel == nil {
		t.Fatalf("%s namespaceSelector is nil", which)
	}
	if got := sel.MatchLabels[injectLabelKey]; got != injectLabelValue {
		t.Fatalf("%s namespaceSelector.matchLabels[%q] = %q, want %q", which, injectLabelKey, got, injectLabelValue)
	}
	if len(sel.MatchExpressions) != 0 {
		t.Fatalf("%s namespaceSelector has pod-author opt-out matchExpressions: %v", which, sel.MatchExpressions)
	}
}

func assertCoreV1PodsRule(t *testing.T, r admissionregistrationv1.RuleWithOperations, resource string) {
	t.Helper()
	if !stringsEqualStr(r.APIGroups, []string{""}) {
		t.Fatalf("apiGroups = %v, want [\"\"]", r.APIGroups)
	}
	if !stringsEqualStr(r.APIVersions, []string{"v1"}) {
		t.Fatalf("apiVersions = %v, want [v1]", r.APIVersions)
	}
	if !stringsEqualStr(r.Resources, []string{resource}) {
		t.Fatalf("resources = %v, want [%s]", r.Resources, resource)
	}
	if r.Scope == nil || *r.Scope != admissionregistrationv1.NamespacedScope {
		t.Fatalf("scope = %v, want Namespaced", r.Scope)
	}
}

func stringsEqual(a, b []admissionregistrationv1.OperationType) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringsEqualStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
