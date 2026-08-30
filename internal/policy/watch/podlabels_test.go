package watch

import (
	"os"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/girishmotwani/aksh/api/v1alpha1"
)

func TestParsePodLabels_KubeletFormat_ReturnsAllLabels(t *testing.T) {
	raw := "app=\"frontend\"\ntier=\"web\"\napp.kubernetes.io/name=\"aksh\"\n"
	got, err := ParsePodLabels([]byte(raw), "labels")
	if err != nil {
		t.Fatalf("ParsePodLabels() error = %v", err)
	}
	want := map[string]string{"app": "frontend", "tier": "web", "app.kubernetes.io/name": "aksh"}
	if len(got) != len(want) {
		t.Fatalf("got %d labels (%v), want %d", len(got), got, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("label %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestParsePodLabels_EmptyFile_ReturnsEmptyMapNoError(t *testing.T) {
	got, err := ParsePodLabels(nil, "labels")
	if err != nil {
		t.Fatalf("ParsePodLabels() error = %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("got %v, want empty non-nil map", got)
	}
}

func TestParsePodLabels_EscapedValue_Unquoted(t *testing.T) {
	got, err := ParsePodLabels([]byte("note=\"a \\\"quoted\\\" value\"\n"), "labels")
	if err != nil {
		t.Fatalf("ParsePodLabels() error = %v", err)
	}
	if got["note"] != `a "quoted" value` {
		t.Fatalf("note = %q, want %q", got["note"], `a "quoted" value`)
	}
}

func TestParsePodLabels_MalformedLine_ReturnsError(t *testing.T) {
	for name, raw := range map[string]string{
		"no separator": "appfrontend\n",
		"unquoted":     "app=frontend\n",
		"empty key":    "=\"frontend\"\n",
	} {
		if _, err := ParsePodLabels([]byte(raw), "labels"); err == nil {
			t.Fatalf("%s: ParsePodLabels() = nil error, want error", name)
		}
	}
}

func TestLoadPodLabels_MissingFile_ReturnsError(t *testing.T) {
	if _, err := LoadPodLabels(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("LoadPodLabels() = nil error, want error so startup fails closed")
	}
}

func TestLoadPodLabels_EmptyPath_ReturnsError(t *testing.T) {
	if _, err := LoadPodLabels("  "); err == nil {
		t.Fatal("LoadPodLabels() = nil error, want error")
	}
}

func TestLoadPodLabels_RealFile_ReturnsLabels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels")
	if err := os.WriteFile(path, []byte("app=\"agent\"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := LoadPodLabels(path)
	if err != nil {
		t.Fatalf("LoadPodLabels() error = %v", err)
	}
	if got["app"] != "agent" {
		t.Fatalf("app = %q, want agent", got["app"])
	}
}

func policyWithSelector(name string, sel *metav1.LabelSelector) v1alpha1.AkshPolicy {
	return v1alpha1.AkshPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v1alpha1.AkshPolicySpec{Selector: sel},
	}
}

func filteredNames(t *testing.T, podLabels map[string]string, items []v1alpha1.AkshPolicy) []string {
	t.Helper()
	w := &Watcher{opts: Options{PodLabels: podLabels}}
	out := []string{}
	for _, p := range w.filterByPodLabels(items) {
		out = append(out, p.Name)
	}
	return out
}

func assertNames(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("applied policies = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("applied policies = %v, want %v", got, want)
		}
	}
}

// The #35 regression: a policy selecting another workload must not apply to
// this pod. Before the fix the empty-PodLabels short-circuit returned every
// policy in the namespace, so each pod's egress was the union of all of them.
func TestFilterByPodLabels_NonMatchingSelector_Excluded(t *testing.T) {
	items := []v1alpha1.AkshPolicy{
		policyWithSelector("mine", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}}),
		policyWithSelector("theirs", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}),
	}
	got := filteredNames(t, map[string]string{"app": "agent"}, items)
	assertNames(t, got, []string{"mine"})
}

func TestFilterByPodLabels_NoSelector_AppliesToEveryPod(t *testing.T) {
	items := []v1alpha1.AkshPolicy{
		policyWithSelector("global", nil),
		policyWithSelector("theirs", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}),
	}
	got := filteredNames(t, map[string]string{"app": "agent"}, items)
	assertNames(t, got, []string{"global"})
}

// An unlabelled pod is a resolved state, not "unknown": it must match only the
// policies that select nothing in particular.
func TestFilterByPodLabels_UnlabelledPod_OnlySelectorlessPoliciesApply(t *testing.T) {
	items := []v1alpha1.AkshPolicy{
		policyWithSelector("global", nil),
		policyWithSelector("empty-selector", &metav1.LabelSelector{}),
		policyWithSelector("theirs", &metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}),
	}
	got := filteredNames(t, map[string]string{}, items)
	assertNames(t, got, []string{"global", "empty-selector"})
}

func TestFilterByPodLabels_MatchExpressions_Honoured(t *testing.T) {
	items := []v1alpha1.AkshPolicy{
		policyWithSelector("in-set", &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"web", "api"}},
		}}),
		policyWithSelector("not-in-set", &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"batch"}},
		}}),
	}
	got := filteredNames(t, map[string]string{"tier": "web"}, items)
	assertNames(t, got, []string{"in-set"})
}

func TestFilterByPodLabels_UnparseableSelector_Excluded(t *testing.T) {
	items := []v1alpha1.AkshPolicy{
		policyWithSelector("broken", &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: "tier", Operator: "NoSuchOperator", Values: []string{"web"}},
		}}),
	}
	got := filteredNames(t, map[string]string{"tier": "web"}, items)
	assertNames(t, got, []string{})
}
