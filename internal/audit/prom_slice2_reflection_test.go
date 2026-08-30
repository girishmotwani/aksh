package audit_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/girishmotwani/aksh/internal/audit"
)

// #69 — MetricsRecorder_NoStringLabelField_AgentValuesUnassignable.
//
// Reflect over the COMPLETE MetricsRecorder method set and assert that no metric
// label parameter is the predeclared `string` type: every label must be a named,
// closed enum (or a named bounded type such as CredentialID) so an
// agent-controlled free string can never be assigned as a label value — the
// cardinality-as-security property of §4.1 enforced by construction, not
// convention (Failure mode: "A metric label would be unbounded → prevented by
// construction").
//
// SnapshotVersion(version string) is the single documented exception: `version`
// is the one operator-controlled, non-enum label (§4.1 / #73), changing at
// operator CRD-edit rate and structurally sanitised, never agent-reachable. It
// is exempted here precisely because it is not an agent value.
func TestMetricsRecorder_NoStringLabelField_AgentValuesUnassignable(t *testing.T) {
	iface := reflect.TypeOf((*audit.MetricsRecorder)(nil)).Elem()

	// The exemption is scoped to a specific (method, param index), NOT the whole
	// method: SnapshotVersion(version string) — param 0 is the single documented
	// operator-controlled label (§4.1 / #73). Scoping to the exact index means any
	// string parameter LATER added to SnapshotVersion (index 1+) is still caught,
	// so the exemption cannot silently widen the agent-reachable label surface.
	exemptParam := map[string]int{"SnapshotVersion": 0}

	sawCredentialID := false
	for i := 0; i < iface.NumMethod(); i++ {
		m := iface.Method(i)
		ft := m.Type // interface method type: no receiver in In(...)
		for p := 0; p < ft.NumIn(); p++ {
			if idx, ok := exemptParam[m.Name]; ok && p == idx {
				continue
			}
			pt := ft.In(p)
			if pt.Name() == "CredentialID" {
				sawCredentialID = true
			}
			// Reject the predeclared string (PkgPath=="" && Name()=="string").
			// A named string-underlying type such as CredentialID has a non-empty
			// PkgPath and thus PASSES.
			if pt.Kind() == reflect.String && pt.PkgPath() == "" && pt.Name() == "string" {
				t.Errorf("method %s param %d is the predeclared string type; a metric label must be a named closed enum (§4.1)", m.Name, p)
			}
		}
	}

	// Guard the assertion's own faithfulness: the bounded derived CredentialID
	// label must be present AND must be a NAMED string type (so the test above
	// meaningfully distinguishes it from a bare string).
	if !sawCredentialID {
		t.Fatal("expected a CredentialID label parameter somewhere in the surface")
	}
	credType := reflect.TypeOf(audit.CredentialID(""))
	if credType.Kind() != reflect.String || credType.PkgPath() == "" || credType.Name() != "CredentialID" {
		t.Fatalf("CredentialID must be a NAMED string type; got kind=%v pkg=%q name=%q", credType.Kind(), credType.PkgPath(), credType.Name())
	}
}

// #74 — Metrics_AgentValues_HostPathMethodResourceScopes_NeverLabels.
//
// Reflect over the COMPLETE MetricsRecorder method set and assert that none of
// the agent-controlled dimensions — identity/host, path, method, resource,
// scopes, requestId, pod — appears as any parameter type. Unlike #69 (label
// params are enums) and #71 (scoped to TransportReject), this enumerates the
// specific forbidden dimensions across the whole surface: there is no typed
// label param for any of them, enforced by construction (ADR-S6-03).
func TestMetrics_AgentValues_HostPathMethodResourceScopes_NeverLabels(t *testing.T) {
	forbidden := map[string]bool{
		"identity":  true,
		"host":      true,
		"path":      true,
		"method":    true,
		"resource":  true,
		"scopes":    true,
		"requestid": true,
		"pod":       true,
	}

	iface := reflect.TypeOf((*audit.MetricsRecorder)(nil)).Elem()
	for i := 0; i < iface.NumMethod(); i++ {
		m := iface.Method(i)
		ft := m.Type
		for p := 0; p < ft.NumIn(); p++ {
			name := strings.ToLower(ft.In(p).Name())
			if forbidden[name] {
				t.Errorf("method %s param %d has type %q — an agent-controlled dimension must never be a metric label (§4.1, ADR-S6-03)", m.Name, p, ft.In(p).Name())
			}
		}
	}
}
