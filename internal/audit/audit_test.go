package audit_test

import (
	"reflect"
	"testing"

	"github.com/girishmotwani/aksh/internal/audit"
)

// TestAuditSink_InterfaceExists verifies the S6 audit sink interface.
func TestAuditSink_InterfaceExists(t *testing.T) {
	iface := reflect.TypeOf((*audit.AuditSink)(nil)).Elem()
	if iface.Kind() != reflect.Interface {
		t.Fatal("AuditSink is not an interface")
	}
	if _, ok := iface.MethodByName("Record"); !ok {
		t.Error("AuditSink missing Record method")
	}
	if _, ok := iface.MethodByName("RecordCompletion"); !ok {
		t.Error("AuditSink missing RecordCompletion method")
	}
}

// TestDataplaneMetrics_InterfaceExists removed in Slice 7: the transitional
// legacy 3-method string metrics interface no longer exists — the whole
// dataplane consumes the typed audit.MetricsRecorder directly.
