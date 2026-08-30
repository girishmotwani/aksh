package audit_test

import (
	"testing"

	"github.com/girishmotwani/aksh/internal/audit"
)

// #57
func TestUpstreamRequest_Result_RecordsTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.UpstreamRequest(audit.UpstreamResultSuccess)
	rec.UpstreamRequest(audit.UpstreamResultFailure)
	rec.UpstreamRequest(audit.UpstreamResultSuccess)
	fam := family(t, reg, "aksh_upstream_requests_total")
	if got := counterWith(fam, map[string]string{"result": "success"}); got != 2 {
		t.Fatalf("aksh_upstream_requests_total{result=success} = %v, want 2", got)
	}
	if got := counterWith(fam, map[string]string{"result": "failure"}); got != 1 {
		t.Fatalf("aksh_upstream_requests_total{result=failure} = %v, want 1", got)
	}
}
