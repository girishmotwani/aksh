package audit_test

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/pipeline"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// newRecorder constructs a PromMetricsRecorder over a fresh registry and fails
// the test on any construction error.
func newRecorder(t *testing.T) (*audit.PromMetricsRecorder, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	rec, err := audit.NewPromMetricsRecorder(reg)
	if err != nil {
		t.Fatalf("NewPromMetricsRecorder() error = %v", err)
	}
	return rec, reg
}

// family returns the gathered metric family with the given name, or nil.
func family(t *testing.T, reg *prometheus.Registry, name string) *dto.MetricFamily {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	for _, f := range fams {
		if f.GetName() == name {
			return f
		}
	}
	return nil
}

// labelsOf returns a metric's labels as a name->value map.
func labelsOf(m *dto.Metric) map[string]string {
	out := map[string]string{}
	for _, lp := range m.GetLabel() {
		out[lp.GetName()] = lp.GetValue()
	}
	return out
}

// counterWith returns the counter value for the series whose labels match want,
// or -1 if no such series exists.
func counterWith(fam *dto.MetricFamily, want map[string]string) float64 {
	if fam == nil {
		return -1
	}
	for _, m := range fam.GetMetric() {
		got := labelsOf(m)
		if len(got) != len(want) {
			continue
		}
		match := true
		for k, v := range want {
			if got[k] != v {
				match = false
				break
			}
		}
		if match {
			return m.GetCounter().GetValue()
		}
	}
	return -1
}

// #42
func TestNewPromMetricsRecorder_NilRegistry_ReturnsError(t *testing.T) {
	rec, err := audit.NewPromMetricsRecorder(nil)
	if err == nil {
		t.Fatal("NewPromMetricsRecorder(nil) error = nil, want non-nil")
	}
	if rec != nil {
		t.Fatalf("NewPromMetricsRecorder(nil) recorder = %v, want nil", rec)
	}
}

// #43
func TestNewPromMetricsRecorder_RegistersAllCollectors(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("registration panicked: %v", r)
		}
	}()
	rec, reg := newRecorder(t)
	if rec == nil {
		t.Fatal("recorder is nil")
	}
	// A second recorder on the SAME registry must fail rather than panic,
	// proving the collectors are registered via Register (not MustRegister).
	if _, err := audit.NewPromMetricsRecorder(reg); err == nil {
		t.Fatal("second registration on same registry: error = nil, want duplicate error")
	}
}

// #44
func TestDecisions_TypedLabels_RecordsDecisionsTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.Decisions(pipeline.DispositionDeny, pipeline.ReasonNoMatch, audit.TransportTLS, false)
	fam := family(t, reg, "aksh_decisions_total")
	want := map[string]string{
		"disposition": "deny",
		"reason":      "policy_no_match",
		"fault":       "false",
		"transport":   "tls",
	}
	if got := counterWith(fam, want); got != 1 {
		t.Fatalf("aksh_decisions_total%v = %v, want 1", want, got)
	}
}

// #45
func TestDecisions_EachDisposition_ProducesDistinctSeries(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.Decisions(pipeline.DispositionAllow, pipeline.ReasonNone, audit.TransportTLS, false)
	rec.Decisions(pipeline.DispositionDeny, pipeline.ReasonNoMatch, audit.TransportTLS, true)
	fam := family(t, reg, "aksh_decisions_total")
	if fam == nil {
		t.Fatal("aksh_decisions_total not present")
	}
	if n := len(fam.GetMetric()); n != 2 {
		t.Fatalf("distinct series = %d, want 2", n)
	}
	allow := counterWith(fam, map[string]string{"disposition": "allow", "reason": "unspecified", "fault": "false", "transport": "tls"})
	deny := counterWith(fam, map[string]string{"disposition": "deny", "reason": "policy_no_match", "fault": "true", "transport": "tls"})
	if allow != 1 || deny != 1 {
		t.Fatalf("allow=%v deny=%v, want 1 and 1", allow, deny)
	}
}

// #46
func TestStageDuration_StageName_RecordsDurationHistogram(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.StageDuration(audit.StageMatch, 5*time.Millisecond)
	fam := family(t, reg, "aksh_decision_duration_seconds")
	if fam == nil {
		t.Fatal("aksh_decision_duration_seconds not present")
	}
	if fam.GetType() != dto.MetricType_HISTOGRAM {
		t.Fatalf("type = %v, want HISTOGRAM", fam.GetType())
	}
	m := fam.GetMetric()[0]
	if labelsOf(m)["stage"] != "match" {
		t.Fatalf("stage label = %q, want match", labelsOf(m)["stage"])
	}
	if c := m.GetHistogram().GetSampleCount(); c != 1 {
		t.Fatalf("sample count = %d, want 1", c)
	}
}

// #54
func TestTransportReject_ClassBound_RecordsTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.TransportReject(audit.RejectClassResourceLimit, audit.BoundMaxInflightRequests)
	fam := family(t, reg, "aksh_transport_reject_total")
	want := map[string]string{"class": "resource_limit", "bound": "max_inflight_requests"}
	if got := counterWith(fam, want); got != 1 {
		t.Fatalf("aksh_transport_reject_total%v = %v, want 1", want, got)
	}
}

// #55
func TestLeafCacheHit_NoLabels_RecordsHitsTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.LeafCacheHit()
	rec.LeafCacheHit()
	fam := family(t, reg, "aksh_leaf_cache_hits_total")
	if got := counterWith(fam, map[string]string{}); got != 2 {
		t.Fatalf("aksh_leaf_cache_hits_total = %v, want 2", got)
	}
}

// #56
func TestLeafCacheMiss_NoLabels_RecordsMissesTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.LeafCacheMiss()
	fam := family(t, reg, "aksh_leaf_cache_misses_total")
	if got := counterWith(fam, map[string]string{}); got != 1 {
		t.Fatalf("aksh_leaf_cache_misses_total = %v, want 1", got)
	}
}

// #58
func TestAuditRecord_Kind_RecordsTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.AuditRecord(audit.AuditRecordDecision)
	rec.AuditRecord(audit.AuditRecordCompletion)
	rec.AuditRecord(audit.AuditRecordCompletion)
	fam := family(t, reg, "aksh_audit_records_total")
	if got := counterWith(fam, map[string]string{"kind": "decision"}); got != 1 {
		t.Fatalf("kind=decision = %v, want 1", got)
	}
	if got := counterWith(fam, map[string]string{"kind": "completion"}); got != 2 {
		t.Fatalf("kind=completion = %v, want 2", got)
	}
}

// #59
func TestAuditWriteDuration_NoLabels_RecordsHistogram(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.AuditWriteDuration(2 * time.Millisecond)
	fam := family(t, reg, "aksh_audit_write_duration_seconds")
	if fam == nil || fam.GetType() != dto.MetricType_HISTOGRAM {
		t.Fatalf("aksh_audit_write_duration_seconds missing or not histogram: %v", fam)
	}
	if c := fam.GetMetric()[0].GetHistogram().GetSampleCount(); c != 1 {
		t.Fatalf("sample count = %d, want 1", c)
	}
}

// #60
func TestAuditUnavailable_Bool_SetsGauge(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.AuditUnavailable(true)
	if got := gaugeValue(t, reg, "aksh_audit_unavailable"); got != 1 {
		t.Fatalf("aksh_audit_unavailable = %v, want 1", got)
	}
	rec.AuditUnavailable(false)
	if got := gaugeValue(t, reg, "aksh_audit_unavailable"); got != 0 {
		t.Fatalf("aksh_audit_unavailable = %v, want 0", got)
	}
}

// #61
func TestSnapshotAge_Duration_SetsGauge(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.SnapshotAge(30 * time.Second)
	if got := gaugeValue(t, reg, "aksh_policy_snapshot_age_seconds"); got != 30 {
		t.Fatalf("aksh_policy_snapshot_age_seconds = %v, want 30", got)
	}
}

// #62
func TestSnapshotVersion_Version_SetsInfoGauge(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.SnapshotVersion("abc123")
	fam := family(t, reg, "aksh_policy_snapshot_version_info")
	if fam == nil {
		t.Fatal("aksh_policy_snapshot_version_info not present")
	}
	m := fam.GetMetric()[0]
	if labelsOf(m)["version"] != "abc123" {
		t.Fatalf("version label = %q, want abc123", labelsOf(m)["version"])
	}
	if m.GetGauge().GetValue() != 1 {
		t.Fatalf("info gauge value = %v, want 1", m.GetGauge().GetValue())
	}
}

// #63
func TestPolicyCompileFailure_NoLabels_RecordsTotal(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.PolicyCompileFailure()
	fam := family(t, reg, "aksh_policy_compile_failures_total")
	if got := counterWith(fam, map[string]string{}); got != 1 {
		t.Fatalf("aksh_policy_compile_failures_total = %v, want 1", got)
	}
}

// #64
func TestCAExpiry_NoLabels_SetsGauge(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.CAExpiry(3600 * time.Second)
	if got := gaugeValue(t, reg, "aksh_ca_expiry_seconds"); got != 3600 {
		t.Fatalf("aksh_ca_expiry_seconds = %v, want 3600", got)
	}
}

// #70
func TestDecisions_ClosedEnumLabels_CardinalityBounded(t *testing.T) {
	rec, reg := newRecorder(t)
	dispositions := []pipeline.Disposition{pipeline.DispositionAllow, pipeline.DispositionDeny}
	reasons := []pipeline.DenyReason{pipeline.ReasonNone, pipeline.ReasonNoMatch, pipeline.ReasonResourceLimit}
	transports := []audit.TransportKind{audit.TransportTLS, audit.TransportPlaintext}
	faults := []bool{true, false}
	// Drive every combination twice; the series count must equal the product of
	// the closed-enum cardinalities, never the number of calls.
	for i := 0; i < 2; i++ {
		for _, d := range dispositions {
			for _, r := range reasons {
				for _, tr := range transports {
					for _, f := range faults {
						rec.Decisions(d, r, tr, f)
					}
				}
			}
		}
	}
	fam := family(t, reg, "aksh_decisions_total")
	want := len(dispositions) * len(reasons) * len(transports) * len(faults)
	if n := len(fam.GetMetric()); n != want {
		t.Fatalf("series count = %d, want bounded %d", n, want)
	}
}

// #71
func TestTransportReject_ClosedEnumOnly_NoAgentControlledLabel(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.TransportReject(audit.RejectClassHandshake, audit.BoundHandover)
	rec.TransportReject(audit.RejectClassResourceLimit, audit.BoundMaxInflightRequests)
	fam := family(t, reg, "aksh_transport_reject_total")
	if fam == nil {
		t.Fatal("aksh_transport_reject_total not present")
	}
	forbidden := map[string]bool{"host": true, "path": true, "method": true, "identity": true, "resource": true, "scopes": true}
	for _, m := range fam.GetMetric() {
		names := map[string]bool{}
		for k := range labelsOf(m) {
			names[k] = true
			if forbidden[k] {
				t.Fatalf("forbidden agent-controlled label %q present", k)
			}
		}
		if len(names) != 2 || !names["class"] || !names["bound"] {
			t.Fatalf("labels = %v, want exactly {class, bound}", names)
		}
	}
}

// #73
func TestSnapshotVersion_VersionLabel_ChangesAtOperatorRate(t *testing.T) {
	rec, reg := newRecorder(t)
	// An operator CRD edit changes the version; the info gauge must track the
	// current version as a single series rather than accreting one series per
	// value (which at agent request-rate would be an unbounded vector).
	rec.SnapshotVersion("v1")
	rec.SnapshotVersion("v2")
	rec.SnapshotVersion("v3")
	fam := family(t, reg, "aksh_policy_snapshot_version_info")
	if fam == nil {
		t.Fatal("aksh_policy_snapshot_version_info not present")
	}
	if n := len(fam.GetMetric()); n != 1 {
		t.Fatalf("info-gauge series = %d, want 1 (operator-rate replacement)", n)
	}
	if v := labelsOf(fam.GetMetric()[0])["version"]; v != "v3" {
		t.Fatalf("version = %q, want v3", v)
	}
}

// #75
func TestDecisions_TransportLabel_ClosedEnumTwoValuesOnly(t *testing.T) {
	rec, reg := newRecorder(t)
	for _, tr := range []audit.TransportKind{audit.TransportTLS, audit.TransportPlaintext} {
		rec.Decisions(pipeline.DispositionAllow, pipeline.ReasonNone, tr, false)
	}
	fam := family(t, reg, "aksh_decisions_total")
	seen := map[string]bool{}
	for _, m := range fam.GetMetric() {
		seen[labelsOf(m)["transport"]] = true
	}
	if len(seen) != 2 || !seen["tls"] || !seen["plaintext"] {
		t.Fatalf("transport label values = %v, want exactly {tls, plaintext}", seen)
	}
}

// #76
func TestGather_ProducesValidPrometheusExposition(t *testing.T) {
	rec, reg := newRecorder(t)
	rec.Decisions(pipeline.DispositionDeny, pipeline.ReasonNoMatch, audit.TransportTLS, true)
	rec.StageDuration(audit.StageMatch, time.Millisecond)
	fams, err := rec.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	if len(fams) == 0 {
		t.Fatal("Gather() returned no families")
	}
	var sb strings.Builder
	enc := expfmt.NewEncoder(&sb, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, f := range fams {
		if err := enc.Encode(f); err != nil {
			t.Fatalf("encoding exposition failed: %v", err)
		}
	}
	out := sb.String()
	if !strings.Contains(out, "aksh_decisions_total") {
		t.Fatalf("exposition missing aksh_decisions_total:\n%s", out)
	}
	// The registry's own gather must also be consistent (parseable) via reg.
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("reg.Gather() error = %v", err)
	}
}

// #77
func TestGather_MetricNames_FollowAkshPrefixAndConventions(t *testing.T) {
	rec, reg := newRecorder(t)
	// Drive every core metric at least once so its family appears in Gather.
	rec.Decisions(pipeline.DispositionDeny, pipeline.ReasonNoMatch, audit.TransportTLS, false)
	rec.StageDuration(audit.StageMatch, time.Millisecond)
	rec.TransportReject(audit.RejectClassHandshake, audit.BoundHandover)
	rec.LeafCacheHit()
	rec.LeafCacheMiss()
	rec.AuditRecord(audit.AuditRecordDecision)
	rec.AuditWriteDuration(time.Millisecond)
	rec.AuditUnavailable(true)
	rec.SnapshotAge(time.Second)
	rec.SnapshotVersion("v1")
	rec.PolicyCompileFailure()
	rec.CAExpiry(time.Hour)

	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	if len(fams) == 0 {
		t.Fatal("no families gathered")
	}
	for _, f := range fams {
		name := f.GetName()
		if !strings.HasPrefix(name, "aksh_") {
			t.Errorf("family %q missing aksh_ prefix", name)
		}
		switch f.GetType() {
		case dto.MetricType_COUNTER:
			if !strings.HasSuffix(name, "_total") {
				t.Errorf("counter %q must end with _total", name)
			}
		case dto.MetricType_HISTOGRAM:
			if !strings.HasSuffix(name, "_seconds") && !strings.HasSuffix(name, "_bytes") {
				t.Errorf("histogram %q must end with _seconds or _bytes", name)
			}
		}
	}
}

func gaugeValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	fam := family(t, reg, name)
	if fam == nil {
		t.Fatalf("gauge %q not present", name)
	}
	return fam.GetMetric()[0].GetGauge().GetValue()
}

// #74
func TestPromMetricsRecorder_ConcurrentDecisionsStageDurationTransportReject_NoDataRace(t *testing.T) {
	rec, reg := newRecorder(t)
	const goroutines = 16
	const perGoroutine = 250

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				rec.Decisions(pipeline.DispositionAllow, pipeline.ReasonNone, audit.TransportTLS, false)
				rec.StageDuration(audit.StageMatch, time.Microsecond)
				rec.TransportReject(audit.RejectClassHandshake, audit.BoundHandover)
			}
		}()
	}
	wg.Wait()

	total := goroutines * perGoroutine
	decFam := family(t, reg, "aksh_decisions_total")
	if got := counterWith(decFam, map[string]string{
		"disposition": "allow", "reason": "unspecified", "fault": "false", "transport": "tls",
	}); got != float64(total) {
		t.Fatalf("aksh_decisions_total = %v, want %d (lost writes under concurrency)", got, total)
	}
	rejFam := family(t, reg, "aksh_transport_reject_total")
	if got := counterWith(rejFam, map[string]string{"class": "handshake", "bound": "handover"}); got != float64(total) {
		t.Fatalf("aksh_transport_reject_total = %v, want %d (lost writes under concurrency)", got, total)
	}
	stageFam := family(t, reg, "aksh_decision_duration_seconds")
	if stageFam == nil {
		t.Fatal("aksh_decision_duration_seconds not present")
	}
	for _, m := range stageFam.GetMetric() {
		if labelsOf(m)["stage"] == "match" {
			if c := m.GetHistogram().GetSampleCount(); c != uint64(total) {
				t.Fatalf("stage=match sample count = %d, want %d", c, total)
			}
		}
	}
}

// #75
func TestPromMetricsRecorder_ConcurrentGatherAndWrites_ConsistentSnapshot(t *testing.T) {
	rec, reg := newRecorder(t)
	const writers = 8
	const perWriter = 400

	var writes atomic.Int64
	var gatherErr atomic.Value // error
	done := make(chan struct{})

	var scraper sync.WaitGroup
	scraper.Add(1)
	go func() {
		defer scraper.Done()
		for {
			select {
			case <-done:
				return
			default:
				if _, err := reg.Gather(); err != nil {
					gatherErr.Store(err)
					return
				}
			}
		}
	}()

	var writersWg sync.WaitGroup
	for i := 0; i < writers; i++ {
		writersWg.Add(1)
		go func() {
			defer writersWg.Done()
			for j := 0; j < perWriter; j++ {
				rec.Decisions(pipeline.DispositionAllow, pipeline.ReasonNone, audit.TransportTLS, false)
				writes.Add(1)
			}
		}()
	}
	writersWg.Wait()
	close(done)
	scraper.Wait()

	if err, ok := gatherErr.Load().(error); ok && err != nil {
		t.Fatalf("concurrent Gather returned error: %v", err)
	}
	// A final scrape after quiescence must reflect every committed write exactly.
	fam := family(t, reg, "aksh_decisions_total")
	if got := counterWith(fam, map[string]string{
		"disposition": "allow", "reason": "unspecified", "fault": "false", "transport": "tls",
	}); got != float64(writes.Load()) {
		t.Fatalf("final snapshot counter = %v, want %d (inconsistent snapshot)", got, writes.Load())
	}
}

// #76
func TestPromMetricsRecorder_MixedWritersAndScraper_RaceFreeStress(t *testing.T) {
	rec, reg := newRecorder(t)
	const writers = 24
	const scrapers = 4

	stop := make(chan struct{})
	var scrapeErr atomic.Value // error
	var wg sync.WaitGroup

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					rec.Decisions(pipeline.DispositionDeny, pipeline.ReasonNoMatch, audit.TransportTLS, true)
					rec.StageDuration(audit.StageResolve, time.Microsecond)
					rec.TransportReject(audit.RejectClassNoOriginalDst, audit.BoundNone)
					rec.LeafCacheHit()
					rec.AuditRecord(audit.AuditRecordDecision)
					rec.SnapshotAge(time.Second)
				}
			}
		}()
	}

	for i := 0; i < scrapers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					fams, err := reg.Gather()
					if err != nil {
						scrapeErr.Store(err)
						return
					}
					var sb strings.Builder
					enc := expfmt.NewEncoder(&sb, expfmt.NewFormat(expfmt.TypeTextPlain))
					for _, f := range fams {
						if err := enc.Encode(f); err != nil {
							scrapeErr.Store(err)
							return
						}
					}
				}
			}
		}()
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	if err, ok := scrapeErr.Load().(error); ok && err != nil {
		t.Fatalf("mixed writer/scraper stress observed scrape error: %v", err)
	}
	// The registry must still gather cleanly after the stress.
	if _, err := reg.Gather(); err != nil {
		t.Fatalf("post-stress Gather() error = %v", err)
	}
}
