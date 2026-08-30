package injector

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// syncBuffer is a goroutine-safe buffer so concurrent slog handlers can write
// records without a data race under -race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newCaptureLogger returns a slog.Logger that writes JSON records to a
// goroutine-safe buffer for assertion.
func newCaptureLogger() (*slog.Logger, *syncBuffer) {
	sb := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(sb, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return logger, sb
}

// logRecords parses the captured JSON log lines into maps, failing the test if
// any non-empty line is not valid JSON so a logging regression cannot be hidden
// by a silent skip.
func logRecords(t *testing.T, sb *syncBuffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(sb.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("captured log line is not valid JSON: %v\nline: %q", err, line)
		}
		out = append(out, m)
	}
	return out
}

// findLogRecord returns the first captured record whose msg matches, and whether
// one was found.
func findLogRecord(t *testing.T, sb *syncBuffer, msg string) (map[string]any, bool) {
	t.Helper()
	for _, r := range logRecords(t, sb) {
		if s, _ := r["msg"].(string); s == msg {
			return r, true
		}
	}
	return nil, false
}

// newTestMetrics constructs a PromMetricsRecorder over a fresh registry.
func newTestMetrics(t *testing.T) (*audit.PromMetricsRecorder, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	rec, err := audit.NewPromMetricsRecorder(reg)
	if err != nil {
		t.Fatalf("NewPromMetricsRecorder() error = %v", err)
	}
	return rec, reg
}

// metricFamily returns the gathered metric family by name, or nil.
func metricFamily(t *testing.T, reg *prometheus.Registry, name string) *dto.MetricFamily {
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

func metricLabels(m *dto.Metric) map[string]string {
	out := map[string]string{}
	for _, lp := range m.GetLabel() {
		out[lp.GetName()] = lp.GetValue()
	}
	return out
}

func labelsMatch(got, want map[string]string) bool {
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// counterValueWith returns the counter value for the series whose labels contain
// want, or -1 if none match.
func counterValueWith(fam *dto.MetricFamily, want map[string]string) float64 {
	if fam == nil {
		return -1
	}
	for _, m := range fam.GetMetric() {
		if labelsMatch(metricLabels(m), want) {
			return m.GetCounter().GetValue()
		}
	}
	return -1
}

// histogramSampleCountWith returns the histogram sample count for the series
// whose labels contain want (empty want matches the first series), or 0.
func histogramSampleCountWith(fam *dto.MetricFamily, want map[string]string) uint64 {
	if fam == nil {
		return 0
	}
	for _, m := range fam.GetMetric() {
		if labelsMatch(metricLabels(m), want) {
			return m.GetHistogram().GetSampleCount()
		}
	}
	return 0
}
