package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/girishmotwani/aksh/internal/audit"
	"github.com/girishmotwani/aksh/internal/config"
	"github.com/girishmotwani/aksh/internal/dataplane"
	"github.com/girishmotwani/aksh/internal/dataplane/capture"
)

// proxySyncBuffer is a goroutine-safe buffer for capturing slog JSON records.
type proxySyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *proxySyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *proxySyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newProxyCaptureLogger() (*slog.Logger, *proxySyncBuffer) {
	sb := &proxySyncBuffer{}
	return slog.New(slog.NewJSONHandler(sb, &slog.HandlerOptions{Level: slog.LevelDebug})), sb
}

func proxyFindLog(t *testing.T, sb *proxySyncBuffer, msg string) (map[string]any, bool) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(sb.String()), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("proxyFindLog: captured log line is not valid JSON: %v\nline: %q", err, line)
		}
		if s, _ := m["msg"].(string); s == msg {
			return m, true
		}
	}
	return nil, false
}

func proxyCounterValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	fams, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		var total float64
		for _, m := range f.GetMetric() {
			total += metricCounterValue(m)
		}
		return total
	}
	return -1
}

func metricCounterValue(m *dto.Metric) float64 {
	if m.GetCounter() != nil {
		return m.GetCounter().GetValue()
	}
	return 0
}

// 180
func TestRun_PodCgroupResolved_LogsCapturePodCgroupResolvedWithPodPath(t *testing.T) {
	logger, sb := newProxyCaptureLogger()
	code := run(context.Background(), deps{
		loadConfig:            func() (config.Config, error) { return validConfig(), nil },
		log:                   logger,
		deriveCgroupCandidate: func(string, string) (string, error) { return "/host/kubepods/pod", nil },
		newPodCgroupResolver: func(config.Config) (podCgroupResolver, error) {
			return &fakeCgroupResolver{resolved: "/proc/1/root/sys/fs/cgroup"}, nil
		},
		// Stop startup right after the resolved log by failing the eager load.
		loadAndAttach: func(context.Context, *capture.Options) (captureHandle, error) {
			return nil, errors.New("stop after cgroup resolution")
		},
	})
	if code == 0 {
		t.Fatal("run() = 0, want non-zero (load aborted after resolution)")
	}
	record, ok := proxyFindLog(t, sb, "aksh-proxy: capture pod cgroup resolved")
	if !ok {
		t.Fatalf("resolved log not found; records=%s", sb.String())
	}
	if record["podPath"] != "/proc/1/root/sys/fs/cgroup" {
		t.Fatalf("podPath = %v, want /proc/1/root/sys/fs/cgroup", record["podPath"])
	}
}

// 181
func TestRun_PodCgroupResolutionFails_LogsCapturePodCgroupResolutionFailedWithError(t *testing.T) {
	logger, sb := newProxyCaptureLogger()
	code := run(context.Background(), deps{
		loadConfig:            func() (config.Config, error) { return validConfig(), nil },
		log:                   logger,
		deriveCgroupCandidate: func(string, string) (string, error) { return "/host/kubepods/pod", nil },
		newPodCgroupResolver: func(config.Config) (podCgroupResolver, error) {
			return &fakeCgroupResolver{err: errors.New("scope validation failed")}, nil
		},
	})
	if code == 0 {
		t.Fatal("run() = 0, want non-zero on cgroup resolution failure")
	}
	record, ok := proxyFindLog(t, sb, "aksh-proxy: capture pod cgroup resolution failed")
	if !ok {
		t.Fatalf("resolution-failed log not found; records=%s", sb.String())
	}
	if _, present := record["error"]; !present {
		t.Fatalf("resolution-failed log missing error field: %v", record)
	}
}

// 182
func TestRun_PodCgroupResolutionFails_IncrementsProxyCgroupResolutionErrorsMetric(t *testing.T) {
	logger, _ := newProxyCaptureLogger()
	reg := prometheus.NewRegistry()
	rec, err := audit.NewPromMetricsRecorder(reg)
	if err != nil {
		t.Fatalf("NewPromMetricsRecorder() error = %v", err)
	}
	code := run(context.Background(), deps{
		loadConfig:            func() (config.Config, error) { return validConfig(), nil },
		log:                   logger,
		metrics:               rec,
		deriveCgroupCandidate: func(string, string) (string, error) { return "", errors.New("cannot read proc cgroup") },
	})
	if code == 0 {
		t.Fatal("run() = 0, want non-zero on cgroup resolution failure")
	}
	if got := proxyCounterValue(t, reg, "aksh_proxy_cgroup_resolution_errors_total"); got < 1 {
		t.Fatalf("aksh_proxy_cgroup_resolution_errors_total = %v, want >= 1", got)
	}
}

// TestRun_AfterLoadAndAttach_LogsCaptureAttachedWithCgroupAndProgramCount asserts
// the bounded startup confirmation emitted right after a successful eager
// LoadAndAttach records the resolved pod cgroup path plus the nonzero kernel
// cgroup id and attached program count, so demo validation can assert the
// sidecar attached to the actual pod cgroup instead of grepping vague text.
// Startup is stopped immediately after by failing resolver construction, which
// runs after the attach log.
func TestRun_AfterLoadAndAttach_LogsCaptureAttachedWithCgroupAndProgramCount(t *testing.T) {
	logger, sb := newProxyCaptureLogger()
	code := run(context.Background(), deps{
		loadConfig:            func() (config.Config, error) { return validConfig(), nil },
		log:                   logger,
		deriveCgroupCandidate: func(string, string) (string, error) { return "/host/kubepods/pod", nil },
		newPodCgroupResolver: func(config.Config) (podCgroupResolver, error) {
			return &fakeCgroupResolver{resolved: "/proc/1/root/sys/fs/cgroup"}, nil
		},
		loadAndAttach: func(context.Context, *capture.Options) (captureHandle, error) {
			return &fakeHandle{attachInfo: healthyAttach()}, nil
		},
		// Abort right after the attach log: newResolver runs next and its
		// failure returns non-zero without needing a kernel.
		newResolver: func(any, capture.Options) (dataplane.DestinationResolver, error) {
			return nil, errors.New("stop after attach log")
		},
	})
	if code == 0 {
		t.Fatal("run() = 0, want non-zero (stopped after attach log)")
	}
	record, ok := proxyFindLog(t, sb, "aksh-proxy: eBPF capture attached")
	if !ok {
		t.Fatalf("attach-confirmation log not found; records=%s", sb.String())
	}
	if record["pod_cgroup_path"] != "/proc/1/root/sys/fs/cgroup" {
		t.Fatalf("pod_cgroup_path = %v, want the resolved pod cgroup path", record["pod_cgroup_path"])
	}
	// JSON numbers decode as float64; healthyAttach() has CgroupID 99 and one program.
	if cid, _ := record["cgroup_id"].(float64); cid != 99 {
		t.Fatalf("cgroup_id = %v, want 99 (nonzero kernel cgroup id)", record["cgroup_id"])
	}
	if pc, _ := record["program_count"].(float64); pc != 1 {
		t.Fatalf("program_count = %v, want 1 (nonzero attached program count)", record["program_count"])
	}
}
